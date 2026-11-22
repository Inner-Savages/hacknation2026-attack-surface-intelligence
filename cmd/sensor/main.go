// Command sensor passively watches network interfaces (or replays a pcap)
// and prints JSON-lines events whenever observed traffic differs from the
// baseline: new hosts/services, closed or silent ones, changed banners.
//
//	./sensor -i br-asilab -learn 30s
//	./sensor -i br-front,br-back -net 172.18.0.0/16
//	./sensor -i 'br-*'          # every Docker bridge
//	./sensor -i 'br-*,!br-edge*' -exclude-net 172.18.0.0/16,10.0.0.5
//	./sensor -r capture.pcap -net 172.28.0.0/24
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"github.com/Inner-Savages/silence-on-the-wire/internal/sensor"
)

type packetSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

// capture is one opened packet source (an interface or a pcap file).
type capture struct {
	name   string
	handle *pcap.Handle
	src    packetSource
}

func main() {
	var (
		ifaces      = flag.String("i", "", `comma-separated interfaces to capture on live, globs allowed ("br-*" = every Docker bridge that is up), "!name" or "!glob" excludes ("br-*,!br-edge*"); needs CAP_NET_RAW`)
		pcapFile    = flag.String("r", "", "replay a pcap/pcapng file instead of live capture")
		filter      = flag.String("f", sensor.DefaultBPF, "BPF filter applied in the kernel (empty = capture everything)")
		snapLen     = flag.Int("snaplen", sensor.DefaultSnapLen, "bytes captured per packet")
		nets        = flag.String("net", "auto", `comma-separated prefixes to watch; "auto" = subnets of the capture interfaces, "" = everything`)
		excludeNets = flag.String("exclude-net", os.Getenv("SOTW_EXCLUDE_NET"), "comma-separated prefixes or addresses to ignore inside -net, e.g. your own infrastructure: no events, nothing added to the baseline (default $SOTW_EXCLUDE_NET)")
		statePath   = flag.String("state", "sensor-state.json", "baseline file (loaded at start, saved periodically)")
		silentAfter = flag.Duration("silent-after", 2*time.Minute, "mark host/service silent after this long without traffic (0 = never)")
		learn       = flag.Duration("learn", 0, "build the baseline without emitting events for this long")
		sweepEvery  = flag.Duration("sweep", 10*time.Second, "how often to check for silent hosts/services")
		saveEvery   = flag.Duration("save", 30*time.Second, "how often to persist the baseline")
		webhookURL  = flag.String("webhook", "", "also POST events (JSON arrays) to this URL, e.g. http://127.0.0.1:8099/events; several URLs separated by commas each get every event (same token)")
		webhookTok  = flag.String("webhook-token", os.Getenv("SOTW_WEBHOOK_TOKEN"), "bearer token for -webhook (default $SOTW_WEBHOOK_TOKEN)")
		name        = flag.String("name", "", "sensor name added to every event")
	)
	flag.Parse()
	log.SetFlags(log.Ltime)
	log.SetPrefix("sensor: ")

	if (*ifaces == "") == (*pcapFile == "") {
		log.Fatal("use exactly one of -i <interface[,interface...]> or -r <file.pcap>")
	}
	live := *ifaces != ""
	var names []string
	if live {
		var err error
		if names, err = resolveInterfaces(splitList(*ifaces)); err != nil {
			log.Fatal(err)
		}
	}

	var scope sensor.Scope
	var err error
	if scope.Watch, err = watchedPrefixes(*nets, names); err != nil {
		log.Fatal(err)
	}
	if scope.Exclude, err = sensor.ParsePrefixes(*excludeNets); err != nil {
		log.Fatalf("-exclude-net: %v", err)
	}
	if err := scope.Validate(); err != nil {
		log.Fatalf("nothing to watch: %v", err)
	}

	captures, start, err := openCaptures(names, *pcapFile, *filter, *snapLen)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		for _, c := range captures {
			c.handle.Close()
		}
	}()

	var hooks []*sensor.Webhook
	for _, u := range strings.Split(*webhookURL, ",") {
		if u = strings.TrimSpace(u); u != "" {
			h := sensor.NewWebhook(u, *webhookTok, 4096)
			h.Logf = log.Printf
			hooks = append(hooks, h)
		}
	}
	var outMu sync.Mutex
	enc := json.NewEncoder(os.Stdout)
	emit := func(e sensor.Event) {
		e.Sensor = *name
		outMu.Lock()
		defer outMu.Unlock()
		if err := enc.Encode(e); err != nil {
			log.Printf("write event: %v", err)
		}
		for _, h := range hooks {
			h.Send(e)
		}
	}

	cfg := sensor.Config{SilentAfter: *silentAfter, Start: start, Scope: scope}
	if *learn > 0 {
		cfg.LearnUntil = start.Add(*learn)
	}
	tracker := sensor.NewTracker(cfg, emit)
	snap, err := sensor.LoadFile(*statePath)
	if err != nil {
		log.Fatalf("load baseline: %v", err)
	}
	tracker.Restore(snap)
	log.Printf("baseline: %d hosts, %d services from %s", len(snap.Hosts), len(snap.Services), *statePath)

	save := func() {
		if err := sensor.SaveFile(*statePath, tracker.Snapshot()); err != nil {
			log.Printf("save baseline: %v", err)
		}
	}
	defer save()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if live {
		// Live: wall-clock timers. Replay sweeps in packet time instead.
		go every(ctx, *sweepEvery, func() { tracker.Sweep(time.Now()) })
		go every(ctx, *saveEvery, save)
		log.Printf("capturing on %s, watching %s, filter %q", strings.Join(names, ","), formatScope(scope), *filter)
	}

	var hookWG sync.WaitGroup
	for _, h := range hooks {
		hookWG.Add(1)
		go func() { defer hookWG.Done(); h.Run(ctx) }()
	}
	if len(hooks) > 0 {
		log.Printf("sending events to %s", *webhookURL)
	}

	var packets atomic.Int64
	var wg sync.WaitGroup
	for _, c := range captures {
		wg.Add(1)
		go func() {
			defer wg.Done()
			readLoop(ctx, c, sensor.NewDecoder(scope), tracker, live, *sweepEvery, &packets)
			if !live {
				stop() // end of the pcap file
			}
		}()
	}
	wg.Wait()
	stop()        // replay ends on EOF without a signal
	hookWG.Wait() // last flush of queued events
	for _, h := range hooks {
		log.Printf("webhook: %d events sent, %d dropped", h.Sent(), h.Dropped())
	}

	if live {
		var passed, dropped int
		for _, c := range captures {
			if st, err := c.handle.Stats(); err == nil {
				passed += st.PacketsReceived
				dropped += st.PacketsDropped
			}
		}
		log.Printf("stopped after %d packets (kernel: %d passed filter, %d dropped)", packets.Load(), passed, dropped)
		return
	}
	log.Printf("stopped after %d packets", packets.Load())
}

// readLoop feeds one capture into the shared tracker until ctx ends or the
// source is exhausted. Each loop has its own decoder (decoders reuse buffers).
func readLoop(ctx context.Context, c capture, dec *sensor.Decoder, tracker *sensor.Tracker,
	live bool, sweepEvery time.Duration, packets *atomic.Int64) {
	var lastSweep time.Time
	for ctx.Err() == nil {
		data, ci, err := c.src.ReadPacketData()
		switch {
		case errors.Is(err, pcap.NextErrorTimeoutExpired):
			continue // lets us notice ctx cancellation
		case errors.Is(err, io.EOF):
			return
		case err != nil:
			log.Printf("%s: read: %v", c.name, err)
			continue
		}
		packets.Add(1)
		for _, o := range dec.Decode(data, ci.Timestamp) {
			tracker.Observe(o)
		}
		if !live && ci.Timestamp.Sub(lastSweep) >= sweepEvery {
			tracker.Sweep(ci.Timestamp)
			lastSweep = ci.Timestamp
		}
	}
}

// openCaptures opens every interface (live) or the pcap file (replay) and
// returns when observation starts: now for live capture, the first packet's
// time for replay, so learn/grace windows work in packet time.
func openCaptures(ifaces []string, pcapFile, filter string, snapLen int) ([]capture, time.Time, error) {
	if len(ifaces) == 0 {
		h, err := openHandle("", pcapFile, filter, snapLen)
		if err != nil {
			return nil, time.Time{}, err
		}
		first, ci, err := h.ReadPacketData()
		if err != nil {
			h.Close()
			return nil, time.Time{}, err
		}
		src := &replay{r: h, first: first, firstCI: ci}
		return []capture{{name: pcapFile, handle: h, src: src}}, ci.Timestamp, nil
	}

	var out []capture
	for _, name := range ifaces {
		h, err := openHandle(name, "", filter, snapLen)
		if err != nil {
			for _, c := range out {
				c.handle.Close()
			}
			return nil, time.Time{}, err
		}
		out = append(out, capture{name: name, handle: h, src: h})
	}
	return out, time.Now(), nil
}

// openHandle opens a live interface or a capture file through libpcap and
// installs the kernel BPF filter.
func openHandle(iface, pcapFile, filter string, snapLen int) (*pcap.Handle, error) {
	var h *pcap.Handle
	if iface != "" {
		in, err := pcap.NewInactiveHandle(iface)
		if err != nil {
			return nil, err
		}
		defer in.CleanUp()
		// A bridge only hands us frames addressed to itself unless promiscuous.
		// libpcap uses socket membership, undone when the socket closes.
		for _, set := range []error{
			in.SetSnapLen(snapLen),
			in.SetPromisc(true),
			in.SetTimeout(500 * time.Millisecond), // wake up to notice Ctrl-C
			in.SetImmediateMode(true),             // deliver packets without buffering delay
		} {
			if set != nil {
				return nil, set
			}
		}
		if h, err = in.Activate(); err != nil {
			return nil, fmt.Errorf("open %s (root or CAP_NET_RAW needed): %w", iface, err)
		}
	} else {
		var err error
		if h, err = pcap.OpenOffline(pcapFile); err != nil {
			return nil, err
		}
	}
	if h.LinkType() != layers.LinkTypeEthernet {
		h.Close()
		return nil, fmt.Errorf("%s: link type %v, only Ethernet supported", iface+pcapFile, h.LinkType())
	}
	if filter != "" {
		if err := h.SetBPFFilter(filter); err != nil {
			h.Close()
			return nil, fmt.Errorf("BPF filter %q: %w", filter, err)
		}
	}
	return h, nil
}

// replay re-delivers the packet consumed while reading the start time.
type replay struct {
	r       packetSource
	first   []byte
	firstCI gopacket.CaptureInfo
}

func (p *replay) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if p.first != nil {
		d := p.first
		p.first = nil
		return d, p.firstCI, nil
	}
	return p.r.ReadPacketData()
}

func every(ctx context.Context, d time.Duration, f func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f()
		}
	}
}

// resolveInterfaces expands -i specs (names and globs) against the host's
// interfaces.
func resolveInterfaces(specs []string) ([]string, error) {
	ifcs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	avail := make([]sensor.Iface, len(ifcs))
	for i, ifc := range ifcs {
		avail[i] = sensor.Iface{Name: ifc.Name, Up: ifc.Flags&net.FlagUp != 0}
	}
	return sensor.ExpandInterfaces(specs, avail)
}

// watchedPrefixes resolves -net. "auto" takes the IPv4 subnets assigned to
// the capture interfaces (a Docker bridge carries its network's gateway
// address, e.g. 172.18.0.1/16); with no interfaces (replay) it means all.
func watchedPrefixes(spec string, ifaces []string) ([]netip.Prefix, error) {
	if spec != "auto" {
		ps, err := sensor.ParsePrefixes(spec)
		if err != nil {
			return nil, fmt.Errorf("-net: %w", err)
		}
		return ps, nil
	}
	var out []netip.Prefix
	for _, name := range ifaces {
		ifc, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("-net auto: %w", err)
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			return nil, fmt.Errorf("-net auto: %s: %w", name, err)
		}
		found := false
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			p, err := netip.ParsePrefix(ipn.String())
			if err != nil || !p.Addr().Is4() {
				continue
			}
			out = append(out, p.Masked())
			found = true
		}
		if !found {
			return nil, fmt.Errorf("-net auto: %s has no IPv4 address; pass -net explicitly", name)
		}
	}
	return out, nil
}

func formatScope(s sensor.Scope) string {
	out := "everything"
	if len(s.Watch) > 0 {
		out = sensor.FormatPrefixes(s.Watch)
	}
	if len(s.Exclude) > 0 {
		out += " except " + sensor.FormatPrefixes(s.Exclude)
	}
	return out
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
