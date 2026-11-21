// Command sensor passively watches a network interface (or replays a pcap)
// and prints JSON-lines events whenever observed traffic differs from the
// baseline: new hosts/services, closed or silent ones, changed banners.
//
//	sudo ./sensor -i br-asilab -net 172.28.0.0/24 -learn 30s
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
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"asi/internal/sensor"
)

type packetSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

func main() {
	var (
		iface       = flag.String("i", "", "interface to capture on live (needs CAP_NET_RAW)")
		pcapFile    = flag.String("r", "", "replay a pcap/pcapng file instead of live capture")
		filter      = flag.String("f", sensor.DefaultBPF, "BPF filter applied in the kernel (empty = capture everything)")
		snapLen     = flag.Int("snaplen", sensor.DefaultSnapLen, "bytes captured per packet")
		nets        = flag.String("net", "172.28.0.0/24", "comma-separated prefixes to watch (empty = all)")
		statePath   = flag.String("state", "sensor-state.json", "baseline file (loaded at start, saved periodically)")
		silentAfter = flag.Duration("silent-after", 2*time.Minute, "mark host/service silent after this long without traffic (0 = never)")
		learn       = flag.Duration("learn", 0, "build the baseline without emitting events for this long")
		sweepEvery  = flag.Duration("sweep", 10*time.Second, "how often to check for silent hosts/services")
		saveEvery   = flag.Duration("save", 30*time.Second, "how often to persist the baseline")
	)
	flag.Parse()
	log.SetFlags(log.Ltime)
	log.SetPrefix("sensor: ")

	if (*iface == "") == (*pcapFile == "") {
		log.Fatal("use exactly one of -i <interface> or -r <file.pcap>")
	}
	prefixes, err := parsePrefixes(*nets)
	if err != nil {
		log.Fatal(err)
	}

	handle, err := openHandle(*iface, *pcapFile, *filter, *snapLen)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	src, start, err := startTime(handle, *iface != "")
	if err != nil {
		log.Fatal(err)
	}

	var outMu sync.Mutex
	enc := json.NewEncoder(os.Stdout)
	emit := func(e sensor.Event) {
		outMu.Lock()
		defer outMu.Unlock()
		if err := enc.Encode(e); err != nil {
			log.Printf("write event: %v", err)
		}
	}

	cfg := sensor.Config{SilentAfter: *silentAfter, Start: start}
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

	live := *iface != ""
	if live {
		// Live: wall-clock timers. Replay uses packet time instead (below).
		go every(ctx, *sweepEvery, func() { tracker.Sweep(time.Now()) })
		go every(ctx, *saveEvery, save)
		log.Printf("capturing on %s, watching %s, filter %q", *iface, *nets, *filter)
	}

	dec := sensor.NewDecoder(prefixes)
	var packets int
	var lastSweep time.Time
	for ctx.Err() == nil {
		data, ci, err := src.ReadPacketData()
		switch {
		case errors.Is(err, pcap.NextErrorTimeoutExpired):
			continue // lets us notice ctx cancellation
		case errors.Is(err, io.EOF):
			stop()
			continue
		case err != nil:
			log.Printf("read: %v", err)
			continue
		}
		packets++
		for _, o := range dec.Decode(data, ci.Timestamp) {
			tracker.Observe(o)
		}
		if !live && ci.Timestamp.Sub(lastSweep) >= *sweepEvery {
			tracker.Sweep(ci.Timestamp)
			lastSweep = ci.Timestamp
		}
	}
	if live {
		if st, err := handle.Stats(); err == nil {
			log.Printf("stopped after %d packets (kernel: %d passed filter, %d dropped)",
				packets, st.PacketsReceived, st.PacketsDropped)
			return
		}
	}
	log.Printf("stopped after %d packets", packets)
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
		return nil, fmt.Errorf("link type %v, only Ethernet supported", h.LinkType())
	}
	if filter != "" {
		if err := h.SetBPFFilter(filter); err != nil {
			h.Close()
			return nil, fmt.Errorf("BPF filter %q: %w", filter, err)
		}
	}
	return h, nil
}

// startTime returns when observation starts: now for live capture, the first
// packet's time for replay (so learn/grace windows work in packet time).
func startTime(h *pcap.Handle, live bool) (packetSource, time.Time, error) {
	if live {
		return h, time.Now(), nil
	}
	first, ci, err := h.ReadPacketData()
	if err != nil {
		return nil, time.Time{}, err
	}
	return &replay{r: h, first: first, firstCI: ci}, ci.Timestamp, nil
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

func parsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("-net: %w", err)
		}
		out = append(out, pfx.Masked())
	}
	return out, nil
}
