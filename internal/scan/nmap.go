package scan

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"maps"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

// Options controls how nmap is invoked. Only discovery and service
// detection are used: no NSE scripts, no OS detection, nothing intrusive.
type Options struct {
	Binary           string        // default "nmap"
	Ports            string        // e.g. "22,80,443,8000-8100"; empty = TopPorts
	TopPorts         int           // used when Ports is empty; default 1000
	SYN              bool          // -sS (needs CAP_NET_RAW/root) instead of -sT
	SkipDiscovery    bool          // -Pn: treat every target as up
	MaxRate          int           // packets per second ceiling (--max-rate)
	VersionIntensity int           // -sV probe intensity 0-9; default 5
	HostTimeout      time.Duration // give up on a single host after this long
	VersionMode      VersionMode   // default VersionBalanced
	VersionWait      time.Duration // per probe in the faster modes; default DefaultVersionWait
}

const defaultTopPorts = 1000

var portsRe = regexp.MustCompile(`^(?:(?:[TU]:)?\d{1,5}(?:-\d{1,5})?)(?:,(?:[TU]:)?\d{1,5}(?:-\d{1,5})?)*$`)

// Validate rejects values that could smuggle extra nmap arguments or make
// the scan unreasonably aggressive.
func (o Options) Validate() error {
	if o.Ports != "" && !portsRe.MatchString(o.Ports) {
		return fmt.Errorf("ports %q: use numbers and ranges, e.g. 22,80,8000-8100", o.Ports)
	}
	if o.TopPorts < 0 || o.TopPorts > 65535 {
		return fmt.Errorf("top ports %d out of range", o.TopPorts)
	}
	if o.VersionIntensity < 0 || o.VersionIntensity > 9 {
		return fmt.Errorf("version intensity %d out of range 0-9", o.VersionIntensity)
	}
	if o.MaxRate < 0 {
		return fmt.Errorf("max rate must not be negative")
	}
	switch o.VersionMode {
	case "", VersionBalanced, VersionFast, VersionFull:
	default:
		return fmt.Errorf("version mode %q: use balanced, fast or full", o.VersionMode)
	}
	if o.VersionWait != 0 && o.VersionWait < minVersionWait {
		return fmt.Errorf("version wait %v is below %v", o.VersionWait, minVersionWait)
	}
	return nil
}

// Args builds the nmap command line. Targets are passed on stdin (-iL -),
// so a large chunk never hits argv limits.
func (o Options) Args() []string {
	scanType := "-sT"
	if o.SYN {
		scanType = "-sS"
	}
	args := []string{scanType, "-sV", "-n", "-oX", "-", "-iL", "-"}
	intensity := o.VersionIntensity
	if intensity == 0 {
		intensity = 5
	}
	args = append(args, "--version-intensity", strconv.Itoa(intensity))
	if o.SkipDiscovery {
		args = append(args, "-Pn")
	}
	if o.Ports != "" {
		args = append(args, "-p", o.Ports)
	} else {
		top := o.TopPorts
		if top == 0 {
			top = defaultTopPorts
		}
		args = append(args, "--top-ports", strconv.Itoa(top))
	}
	if o.MaxRate > 0 {
		args = append(args, "--max-rate", strconv.Itoa(o.MaxRate))
	}
	if o.HostTimeout > 0 {
		args = append(args, "--host-timeout", fmt.Sprintf("%ds", int(o.HostTimeout.Seconds())))
	}
	return args
}

func (o Options) versionMode() VersionMode {
	if o.VersionMode == "" {
		return VersionBalanced
	}
	return o.VersionMode
}

func (o Options) versionWait() time.Duration {
	if o.VersionWait == 0 {
		return DefaultVersionWait
	}
	return o.VersionWait
}

func (o Options) binary() string {
	if o.Binary == "" {
		return "nmap"
	}
	return o.Binary
}

// estimate guesses how long one target takes from the number of ports and
// the rate limit; 0 when there is no limit. Targets that do not answer are
// probed twice, which matters when all of them are treated as up.
func (o Options) estimate() time.Duration {
	if o.MaxRate <= 0 {
		return 0
	}
	probes := o.portCount()
	if o.SkipDiscovery {
		probes *= 2
	}
	return time.Duration(probes) * time.Second / time.Duration(o.MaxRate)
}

func (o Options) portCount() int {
	if o.Ports == "" {
		if o.TopPorts == 0 {
			return defaultTopPorts
		}
		return o.TopPorts
	}
	n := 0
	for _, f := range strings.Split(o.Ports, ",") {
		from, to, isRange := strings.Cut(strings.TrimLeft(f, "TU:"), "-")
		a, _ := strconv.Atoi(from)
		b := a
		if isRange {
			b, _ = strconv.Atoi(to)
		}
		n += max(0, b-a+1)
	}
	return n
}

// killGrace is how long a cancelled nmap gets between SIGTERM and SIGKILL.
const killGrace = 3 * time.Second

// runNmap scans one group of targets with a single nmap process. A
// non-empty probeDB replaces nmap's service probe database.
func runNmap(ctx context.Context, o Options, probeDB string, targets []string) ([]result.Host, error) {
	args := o.Args()
	if probeDB != "" {
		args = append(args, "--versiondb", probeDB)
	}
	cmd := exec.CommandContext(ctx, o.binary(), args...)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = killGrace
	cmd.Stdin = strings.NewReader(strings.Join(targets, "\n") + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("nmap: %s", msg)
	}
	return ParseXML(stdout.Bytes())
}

// scanChunk scans one chunk. In balanced mode the ports the tuned database
// could not identify get a second pass with nmap's own database and waits,
// so a slow or unusual service costs time instead of its identification.
// It returns how many services that pass covered.
func scanChunk(ctx context.Context, o Options, probeDB string, targets []string) ([]result.Host, int, error) {
	hosts, err := runNmap(ctx, o, probeDB, targets)
	if err != nil || probeDB == "" || o.versionMode() != VersionBalanced {
		return hosts, 0, err
	}
	byAddr := map[string]*result.Host{}
	ports := map[int]bool{}
	var again []string
	retried := 0
	for i := range hosts {
		h := &hosts[i]
		n := 0
		for _, s := range h.Services {
			if s.Guessed && s.Proto == "tcp" {
				ports[s.Port] = true
				n++
			}
		}
		if n > 0 && byAddr[h.Address] == nil {
			byAddr[h.Address] = h
			again = append(again, h.Address)
			retried += n
		}
	}
	if len(again) == 0 {
		return hosts, 0, nil
	}
	list := make([]string, 0, len(ports))
	for _, p := range slices.Sorted(maps.Keys(ports)) {
		list = append(list, strconv.Itoa(p))
	}
	o.Ports, o.SkipDiscovery = strings.Join(list, ","), true
	second, err := runNmap(ctx, o, "", again)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, err
		}
		return hosts, 0, nil // the first pass still stands
	}
	for _, h := range second {
		first := byAddr[h.Address]
		if first == nil {
			continue
		}
		for _, s := range h.Services {
			if s.State != "open" || s.Guessed {
				continue
			}
			for i := range first.Services {
				f := &first.Services[i]
				if f.Guessed && f.Port == s.Port && f.Proto == s.Proto {
					*f = s
				}
			}
		}
	}
	return hosts, retried, nil
}

// nmap XML (only the parts we use).
type nmapRun struct {
	Hosts []struct {
		Status struct {
			State  string `xml:"state,attr"`
			Reason string `xml:"reason,attr"`
		} `xml:"status"`
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Hostnames []struct {
			Name string `xml:"name,attr"`
		} `xml:"hostnames>hostname"`
		ExtraPorts []struct {
			State string `xml:"state,attr"`
			Count int    `xml:"count,attr"`
		} `xml:"ports>extraports"`
		Ports []struct {
			Proto  string `xml:"protocol,attr"`
			PortID int    `xml:"portid,attr"`
			State  struct {
				State  string `xml:"state,attr"`
				Reason string `xml:"reason,attr"`
			} `xml:"state"`
			Service struct {
				Name      string   `xml:"name,attr"`
				Product   string   `xml:"product,attr"`
				Version   string   `xml:"version,attr"`
				ExtraInfo string   `xml:"extrainfo,attr"`
				Tunnel    string   `xml:"tunnel,attr"`
				Method    string   `xml:"method,attr"`
				CPE       []string `xml:"cpe"`
			} `xml:"service"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

// ParseXML converts nmap -oX output into hosts.
func ParseXML(data []byte) ([]result.Host, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parse nmap XML: %w", err)
	}
	var hosts []result.Host
	for _, h := range run.Hosts {
		host := result.Host{State: h.Status.State, Reason: h.Status.Reason}
		for _, a := range h.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				host.Address = a.Addr
				break
			}
		}
		if host.Address == "" {
			continue
		}
		for _, n := range h.Hostnames {
			host.Hostnames = append(host.Hostnames, n.Name)
		}
		for _, p := range h.Ports {
			host.Services = append(host.Services, result.Service{
				Port: p.PortID, Proto: p.Proto,
				State: p.State.State, Reason: p.State.Reason,
				Name: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version,
				ExtraInfo: p.Service.ExtraInfo, Tunnel: p.Service.Tunnel, CPE: p.Service.CPE,
				Guessed: p.State.State == "open" && p.Service.Method != "probed",
			})
		}
		for _, e := range h.ExtraPorts {
			host.ExtraPorts = append(host.ExtraPorts, result.ExtraPorts{State: e.State, Count: e.Count})
		}
		hosts = append(hosts, host)
	}
	return hosts, nil
}

var (
	// ErrNoTargets is returned when there is nothing to scan.
	ErrNoTargets = errors.New("no targets")
	// ErrDeadline is returned when Scanner.Deadline left targets unscanned.
	ErrDeadline = errors.New("deadline reached before all targets were scanned")
)
