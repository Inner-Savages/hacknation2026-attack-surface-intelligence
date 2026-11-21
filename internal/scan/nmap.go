package scan

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
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
}

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
			top = 1000
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

func (o Options) binary() string {
	if o.Binary == "" {
		return "nmap"
	}
	return o.Binary
}

// RunChunk scans one group of targets with a single nmap process.
func RunChunk(ctx context.Context, o Options, targets []string) ([]result.Host, error) {
	cmd := exec.CommandContext(ctx, o.binary(), o.Args()...)
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
			})
		}
		hosts = append(hosts, host)
	}
	return hosts, nil
}

// ErrNoTargets is returned when there is nothing to scan.
var ErrNoTargets = errors.New("no targets")
