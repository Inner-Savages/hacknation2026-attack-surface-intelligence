// Package result is the scan result model shared by the scanner, the HTTP
// prober, fingerprinting and diffing. A scan serializes to a single JSON
// document, so two runs can be compared without a database.
package result

import (
	"sort"
	"time"
)

// Scan is one scanner run.
type Scan struct {
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Duration   Duration  `json:"duration"`
	Targets    []string  `json:"targets"`
	Settings   Settings  `json:"settings"`
	Chunks     []Chunk   `json:"chunks"`
	Hosts      []Host    `json:"hosts"`
}

// Settings records how the scan was run, so results are reproducible.
type Settings struct {
	NmapArgs  []string `json:"nmap_args"`
	ChunkSize int      `json:"chunk_size"`
	Parallel  int      `json:"parallel"`
}

// Chunk is one nmap invocation over a subset of targets. Its duration is
// the basis for tuning chunk sizes to the scan speed.
type Chunk struct {
	Index    int      `json:"index"`
	Targets  int      `json:"targets"`
	HostsUp  int      `json:"hosts_up"`
	Duration Duration `json:"duration"`
	Error    string   `json:"error,omitempty"`
}

// Host is one scanned address.
type Host struct {
	Address   string    `json:"address"`
	Hostnames []string  `json:"hostnames,omitempty"`
	State     string    `json:"state"` // up, down
	Reason    string    `json:"reason,omitempty"`
	Services  []Service `json:"services,omitempty"`
}

// Service is one port on a host.
type Service struct {
	Port      int      `json:"port"`
	Proto     string   `json:"proto"`
	State     string   `json:"state"` // open, closed, filtered, ...
	Reason    string   `json:"reason,omitempty"`
	Name      string   `json:"name,omitempty"`    // nmap service name: http, ssh, ...
	Product   string   `json:"product,omitempty"` // nmap product: nginx, OpenSSH, ...
	Version   string   `json:"version,omitempty"`
	ExtraInfo string   `json:"extra_info,omitempty"`
	Tunnel    string   `json:"tunnel,omitempty"` // "ssl" when nmap saw TLS
	CPE       []string `json:"cpe,omitempty"`
	HTTP      *HTTP    `json:"http,omitempty"` // filled by the HTTP prober for web services
}

// Duration marshals as a human-readable string ("1m2.5s").
type Duration time.Duration

func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	*d = Duration(v)
	return err
}

// Sort orders hosts by address and services by protocol and port, so
// results are stable regardless of chunk completion order.
func (s *Scan) Sort() {
	sort.Slice(s.Hosts, func(i, j int) bool { return addrLess(s.Hosts[i].Address, s.Hosts[j].Address) })
	for i := range s.Hosts {
		svc := s.Hosts[i].Services
		sort.Slice(svc, func(a, b int) bool {
			if svc[a].Proto != svc[b].Proto {
				return svc[a].Proto < svc[b].Proto
			}
			return svc[a].Port < svc[b].Port
		})
	}
	sort.Slice(s.Chunks, func(i, j int) bool { return s.Chunks[i].Index < s.Chunks[j].Index })
}
