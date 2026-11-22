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
	Duration   Duration  `json:"duration"` // time spent scanning; without Sessions the same as finished - started
	Targets    []string  `json:"targets"`
	Settings   Settings  `json:"settings"`
	Sessions   []Session `json:"sessions,omitempty"` // scheduled scans: the stretches the run was split into
	Chunks     []Chunk   `json:"chunks"`
	Hosts      []Host    `json:"hosts"`
}

// Session is one uninterrupted stretch of a scan. A scan that does not fit
// its time window continues in another session.
type Session struct {
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Duration   Duration  `json:"duration"`
	Chunks     int       `json:"chunks"`  // finished in this session
	Targets    int       `json:"targets"` // covered by those chunks
	Stopped    string    `json:"stopped"` // "completed", "window closed", ...
}

// Settings records how the scan was run, so results are reproducible.
type Settings struct {
	NmapArgs  []string `json:"nmap_args"`
	ChunkSize int      `json:"chunk_size"`
	Parallel  int      `json:"parallel"`
	// Adaptive chunking: the duration chunks are sized for and the bounds
	// on their size. Zero target: every chunk has ChunkSize targets.
	ChunkTarget Duration `json:"chunk_target,omitzero"`
	ChunkMin    int      `json:"chunk_min,omitempty"`
	ChunkMax    int      `json:"chunk_max,omitempty"`
	VersionMode string   `json:"version_mode,omitempty"`
	VersionWait Duration `json:"version_wait,omitzero"`
}

// Chunk is one group of targets scanned together. Its duration is the basis
// for tuning chunk sizes to the scan speed.
type Chunk struct {
	Index     int       `json:"index"`
	Targets   int       `json:"targets"`
	HostsUp   int       `json:"hosts_up"`
	StartedAt time.Time `json:"started_at"`
	Duration  Duration  `json:"duration"`
	Reason    string    `json:"reason,omitempty"`  // why the chunk has this many targets
	Retried   int       `json:"retried,omitempty"` // services scanned again with full -sV waits
	Error     string    `json:"error,omitempty"`
}

// Host is one scanned address.
type Host struct {
	Address   string    `json:"address"`
	Hostnames []string  `json:"hostnames,omitempty"`
	State     string    `json:"state"` // up, down
	Reason    string    `json:"reason,omitempty"`
	Services  []Service `json:"services,omitempty"`
	// ExtraPorts are ports nmap summarized instead of listing ("Not shown:
	// 100 closed tcp ports"). Closed ones prove the host answers even with
	// nothing open; all-filtered usually means nobody is there.
	ExtraPorts []ExtraPorts `json:"extra_ports,omitempty"`
}

// ExtraPorts is a group of unlisted ports in one state.
type ExtraPorts struct {
	State string `json:"state"`
	Count int    `json:"count"`
}

// Responded reports whether the host answered on any port (open, or
// closed with a reset), as opposed to every probe timing out.
func (h *Host) Responded() bool {
	for _, s := range h.Services {
		if s.State == "open" || s.State == "closed" {
			return true
		}
	}
	for _, e := range h.ExtraPorts {
		if e.State == "closed" && e.Count > 0 {
			return true
		}
	}
	return false
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
	Guessed   bool     `json:"guessed,omitempty"` // Name comes from the port number; version detection found nothing
	HTTP      *HTTP    `json:"http,omitempty"`    // filled by the HTTP prober for web services
	Tech      []Tech   `json:"tech,omitempty"`    // filled by fingerprinting
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
	sort.Slice(s.Hosts, func(i, j int) bool { return AddrLess(s.Hosts[i].Address, s.Hosts[j].Address) })
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
