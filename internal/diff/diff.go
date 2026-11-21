// Package diff compares two scan results: hosts and open services that
// appeared, disappeared or changed (product, version, HTTP title, headers,
// certificate, recognized technologies, ...).
//
// Something only counts as gone if the newer scan actually covered it:
// a host that was not among the new scan's targets is "not scanned", not
// "gone". Volatile data (dates, ETags, body hashes) is ignored.
package diff

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

// Kind of change.
type Kind string

const (
	New     Kind = "new"
	Gone    Kind = "gone"
	Changed Kind = "changed"
)

// Diff is the comparison of an older and a newer scan.
type Diff struct {
	Old      Meta         `json:"old"`
	New      Meta         `json:"new"`
	Warnings []string     `json:"warnings,omitempty"`
	Hosts    []HostChange `json:"hosts"`
	Summary  Summary      `json:"summary"`
}

// Meta identifies a compared scan.
type Meta struct {
	StartedAt time.Time `json:"started_at"`
	Hosts     int       `json:"hosts_up"`
	Services  int       `json:"open_services"`
}

// HostChange lists what changed on one host. Kind is New/Gone for the host
// itself, Changed when only its services changed.
type HostChange struct {
	Address  string          `json:"address"`
	Kind     Kind            `json:"kind"`
	Services []ServiceChange `json:"services,omitempty"`
}

// ServiceChange is one service that appeared, disappeared or changed.
type ServiceChange struct {
	Port    int           `json:"port"`
	Proto   string        `json:"proto"`
	Kind    Kind          `json:"kind"`
	Label   string        `json:"label"` // short description: "http nginx 1.25"
	Changes []FieldChange `json:"changes,omitempty"`
}

// FieldChange is one attribute that differs.
type FieldChange struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

// Summary counts changes.
type Summary struct {
	NewHosts        int `json:"new_hosts"`
	GoneHosts       int `json:"gone_hosts"`
	NewServices     int `json:"new_services"`
	GoneServices    int `json:"gone_services"`
	ChangedServices int `json:"changed_services"`
}

// Empty reports whether nothing changed.
func (s Summary) Empty() bool { return s == Summary{} }

// Compare diffs old against new.
func Compare(old, cur *result.Scan) *Diff {
	d := &Diff{Old: meta(old), New: meta(cur)}
	if strings.Join(old.Settings.NmapArgs, " ") != strings.Join(cur.Settings.NmapArgs, " ") {
		d.Warnings = append(d.Warnings, "scans used different nmap settings; some differences may come from that, not from the network")
	}

	oldHosts, curHosts := upHosts(old), upHosts(cur)
	covered := map[string]bool{}
	for _, t := range cur.Targets {
		covered[t] = true
	}

	addrs := map[string]bool{}
	for a := range oldHosts {
		addrs[a] = true
	}
	for a := range curHosts {
		addrs[a] = true
	}
	notScanned := 0
	for a := range addrs {
		o, c := oldHosts[a], curHosts[a]
		switch {
		case o == nil:
			hc := HostChange{Address: a, Kind: New}
			for _, s := range openServices(c) {
				hc.Services = append(hc.Services, ServiceChange{Port: s.Port, Proto: s.Proto, Kind: New, Label: label(s)})
			}
			d.add(hc)
		case c == nil:
			if !coveredHost(o, covered) {
				notScanned++
				continue
			}
			hc := HostChange{Address: a, Kind: Gone}
			for _, s := range openServices(o) {
				hc.Services = append(hc.Services, ServiceChange{Port: s.Port, Proto: s.Proto, Kind: Gone, Label: label(s)})
			}
			d.add(hc)
		default:
			if sc := compareServices(o, c); len(sc) > 0 {
				d.add(HostChange{Address: a, Kind: Changed, Services: sc})
			}
		}
	}
	if notScanned > 0 {
		d.Warnings = append(d.Warnings, fmt.Sprintf("%d host(s) from the old scan were not targets of the new one and are not compared", notScanned))
	}
	sort.Slice(d.Hosts, func(i, j int) bool { return result.AddrLess(d.Hosts[i].Address, d.Hosts[j].Address) })
	return d
}

func (d *Diff) add(hc HostChange) {
	switch hc.Kind {
	case New:
		d.Summary.NewHosts++
	case Gone:
		d.Summary.GoneHosts++
	}
	for _, s := range hc.Services {
		switch s.Kind {
		case New:
			d.Summary.NewServices++
		case Gone:
			d.Summary.GoneServices++
		case Changed:
			d.Summary.ChangedServices++
		}
	}
	d.Hosts = append(d.Hosts, hc)
}

func meta(s *result.Scan) Meta {
	m := Meta{StartedAt: s.StartedAt}
	for i := range s.Hosts {
		if s.Hosts[i].State == "up" {
			m.Hosts++
			m.Services += len(openServices(&s.Hosts[i]))
		}
	}
	return m
}

func upHosts(s *result.Scan) map[string]*result.Host {
	out := map[string]*result.Host{}
	for i := range s.Hosts {
		if s.Hosts[i].State == "up" {
			out[s.Hosts[i].Address] = &s.Hosts[i]
		}
	}
	return out
}

func coveredHost(h *result.Host, covered map[string]bool) bool {
	if covered[h.Address] {
		return true
	}
	for _, n := range h.Hostnames {
		if covered[strings.ToLower(n)] {
			return true
		}
	}
	return false
}

func openServices(h *result.Host) []result.Service {
	var out []result.Service
	for _, s := range h.Services {
		if s.State == "open" {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].Port < out[j].Port
	})
	return out
}

type svcKey struct {
	proto string
	port  int
}

func compareServices(o, c *result.Host) []ServiceChange {
	om, cm := map[svcKey]result.Service{}, map[svcKey]result.Service{}
	var keys []svcKey
	for _, s := range openServices(o) {
		k := svcKey{s.Proto, s.Port}
		om[k] = s
		keys = append(keys, k)
	}
	for _, s := range openServices(c) {
		k := svcKey{s.Proto, s.Port}
		cm[k] = s
		if _, ok := om[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].proto != keys[j].proto {
			return keys[i].proto < keys[j].proto
		}
		return keys[i].port < keys[j].port
	})
	var out []ServiceChange
	for _, k := range keys {
		prev, inOld := om[k]
		cs, inCur := cm[k]
		switch {
		case !inOld:
			out = append(out, ServiceChange{Port: k.port, Proto: k.proto, Kind: New, Label: label(cs)})
		case !inCur:
			out = append(out, ServiceChange{Port: k.port, Proto: k.proto, Kind: Gone, Label: label(prev)})
		default:
			if fc := fields(prev, cs); len(fc) > 0 {
				out = append(out, ServiceChange{Port: k.port, Proto: k.proto, Kind: Changed, Label: label(cs), Changes: fc})
			}
		}
	}
	return out
}

// fields lists attribute differences worth reporting.
func fields(o, c result.Service) []FieldChange {
	var out []FieldChange
	cmp := func(field, a, b string) {
		if a != b {
			out = append(out, FieldChange{Field: field, Old: a, New: b})
		}
	}
	cmp("service", o.Name, c.Name)
	cmp("product", o.Product, c.Product)
	cmp("version", o.Version, c.Version)
	cmp("tunnel", o.Tunnel, c.Tunnel)

	oh, ch := o.HTTP, c.HTTP
	if (oh == nil) != (ch == nil) {
		cmp("http", present(oh), present(ch))
	} else if oh != nil {
		cmp("http.status", itoa(oh.Status), itoa(ch.Status))
		cmp("http.title", oh.Title, ch.Title)
		cmp("http.final_url", pathOf(oh.FinalURL), pathOf(ch.FinalURL))
		for _, h := range []string{"server", "x-powered-by", "x-generator", "x-env", "location"} {
			cmp("http.header."+h, header(oh, h), header(ch, h))
		}
		cmp("http.cookies", cookieNames(oh), cookieNames(ch))
		cmp("http.favicon", favicon(oh), favicon(ch))
		cmp("tls.certificate", certID(oh), certID(ch))
		cmp("tls.version", tlsVersion(oh), tlsVersion(ch))
	}
	ot, ct := techSet(o.Tech), techSet(c.Tech)
	var techChanges []FieldChange
	for name, ver := range ct {
		if old, ok := ot[name]; !ok {
			techChanges = append(techChanges, FieldChange{Field: "tech", New: withVersion(name, ver)})
		} else if old != ver {
			techChanges = append(techChanges, FieldChange{Field: "tech." + name, Old: old, New: ver})
		}
	}
	for name, ver := range ot {
		if _, ok := ct[name]; !ok {
			techChanges = append(techChanges, FieldChange{Field: "tech", Old: withVersion(name, ver)})
		}
	}
	// Map iteration order is random: sort for stable output.
	sort.Slice(techChanges, func(i, j int) bool {
		a, b := techChanges[i], techChanges[j]
		return a.Field+"\x00"+a.Old+"\x00"+a.New < b.Field+"\x00"+b.Old+"\x00"+b.New
	})
	out = append(out, techChanges...)
	return out
}

func label(s result.Service) string {
	parts := []string{s.Name}
	if s.Product != "" {
		parts = append(parts, s.Product)
	}
	if s.Version != "" {
		parts = append(parts, s.Version)
	}
	if s.HTTP != nil && s.HTTP.Title != "" {
		parts = append(parts, fmt.Sprintf("%q", s.HTTP.Title))
	}
	return strings.Join(parts, " ")
}

func present(h *result.HTTP) string {
	if h == nil {
		return ""
	}
	return "probed"
}

func itoa(i int) string { return fmt.Sprint(i) }

// pathOf drops scheme and host: the same service may be reached by a
// different name in another run.
func pathOf(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
		if j := strings.IndexByte(u, '/'); j >= 0 {
			return u[j:]
		}
		return "/"
	}
	return u
}

func header(h *result.HTTP, name string) string { return strings.Join(h.Headers[name], ", ") }

func cookieNames(h *result.HTTP) string {
	var n []string
	for _, c := range h.Cookies {
		n = append(n, c.Name)
	}
	sort.Strings(n)
	return strings.Join(n, ", ")
}

func favicon(h *result.HTTP) string {
	if h.Favicon == nil {
		return ""
	}
	return fmt.Sprint(h.Favicon.Hash)
}

func certID(h *result.HTTP) string {
	if h.TLS == nil {
		return ""
	}
	return fmt.Sprintf("%s (until %s)", h.TLS.Subject, h.TLS.NotAfter.Format("2006-01-02"))
}

func tlsVersion(h *result.HTTP) string {
	if h.TLS == nil {
		return ""
	}
	return h.TLS.Version
}

func techSet(ts []result.Tech) map[string]string {
	out := map[string]string{}
	for _, t := range ts {
		out[t.Name] = t.Version
	}
	return out
}

func withVersion(name, ver string) string {
	if ver == "" {
		return name
	}
	return name + " " + ver
}
