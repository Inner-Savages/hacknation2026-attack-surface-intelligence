package main

// Inventory is the console's attack-surface model: the targets an operator
// entered or imported, the current merged scan result and the user overrides
// layered on top of it. Manual targets, imported files and imported scan
// results all end up here, so they are listed, diffed and overridden the same
// way as a result produced by cmd/scanner.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/diff"
	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
	"github.com/Inner-Savages/silence-on-the-wire/internal/scan"
)

const (
	maxImportBytes = 5 << 20 // upload size limit
	maxTargets     = 50000   // targets kept in the inventory
	maxScanHosts   = 20000   // hosts accepted in one imported scan
	maxCIDRBits    = 20      // a CIDR may cover at most 2^20 addresses
	maxTagLen      = 64
	maxTags        = 32
	maxTextLen     = 2000
)

// Target is one manually entered or imported scan target.
type Target struct {
	Value  string    `json:"value"` // canonical IP, CIDR or lower-case domain
	Kind   string    `json:"kind"`  // ip, cidr, domain
	Tags   []string  `json:"tags,omitempty"`
	Source string    `json:"source"` // manual, import:<file>
	Actor  string    `json:"actor,omitempty"`
	Added  time.Time `json:"added"`
}

// ImportRecord is one line of the import log.
type ImportRecord struct {
	At         time.Time `json:"at"`
	Actor      string    `json:"actor"`
	Kind       string    `json:"kind"` // targets, scan
	Format     string    `json:"format"`
	Source     string    `json:"source"`
	Accepted   int       `json:"accepted"`
	Duplicates int       `json:"duplicates"`
	Rejected   int       `json:"rejected"`
}

type invState struct {
	Targets   []Target             `json:"targets"`
	Overrides map[string]*Override `json:"overrides"`
	Imports   []ImportRecord       `json:"imports"`
	LastDiff  *diff.Diff           `json:"last_diff,omitempty"`
}

type inventory struct {
	mu   sync.Mutex
	dir  string
	st   invState
	scan *result.Scan // current merged scan, nil before the first one
}

func openInventory(dataDir string) (*inventory, error) {
	inv := &inventory{dir: filepath.Join(dataDir, "inventory")}
	inv.st.Overrides = map[string]*Override{}
	if err := os.MkdirAll(inv.dir, 0o755); err != nil {
		return nil, err
	}
	if b, err := os.ReadFile(filepath.Join(inv.dir, "state.json")); err == nil {
		if err := json.Unmarshal(b, &inv.st); err != nil {
			return nil, fmt.Errorf("inventory state: %w", err)
		}
		if inv.st.Overrides == nil {
			inv.st.Overrides = map[string]*Override{}
		}
	}
	if b, err := os.ReadFile(filepath.Join(inv.dir, "scan.json")); err == nil {
		var sc result.Scan
		if err := json.Unmarshal(b, &sc); err != nil {
			return nil, fmt.Errorf("inventory scan: %w", err)
		}
		inv.scan = &sc
	}
	return inv, nil
}

func writeAtomic(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (inv *inventory) saveLocked() error {
	if err := writeAtomic(filepath.Join(inv.dir, "state.json"), inv.st); err != nil {
		return err
	}
	if inv.scan != nil {
		return writeAtomic(filepath.Join(inv.dir, "scan.json"), inv.scan)
	}
	return nil
}

// normalizeTarget validates a target spec and returns its canonical value and
// kind. CIDRs stay compact (they are not expanded) but are size-limited.
func normalizeTarget(spec string) (value, kind string, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || len(spec) > 255 {
		return "", "", fmt.Errorf("empty or too long target")
	}
	if strings.Contains(spec, "/") {
		p, err := netip.ParsePrefix(spec)
		if err != nil {
			return "", "", fmt.Errorf("target %q: %v", spec, err)
		}
		p = p.Masked()
		if p.Addr().BitLen()-p.Bits() > maxCIDRBits {
			return "", "", fmt.Errorf("target %q: covers more than 2^%d addresses", spec, maxCIDRBits)
		}
		return p.String(), "cidr", nil
	}
	var t scan.Targets
	if err := t.Add(spec); err != nil {
		return "", "", err
	}
	v := t.Items()[0]
	if _, err := netip.ParseAddr(v); err == nil {
		return v, "ip", nil
	}
	return v, "domain", nil
}

func cleanTags(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || len(t) > maxTagLen || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
		if len(out) == maxTags {
			break
		}
	}
	return out
}

// addTargets adds targets, merging tags into existing ones. Returns counts of
// added and duplicate (already known) values.
func (inv *inventory) addTargets(in []Target) (added, dups int, err error) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	idx := map[string]int{}
	for i, t := range inv.st.Targets {
		idx[t.Value] = i
	}
	for _, t := range in {
		if i, ok := idx[t.Value]; ok {
			dups++
			inv.st.Targets[i].Tags = cleanTags(append(inv.st.Targets[i].Tags, t.Tags...))
			continue
		}
		if len(inv.st.Targets) >= maxTargets {
			return added, dups, fmt.Errorf("target limit %d reached", maxTargets)
		}
		idx[t.Value] = len(inv.st.Targets)
		inv.st.Targets = append(inv.st.Targets, t)
		added++
	}
	return added, dups, inv.saveLocked()
}

func (inv *inventory) deleteTarget(value string) (bool, error) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	for i, t := range inv.st.Targets {
		if t.Value == value {
			inv.st.Targets = append(inv.st.Targets[:i], inv.st.Targets[i+1:]...)
			return true, inv.saveLocked()
		}
	}
	return false, nil
}

func (inv *inventory) listTargets() []Target {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	return append([]Target{}, inv.st.Targets...)
}

func (inv *inventory) record(r ImportRecord) {
	inv.st.Imports = append(inv.st.Imports, r)
	if n := len(inv.st.Imports); n > 100 {
		inv.st.Imports = inv.st.Imports[n-100:]
	}
}

// ingestScan runs an imported scan through the same path as a scanner result:
// it is diffed against the current scan and merged into it. Hosts the new scan
// did not touch are kept, so a partial import never erases the rest.
func (inv *inventory) ingestScan(sc *result.Scan, rec ImportRecord) (*diff.Diff, error) {
	sc.Sort()
	inv.mu.Lock()
	defer inv.mu.Unlock()
	var d *diff.Diff
	merged := sc
	if inv.scan != nil {
		d = diff.Compare(inv.scan, sc)
		covered := map[string]bool{}
		for _, t := range sc.Targets {
			covered[t] = true
		}
		for _, h := range sc.Hosts {
			covered[h.Address] = true
		}
		m := *sc
		m.Hosts = append([]result.Host{}, sc.Hosts...)
		for _, h := range inv.scan.Hosts {
			if !covered[h.Address] {
				m.Hosts = append(m.Hosts, h)
			}
		}
		m.Targets = unionStrings(inv.scan.Targets, sc.Targets)
		merged = &m
		merged.Sort()
	}
	prevScan, prevDiff := inv.scan, inv.st.LastDiff
	inv.scan, inv.st.LastDiff = merged, d
	inv.record(rec)
	if err := inv.saveLocked(); err != nil {
		inv.scan, inv.st.LastDiff = prevScan, prevDiff
		return nil, err
	}
	return d, nil
}

func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range [][]string{a, b} {
		for _, s := range l {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// Fields is the operator-editable view of an entry.
type Fields struct {
	Title      string   `json:"title"`
	Technology string   `json:"technology"`
	Tags       []string `json:"tags"`
	Note       string   `json:"note"`
	Status     string   `json:"status"`
}

// Entry is one row of the inventory: a host, a service, or a bare target.
// Original is what the scan/import says, Effective is Original with the
// user's Override applied.
type Entry struct {
	Key       string    `json:"key"`
	Kind      string    `json:"kind"` // host, service, target
	Address   string    `json:"address"`
	Hostnames []string  `json:"hostnames,omitempty"`
	Port      int       `json:"port,omitempty"`
	Proto     string    `json:"proto,omitempty"`
	Origin    string    `json:"origin"` // scan, target
	Original  Fields    `json:"original"`
	Override  *Override `json:"override,omitempty"`
	Effective Fields    `json:"effective"`
}

func hostKey(addr string) string { return "host:" + addr }
func svcKey(addr, proto string, port int) string {
	return fmt.Sprintf("svc:%s:%s:%d", addr, proto, port)
}

// entries builds the layered view. Overrides are applied at read time only;
// the stored scan and targets are never modified by them.
func (inv *inventory) entries() []Entry {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	var out []Entry
	known := map[string]bool{}
	tagsByTarget := map[string][]string{}
	for _, t := range inv.st.Targets {
		tagsByTarget[t.Value] = t.Tags
	}
	if inv.scan != nil {
		for i := range inv.scan.Hosts {
			h := &inv.scan.Hosts[i]
			known[h.Address] = true
			for _, n := range h.Hostnames {
				known[n] = true
			}
			if h.State != "up" && len(h.Services) == 0 {
				continue
			}
			for j := range h.Services {
				s := &h.Services[j]
				if s.State != "open" {
					continue
				}
				f := serviceFields(s, tagsByTarget[h.Address])
				out = append(out, inv.layer(Entry{
					Key: svcKey(h.Address, s.Proto, s.Port), Kind: "service", Address: h.Address,
					Hostnames: h.Hostnames, Port: s.Port, Proto: s.Proto, Origin: "scan", Original: f,
				}))
			}
		}
	}
	for _, t := range inv.st.Targets {
		if known[t.Value] {
			continue
		}
		out = append(out, inv.layer(Entry{
			Key: hostKey(t.Value), Kind: "target", Address: t.Value, Origin: "target",
			Original: Fields{Title: t.Value, Tags: t.Tags, Status: StatusNew},
		}))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Address != out[j].Address {
			return result.AddrLess(out[i].Address, out[j].Address)
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func (inv *inventory) layer(e Entry) Entry {
	e.Effective = e.Original
	if o := inv.st.Overrides[e.Key]; o != nil {
		e.Override = o
		e.Effective = o.apply(e.Original)
	}
	if e.Original.Tags == nil {
		e.Original.Tags = []string{}
	}
	if e.Effective.Tags == nil {
		e.Effective.Tags = []string{}
	}
	return e
}

func serviceFields(s *result.Service, targetTags []string) Fields {
	f := Fields{Status: StatusNew}
	if s.HTTP != nil {
		f.Title = s.HTTP.Title
	}
	var techs []string
	tags := map[string]bool{}
	for _, t := range s.Tech {
		if t.Version != "" {
			techs = append(techs, t.Name+" "+t.Version)
		} else {
			techs = append(techs, t.Name)
		}
		for _, tg := range t.Tags {
			tags[tg] = true
		}
	}
	for _, tg := range targetTags {
		tags[tg] = true
	}
	if len(techs) == 0 {
		techs = []string{strings.TrimSpace(strings.Join([]string{s.Name, s.Product, s.Version}, " "))}
	}
	f.Technology = strings.Join(techs, "; ")
	if f.Title == "" {
		f.Title = strings.TrimSpace(fmt.Sprintf("%s/%d %s", s.Proto, s.Port, s.Name))
	}
	for t := range tags {
		f.Tags = append(f.Tags, t)
	}
	sort.Strings(f.Tags)
	return f
}
