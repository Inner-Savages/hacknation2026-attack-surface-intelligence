// Package scan turns a list of targets into nmap runs and parses their XML
// output into the result model. Large target lists are split into chunks
// scanned in parallel; each chunk's duration is recorded.
package scan

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
)

// MaxExpand bounds how many addresses a single CIDR may expand to
// (a /12 is ~1M addresses); larger ranges are almost always a typo.
const MaxExpand = 1 << 20

var hostnameRe = regexp.MustCompile(`^(?i:[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.(?i:[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?))*$`)

// Targets is a deduplicated, ordered list of scan targets: IP addresses
// (CIDRs already expanded) and hostnames (resolved by nmap).
type Targets struct {
	items []string
	seen  map[string]bool
}

// Add parses one target spec: an IP, a CIDR or a hostname.
func (t *Targets) Add(spec string) error {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	if t.seen == nil {
		t.seen = map[string]bool{}
	}
	if strings.Contains(spec, "/") {
		p, err := netip.ParsePrefix(spec)
		if err != nil {
			return fmt.Errorf("target %q: %w", spec, err)
		}
		p = p.Masked()
		if bits := p.Addr().BitLen() - p.Bits(); bits > 20 {
			return fmt.Errorf("target %q: expands to more than %d addresses", spec, MaxExpand)
		}
		for a := p.Addr(); p.Contains(a); a = a.Next() {
			t.push(a.String())
		}
		return nil
	}
	if a, err := netip.ParseAddr(spec); err == nil {
		t.push(a.Unmap().String())
		return nil
	}
	if !hostnameRe.MatchString(spec) {
		return fmt.Errorf("target %q: not an IP, CIDR or hostname", spec)
	}
	t.push(strings.ToLower(spec))
	return nil
}

func (t *Targets) push(s string) {
	if !t.seen[s] {
		t.seen[s] = true
		t.items = append(t.items, s)
	}
}

// AddList adds comma- or whitespace-separated specs.
func (t *Targets) AddList(s string) error {
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' }) {
		if err := t.Add(f); err != nil {
			return err
		}
	}
	return nil
}

// AddReader adds targets from a text file: one or more per line, '#'
// starts a comment.
func (t *Targets) AddReader(r io.Reader) error {
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if i := strings.IndexByte(text, '#'); i >= 0 {
			text = text[:i]
		}
		if err := t.AddList(text); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
	}
	return sc.Err()
}

// Items returns the targets in insertion order.
func (t *Targets) Items() []string { return t.items }

// Len is the number of distinct targets.
func (t *Targets) Len() int { return len(t.items) }

// CheckAllowed returns an error for the first IP target outside allow
// (hostnames are checked by nmap's resolution, not here). An empty allow
// list permits everything.
func (t *Targets) CheckAllowed(allow []netip.Prefix) error {
	if len(allow) == 0 {
		return nil
	}
outer:
	for _, s := range t.items {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		for _, p := range allow {
			if p.Contains(a) {
				continue outer
			}
		}
		return fmt.Errorf("target %s is outside the allowed ranges", s)
	}
	return nil
}

// Chunks splits the targets into groups of at most size.
func (t *Targets) Chunks(size int) [][]string {
	if size <= 0 {
		size = len(t.items)
	}
	var out [][]string
	for i := 0; i < len(t.items); i += size {
		out = append(out, t.items[i:min(i+size, len(t.items))])
	}
	return out
}
