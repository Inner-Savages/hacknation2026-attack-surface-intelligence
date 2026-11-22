package sensor

import (
	"fmt"
	"net/netip"
	"strings"
)

// Scope says which addresses the sensor reports on: those inside Watch
// (empty = everything) and not inside Exclude. The zero Scope is everything.
type Scope struct {
	Watch   []netip.Prefix
	Exclude []netip.Prefix
}

// Contains reports whether the sensor should report on a.
func (s Scope) Contains(a netip.Addr) bool {
	if !a.IsValid() || a.IsUnspecified() {
		return false
	}
	return (len(s.Watch) == 0 || anyContains(s.Watch, a)) && !anyContains(s.Exclude, a)
}

// Validate rejects a scope in which every watched prefix is excluded: such a
// sensor would run and never report anything.
func (s Scope) Validate() error {
	watch := s.Watch
	if len(watch) == 0 {
		watch = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	}
	for _, w := range watch {
		if !covered(w, s.Exclude) {
			return nil
		}
	}
	return fmt.Errorf("all of %s is excluded by %s", FormatPrefixes(watch), FormatPrefixes(s.Exclude))
}

// covered reports whether a single prefix in by contains all of p.
func covered(p netip.Prefix, by []netip.Prefix) bool {
	for _, b := range by {
		if b.Bits() <= p.Bits() && b.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func anyContains(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ParsePrefixes parses a comma-separated list of CIDRs and single addresses
// ("172.18.0.0/16,10.0.0.5"); an address means just that host.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		if a, err := netip.ParseAddr(f); err == nil {
			a = a.Unmap().WithZone("")
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, fmt.Errorf("%q is neither a CIDR nor an IP address", f)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// FormatPrefixes is the inverse of ParsePrefixes, for log lines.
func FormatPrefixes(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ",")
}
