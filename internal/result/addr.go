package result

import "net/netip"

// addrLess sorts IP addresses numerically and anything else (hostnames)
// after them, alphabetically.
func addrLess(a, b string) bool {
	pa, ea := netip.ParseAddr(a)
	pb, eb := netip.ParseAddr(b)
	switch {
	case ea == nil && eb == nil:
		return pa.Less(pb)
	case ea == nil:
		return true
	case eb == nil:
		return false
	}
	return a < b
}
