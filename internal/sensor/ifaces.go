package sensor

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// Iface is the part of a network interface that ExpandInterfaces needs.
type Iface struct {
	Name string
	Up   bool
}

// ExpandInterfaces resolves capture interface specs against the available
// interfaces. A spec with glob characters (e.g. "br-*" for every Docker
// bridge) selects all matching interfaces that are up; a plain name must
// exist as given. The result keeps spec order and has no duplicates.
func ExpandInterfaces(specs []string, available []Iface) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, spec := range specs {
		if !strings.ContainsAny(spec, "*?[") {
			found := false
			for _, ifc := range available {
				if ifc.Name == spec {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("interface %q not found", spec)
			}
			add(spec)
			continue
		}
		if _, err := path.Match(spec, ""); err != nil {
			return nil, fmt.Errorf("interface pattern %q: %w", spec, err)
		}
		var matched []string
		for _, ifc := range available {
			if ok, _ := path.Match(spec, ifc.Name); ok && ifc.Up {
				matched = append(matched, ifc.Name)
			}
		}
		if len(matched) == 0 {
			return nil, fmt.Errorf("no interface that is up matches %q", spec)
		}
		sort.Strings(matched)
		for _, n := range matched {
			add(n)
		}
	}
	return out, nil
}
