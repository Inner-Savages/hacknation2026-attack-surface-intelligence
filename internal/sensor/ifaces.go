package sensor

import (
	"errors"
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
// exist as given. A spec starting with "!" (name or glob) excludes: whatever
// it matches is removed from the result, wherever it stands in the list, and
// it may match nothing. The result keeps spec order and has no duplicates.
func ExpandInterfaces(specs []string, available []Iface) ([]string, error) {
	var include, exclude []string
	for _, spec := range specs {
		pattern, negated := strings.CutPrefix(spec, "!")
		if pattern == "" {
			return nil, fmt.Errorf("empty interface name in %q", spec)
		}
		if _, err := path.Match(pattern, ""); err != nil {
			return nil, fmt.Errorf("interface pattern %q: %w", spec, err)
		}
		if negated {
			exclude = append(exclude, pattern)
		} else {
			include = append(include, pattern)
		}
	}
	if len(include) == 0 {
		return nil, errors.New(`no interface to capture on: exclusions ("!...") need at least one name or pattern to exclude from, e.g. 'br-*,!br-edge*'`)
	}

	var out []string
	seen := map[string]bool{}
	for _, spec := range include {
		matched, err := matchInterfaces(spec, available)
		if err != nil {
			return nil, err
		}
		for _, n := range matched {
			if !seen[n] && !matchesAny(exclude, n) {
				out = append(out, n)
			}
			seen[n] = true
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no interface left to capture on: %q excludes everything %q selects",
			"!"+strings.Join(exclude, ",!"), strings.Join(include, ","))
	}
	return out, nil
}

// matchInterfaces resolves one selecting spec, sorted by name.
func matchInterfaces(spec string, available []Iface) ([]string, error) {
	glob := strings.ContainsAny(spec, "*?[")
	var matched []string
	for _, ifc := range available {
		if !glob {
			if ifc.Name == spec {
				return []string{spec}, nil
			}
		} else if ok, _ := path.Match(spec, ifc.Name); ok && ifc.Up {
			matched = append(matched, ifc.Name)
		}
	}
	switch {
	case !glob:
		return nil, fmt.Errorf("interface %q not found", spec)
	case len(matched) == 0:
		return nil, fmt.Errorf("no interface that is up matches %q", spec)
	}
	sort.Strings(matched)
	return matched, nil
}

func matchesAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}
