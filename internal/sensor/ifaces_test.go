package sensor

import (
	"reflect"
	"strings"
	"testing"
)

var host = []Iface{
	{"lo", true}, {"eth0", true}, {"docker0", false},
	{"br-asilab", true}, {"br-3f2a9c1d7e0b", true}, {"br-down", false}, {"veth12ab", true},
}

func TestExpandInterfaces(t *testing.T) {
	got, err := ExpandInterfaces([]string{"br-*"}, host)
	if want := []string{"br-3f2a9c1d7e0b", "br-asilab"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("br-*: %v %v, want %v", got, err, want)
	}
	got, err = ExpandInterfaces([]string{"eth0", "br-*", "br-asilab", "docker0"}, host)
	if want := []string{"eth0", "br-3f2a9c1d7e0b", "br-asilab", "docker0"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("mixed: %v %v, want %v", got, err, want)
	}
}

func TestExpandInterfacesErrors(t *testing.T) {
	for _, specs := range [][]string{{"nope0"}, {"wg*"}, {"br-["}} {
		if _, err := ExpandInterfaces(specs, host); err == nil {
			t.Errorf("%v: expected error", specs)
		}
	}
}

func TestExpandInterfacesExclusions(t *testing.T) {
	host := append([]Iface{{"br-edge0", true}, {"br-edge1", true}}, host...)
	for _, tc := range []struct{ specs, want []string }{
		{[]string{"br-*", "!br-edge*", "!docker0"}, []string{"br-3f2a9c1d7e0b", "br-asilab"}},
		{[]string{"!br-edge*", "br-*"}, []string{"br-3f2a9c1d7e0b", "br-asilab"}}, // order does not matter
		{[]string{"br-*", "!br-edge1"}, []string{"br-3f2a9c1d7e0b", "br-asilab", "br-edge0"}},
		{[]string{"br-*", "!br-edge?", "!br-[0-9]*"}, []string{"br-asilab"}},
		{[]string{"eth0", "br-edge0", "!br-*"}, []string{"eth0"}},                              // beats an explicit name too
		{[]string{"eth0", "!nope0", "!wg*"}, []string{"eth0"}},                                 // the excluded thing may be absent
		{[]string{"*", "!veth*", "!lo", "!br-*", "!docker0"}, []string{"eth0"}},                // everything but ...
		{[]string{"br-asilab", "br-*", "!br-edge*"}, []string{"br-asilab", "br-3f2a9c1d7e0b"}}, // spec order kept
	} {
		got, err := ExpandInterfaces(tc.specs, host)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v: %v %v, want %v", tc.specs, got, err, tc.want)
		}
	}
}

func TestExpandInterfacesExclusionErrors(t *testing.T) {
	for want, specs := range map[string][]string{
		"no interface to capture on":      {"!br-edge*"},
		"no interface left to capture on": {"br-*", "!br-*"},
		"empty interface name":            {"br-*", "!"},
		`interface pattern "!br-["`:       {"br-*", "!br-["},
		`"nope0" not found`:               {"nope0", "!nope0"}, // a typo stays an error
	} {
		if _, err := ExpandInterfaces(specs, host); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: got %v, want %q", specs, err, want)
		}
	}
}
