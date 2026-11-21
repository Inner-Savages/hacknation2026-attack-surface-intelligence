package sensor

import (
	"reflect"
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
