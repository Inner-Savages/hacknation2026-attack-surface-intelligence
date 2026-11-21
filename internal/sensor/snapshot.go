package sensor

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
)

// Snapshot is the on-disk baseline: everything the sensor has seen so far.
type Snapshot struct {
	Hosts    []HostEntry    `json:"hosts"`
	Services []ServiceEntry `json:"services"`
}

type HostEntry struct {
	IP netip.Addr `json:"ip"`
	Record
}

type ServiceEntry struct {
	ServiceKey
	Record
}

// Snapshot returns a copy of the current state in a stable order.
func (t *Tracker) Snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := Snapshot{Hosts: []HostEntry{}, Services: []ServiceEntry{}}
	for _, ip := range sortedAddrs(t.hosts) {
		s.Hosts = append(s.Hosts, HostEntry{IP: ip, Record: *t.hosts[ip]})
	}
	for _, k := range sortedKeys(t.services) {
		s.Services = append(s.Services, ServiceEntry{ServiceKey: k, Record: *t.services[k]})
	}
	return s
}

// Restore replaces the state with a previously saved baseline.
func (t *Tracker) Restore(s Snapshot) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.hosts = map[netip.Addr]*Record{}
	t.services = map[ServiceKey]*Record{}
	for _, h := range s.Hosts {
		r := h.Record
		t.hosts[h.IP] = &r
	}
	for _, e := range s.Services {
		r := e.Record
		t.services[e.ServiceKey] = &r
	}
}

// SaveFile writes the snapshot atomically (temp file + rename).
func SaveFile(path string, s Snapshot) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sensor-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// LoadFile reads a snapshot; a missing file is an empty baseline.
func LoadFile(path string) (Snapshot, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	var s Snapshot
	return s, json.Unmarshal(data, &s)
}
