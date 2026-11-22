package main

// User overrides: operator edits of an entry's fields, stored apart from scan
// data and layered on at read time. A new scan or import replaces the scan
// data, never the overrides, so edits survive rescans.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Override holds the fields an operator changed. A nil field is not
// overridden; Tags, when non-nil, replaces the original tag set.
type Override struct {
	Title      *string   `json:"title,omitempty"`
	Technology *string   `json:"technology,omitempty"`
	Tags       *[]string `json:"tags,omitempty"`
	Note       *string   `json:"note,omitempty"`
	Status     *string   `json:"status,omitempty"`
	Actor      string    `json:"actor,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (o *Override) apply(f Fields) Fields {
	if o.Title != nil {
		f.Title = *o.Title
	}
	if o.Technology != nil {
		f.Technology = *o.Technology
	}
	if o.Tags != nil {
		f.Tags = append([]string{}, *o.Tags...)
	}
	if o.Note != nil {
		f.Note = *o.Note
	}
	if o.Status != nil {
		f.Status = *o.Status
	}
	return f
}

func (o *Override) empty() bool {
	return o.Title == nil && o.Technology == nil && o.Tags == nil && o.Note == nil && o.Status == nil
}

// validate checks and normalizes an override in place.
func (o *Override) validate() error {
	for name, p := range map[string]*string{"title": o.Title, "technology": o.Technology, "note": o.Note} {
		if p != nil && len(*p) > maxTextLen {
			return fmt.Errorf("%s longer than %d bytes", name, maxTextLen)
		}
	}
	if o.Tags != nil {
		t := cleanTags(*o.Tags)
		if t == nil {
			t = []string{}
		}
		o.Tags = &t
	}
	if o.Status != nil && !validStatus(*o.Status) {
		return fmt.Errorf("status must be one of %v", caseStatuses)
	}
	return nil
}

func validOverrideKey(k string) bool {
	return len(k) < 300 && (strings.HasPrefix(k, "host:") || strings.HasPrefix(k, "svc:"))
}

func (inv *inventory) setOverride(key string, o *Override) error {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	prev, had := inv.st.Overrides[key]
	inv.st.Overrides[key] = o
	if err := inv.saveLocked(); err != nil {
		if had {
			inv.st.Overrides[key] = prev
		} else {
			delete(inv.st.Overrides, key)
		}
		return err
	}
	return nil
}

func (inv *inventory) deleteOverride(key string) (bool, error) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	prev, ok := inv.st.Overrides[key]
	if !ok {
		return false, nil
	}
	delete(inv.st.Overrides, key)
	if err := inv.saveLocked(); err != nil {
		inv.st.Overrides[key] = prev
		return false, err
	}
	return true, nil
}

func (s *server) listOverrides(w http.ResponseWriter, r *http.Request) {
	s.inv.mu.Lock()
	defer s.inv.mu.Unlock()
	writeJSON(w, 200, s.inv.st.Overrides)
}

func (s *server) getOverride(w http.ResponseWriter, r *http.Request) {
	s.inv.mu.Lock()
	defer s.inv.mu.Unlock()
	o, ok := s.inv.st.Overrides[r.PathValue("key")]
	if !ok {
		http.Error(w, "no override", 404)
		return
	}
	writeJSON(w, 200, o)
}

// putOverride replaces the override for a key. An empty body object ({}) is
// rejected; use DELETE to go back to the original values.
func (s *server) putOverride(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !validOverrideKey(key) {
		http.Error(w, "key must look like host:<addr> or svc:<addr>:<proto>:<port>", 400)
		return
	}
	var o Override
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&o); err != nil {
		http.Error(w, "bad json: "+err.Error(), 400)
		return
	}
	if o.empty() {
		http.Error(w, "nothing to override; use DELETE to restore originals", 400)
		return
	}
	if err := o.validate(); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	o.Actor, o.UpdatedAt = s.actor(r, nil), time.Now().UTC()
	if err := s.inv.setOverride(key, &o); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, &o)
}

func (s *server) deleteOverrideH(w http.ResponseWriter, r *http.Request) {
	ok, err := s.inv.deleteOverride(r.PathValue("key"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !ok {
		http.Error(w, "no override", 404)
		return
	}
	w.WriteHeader(204)
}
