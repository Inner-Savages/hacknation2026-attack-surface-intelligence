package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// registerRBACRoutes adds the role, permission, audit and case create/delete
// endpoints. Their permissions are declared in routePerms (rbac.go).
func (s *server) registerRBACRoutes(mux *http.ServeMux) {
	// Servers assembled without main (tests) get in-memory defaults.
	if s.roles == nil {
		s.roles = &roleStore{custom: map[string]*Role{}}
	}
	if s.audit == nil {
		s.audit = &auditLog{}
	}
	mux.HandleFunc("GET /api/rbac/me", s.rbacMe)
	mux.HandleFunc("GET /api/rbac/users", s.rbacUsers)
	mux.HandleFunc("GET /api/roles", s.listRoles)
	mux.HandleFunc("POST /api/roles", s.createRole)
	mux.HandleFunc("PUT /api/roles/{name}", s.updateRole)
	mux.HandleFunc("DELETE /api/roles/{name}", s.deleteRole)
	mux.HandleFunc("POST /api/users/{login}/role", s.setUserRole)
	mux.HandleFunc("GET /api/audit", s.listAudit)
	mux.HandleFunc("POST /api/cases", s.createCase)
	mux.HandleFunc("DELETE /api/cases/{id}", s.deleteCase)
}

func (s *server) rbacMe(w http.ResponseWriter, r *http.Request) {
	sess := s.auth.who(r)
	role := s.auth.roleOf(sess.Login)
	perms := []string{}
	label := role
	if ro, ok := s.roles.get(role); ok {
		perms, label = ro.Permissions, ro.Label
	}
	writeJSON(w, 200, map[string]interface{}{"login": sess.Login, "role": role, "role_label": label, "permissions": perms})
}

func (s *server) rbacUsers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]interface{}{"items": s.auth.usersWithRoles()})
}

func (s *server) listRoles(w http.ResponseWriter, r *http.Request) {
	cat := []map[string]string{}
	for _, c := range permCatalog {
		cat = append(cat, map[string]string{"permission": c.Perm, "description": c.Desc})
	}
	writeJSON(w, 200, map[string]interface{}{"roles": s.roles.list(), "permissions": cat})
}

type rolePayload struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

func readJSON(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil || json.Unmarshal(b, v) != nil {
		http.Error(w, "invalid JSON body", 400)
		return false
	}
	return true
}

func (s *server) createRole(w http.ResponseWriter, r *http.Request) {
	var p rolePayload
	if !readJSON(w, r, &p) {
		return
	}
	role, err := s.roles.upsert(p.Name, p.Label, p.Description, p.Permissions, true)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, 201, role)
}

func (s *server) updateRole(w http.ResponseWriter, r *http.Request) {
	var p rolePayload
	if !readJSON(w, r, &p) {
		return
	}
	role, err := s.roles.upsert(r.PathValue("name"), p.Label, p.Description, p.Permissions, false)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, 200, role)
}

func (s *server) deleteRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	for _, u := range s.auth.usersWithRoles() {
		if u["role"] == name {
			http.Error(w, "rola jest przypisana do operatora "+u["login"], 409)
			return
		}
	}
	if err := s.roles.remove(name); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

func (s *server) setUserRole(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Role string `json:"role"`
	}
	if !readJSON(w, r, &p) {
		return
	}
	if _, ok := s.roles.get(p.Role); !ok {
		http.Error(w, "nieznana rola", 400)
		return
	}
	login := r.PathValue("login")
	if err := s.auth.setRole(login, p.Role); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	who := "operator"
	if sess := s.auth.who(r); sess != nil {
		who = sess.Name
	}
	s.feed.Append("status", "", who+": ustawił(a) rolę "+p.Role+" operatorowi "+login, nil)
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

func (s *server) listAudit(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 || n > 1000 {
		n = 200
	}
	writeJSON(w, 200, map[string]interface{}{"items": s.audit.tail(n)})
}

// createCase adds a case by hand (e.g. an analyst's own finding).
func (s *server) createCase(w http.ResponseWriter, r *http.Request) {
	var p struct {
		SensorID  string  `json:"sensor_id"`
		Source    string  `json:"source"`
		EventType string  `json:"event_type"`
		Reason    string  `json:"reason"`
		Port      int     `json:"port"`
		Proto     string  `json:"proto"`
		Score     float64 `json:"score"`
	}
	if !readJSON(w, r, &p) {
		return
	}
	if strings.TrimSpace(p.Source) == "" || strings.TrimSpace(p.EventType) == "" {
		http.Error(w, "wymagane: source, event_type", 400)
		return
	}
	if p.SensorID == "" {
		p.SensorID = "manual"
	}
	if p.Reason == "" {
		p.Reason = "manual_entry"
	}
	idb := make([]byte, 6)
	rand.Read(idb)
	id := "manual-" + hex.EncodeToString(idb)
	env := map[string]interface{}{
		"event_id": id, "sensor_id": p.SensorID, "forward": true, "reason": p.Reason,
		"event": map[string]interface{}{"time": time.Now().UTC().Format(time.RFC3339), "type": p.EventType, "ip": p.Source, "port": p.Port, "proto": p.Proto},
	}
	raw, _ := json.Marshal(env)
	var e escalationEnvelope
	json.Unmarshal(raw, &e)
	c := caseFromEnvelope(raw, &e)
	c.Score = p.Score
	if _, err := s.store.AddEscalation(c); err != nil {
		http.Error(w, "persistence failed", 503)
		return
	}
	writeJSON(w, 201, map[string]string{"event_id": id})
}

func (s *server) deleteCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.store.Delete(id) {
		http.Error(w, "unknown event id", 404)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

// Delete removes a case from memory and disk; the append-only audit log keeps
// its history.
func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cases[id]; !ok {
		return false
	}
	delete(s.cases, id)
	os.Remove(filepath.Join(s.dir, "cases", id+".json"))
	s.recountSensors()
	return true
}
