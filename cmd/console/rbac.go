package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Permissions are the unit of access control; roles are named sets of them.
// Endpoints require a permission (see routePerms), never a role name, so
// custom roles work without touching handlers.
const (
	PermCasesRead   = "cases:read"
	PermCasesCreate = "cases:create"
	PermCasesUpdate = "cases:update"
	PermCasesDelete = "cases:delete"
	PermSensorsRead = "sensors:read"
	PermLogsRead    = "logs:read"
	PermRulesRead   = "rules:read"
	PermRulesWrite  = "rules:write"
	PermConfigRead  = "config:read"
	PermConfigWrite = "config:write"
	PermScanRun     = "groundtruth:run"
	PermExposureRun = "exposure:run"
	PermUsersManage = "users:manage"
	PermRolesManage = "roles:manage"
	PermAuditRead   = "audit:read"

	PermTargetsRead    = "targets:read"    // inventory, targets, overrides: read
	PermTargetsWrite   = "targets:write"   // add/delete targets, import files and scans
	PermOverridesWrite = "overrides:write" // edit/restore user overrides

	PermTLSRead = "tls:read" // TLS certificate inventory and findings
	PermTLSRun  = "tls:run"  // trigger an on-demand TLS policy pass

	PermAssetsRead = "assets:read" // passive device classification (asset inventory)
	PermRiskRead   = "risk:read"   // per-host risk ranking
)

// permCatalog lists every permission with a description for the role editor.
var permCatalog = []struct{ Perm, Desc string }{
	{PermCasesRead, "Odczyt alertów i podsumowań"},
	{PermCasesCreate, "Dodawanie spraw (ręczne zgłoszenie)"},
	{PermCasesUpdate, "Modyfikacja spraw: status, przypisanie, notatki, akcje, analiza"},
	{PermCasesDelete, "Usuwanie spraw"},
	{PermSensorsRead, "Odczyt sensorów i ground truth"},
	{PermLogsRead, "Odczyt logów live"},
	{PermRulesRead, "Odczyt reguł triage"},
	{PermRulesWrite, "Zmiana i stosowanie reguł triage"},
	{PermConfigRead, "Odczyt ustawień konsoli"},
	{PermConfigWrite, "Zmiana ustawień konsoli (klucze AI, tryby)"},
	{PermScanRun, "Uruchamianie skanów ground truth"},
	{PermExposureRun, "Uruchamianie kontroli ekspozycji"},
	{PermUsersManage, "Zarządzanie kontami operatorów"},
	{PermRolesManage, "Tworzenie i edycja ról"},
	{PermAuditRead, "Odczyt dziennika audytu zmian"},
	{PermTargetsRead, "Odczyt celów, inwentarza i nadpisań"},
	{PermTargetsWrite, "Dodawanie i usuwanie celów, import list celów i wyników skanów"},
	{PermOverridesWrite, "Edycja nadpisań użytkownika (tytuł, tagi, notatka, status)"},
	{PermTLSRead, "Odczyt monitoringu certyfikatów TLS"},
	{PermTLSRun, "Uruchamianie kontroli TLS na żądanie"},
	{PermAssetsRead, "Odczyt inwentarza zasobów (klasyfikacja urządzeń)"},
	{PermRiskRead, "Odczyt rankingu ryzyka hostów"},
}

func validPerm(p string) bool {
	for _, c := range permCatalog {
		if c.Perm == p {
			return true
		}
	}
	return false
}

// Role is a named permission set. Built-in roles are immutable.
type Role struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	Builtin     bool     `json:"builtin"`
}

const defaultRole = "analyst" // new self-registered accounts keep today's working rights

func builtinRoles() []*Role {
	read := []string{PermCasesRead, PermSensorsRead, PermLogsRead, PermRulesRead, PermTargetsRead, PermTLSRead, PermAssetsRead, PermRiskRead}
	analyst := append(append([]string{}, read...), PermCasesUpdate, PermOverridesWrite)
	editor := append(append([]string{}, analyst...), PermCasesCreate, PermCasesDelete, PermRulesWrite, PermScanRun, PermExposureRun, PermTargetsWrite, PermTLSRun)
	all := make([]string, 0, len(permCatalog))
	for _, c := range permCatalog {
		all = append(all, c.Perm)
	}
	return []*Role{
		{Name: "admin", Label: "Administracja", Description: "Pełny dostęp, w tym użytkownicy, role, ustawienia i audyt", Permissions: all, Builtin: true},
		{Name: "editor", Label: "Edytor", Description: "Dodawanie, usuwanie i modyfikacja danych", Permissions: editor, Builtin: true},
		{Name: "analyst", Label: "Analityk", Description: "Modyfikacja i odczyt spraw", Permissions: analyst, Builtin: true},
		{Name: "viewer", Label: "Podgląd", Description: "Tylko odczyt", Permissions: read, Builtin: true},
	}
}

var roleNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,31}$`)

// roleStore keeps built-in and custom roles; custom ones persist (encrypted)
// in roles.json.
type roleStore struct {
	mu     sync.Mutex
	path   string
	custom map[string]*Role
}

func openRoles(dir string) (*roleStore, error) {
	rs := &roleStore{path: filepath.Join(dir, "roles.json"), custom: map[string]*Role{}}
	b, err := rest.ReadFile(rs.path)
	if err != nil {
		if os.IsNotExist(err) {
			return rs, nil
		}
		return nil, err
	}
	var list []*Role
	if json.Unmarshal(b, &list) != nil {
		return nil, fmt.Errorf("corrupt roles.json")
	}
	for _, r := range list {
		r.Builtin = false
		rs.custom[r.Name] = r
	}
	return rs, nil
}

func (rs *roleStore) saveLocked() error {
	list := make([]*Role, 0, len(rs.custom))
	for _, r := range rs.custom {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil || rs.path == "" {
		return err
	}
	return rest.WriteFile(rs.path, b, 0o600)
}

func (rs *roleStore) get(name string) (*Role, bool) {
	for _, r := range builtinRoles() {
		if r.Name == name {
			return r, true
		}
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	r, ok := rs.custom[name]
	if !ok {
		return nil, false
	}
	cp := *r
	cp.Permissions = append([]string{}, r.Permissions...)
	return &cp, true
}

func (rs *roleStore) list() []*Role {
	out := builtinRoles()
	rs.mu.Lock()
	defer rs.mu.Unlock()
	names := make([]string, 0, len(rs.custom))
	for n := range rs.custom {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		cp := *rs.custom[n]
		out = append(out, &cp)
	}
	return out
}

func (rs *roleStore) has(perms []string, p string) bool {
	for _, x := range perms {
		if x == p {
			return true
		}
	}
	return false
}

// can reports whether the role grants the permission. Unknown role: no rights.
func (rs *roleStore) can(role, perm string) bool {
	r, ok := rs.get(role)
	return ok && rs.has(r.Permissions, perm)
}

func normPerms(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, p := range in {
		p = strings.TrimSpace(p)
		if !validPerm(p) {
			return nil, fmt.Errorf("nieznane uprawnienie: %q", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (rs *roleStore) upsert(name, label, desc string, perms []string, create bool) (*Role, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !roleNameRe.MatchString(name) {
		return nil, fmt.Errorf("nazwa roli: 2–32 znaków a-z, 0-9, _ lub -")
	}
	for _, b := range builtinRoles() {
		if b.Name == name {
			return nil, fmt.Errorf("rola wbudowana %q jest niezmienna", name)
		}
	}
	np, err := normPerms(perms)
	if err != nil {
		return nil, err
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	_, exists := rs.custom[name]
	if create && exists {
		return nil, fmt.Errorf("rola %q już istnieje", name)
	}
	if !create && !exists {
		return nil, fmt.Errorf("nie ma roli %q", name)
	}
	if strings.TrimSpace(label) == "" {
		label = name
	}
	r := &Role{Name: name, Label: strings.TrimSpace(label), Description: strings.TrimSpace(desc), Permissions: np}
	old := rs.custom[name]
	rs.custom[name] = r
	if err := rs.saveLocked(); err != nil {
		if old != nil {
			rs.custom[name] = old
		} else {
			delete(rs.custom, name)
		}
		return nil, err
	}
	return r, nil
}

func (rs *roleStore) remove(name string) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	old, ok := rs.custom[name]
	if !ok {
		return fmt.Errorf("nie ma roli niestandardowej %q", name)
	}
	delete(rs.custom, name)
	if err := rs.saveLocked(); err != nil {
		rs.custom[name] = old
		return err
	}
	return nil
}

// routePerms maps a mux pattern to the permission it requires. Patterns not
// listed here and not in publicRoutes are denied (default deny), so a new
// endpoint cannot be left unprotected by accident.
var routePerms = map[string]string{
	"GET /api/summary":               PermCasesRead,
	"GET /api/alerts":                PermCasesRead,
	"GET /api/alerts/{id}":           PermCasesRead,
	"POST /api/alerts/{id}/status":   PermCasesUpdate,
	"POST /api/alerts/{id}/assign":   PermCasesUpdate,
	"POST /api/alerts/{id}/notes":    PermCasesUpdate,
	"POST /api/alerts/{id}/actions":  PermCasesUpdate,
	"POST /api/alerts/{id}/analysis": PermCasesUpdate,
	"POST /api/alerts/{id}/operator": PermCasesUpdate,
	"POST /api/cases":                PermCasesCreate,
	"DELETE /api/cases/{id}":         PermCasesDelete,
	"GET /api/sensors":               PermSensorsRead,
	"GET /api/logs":                  PermLogsRead,
	"GET /api/ai/status":             PermCasesRead,
	"GET /api/rules":                 PermRulesRead,
	"PUT /api/rules":                 PermRulesWrite,
	"POST /api/rules/apply":          PermRulesWrite,
	"GET /api/config":                PermConfigRead,
	"POST /api/config":               PermConfigWrite,
	"GET /api/map":                   PermCasesRead,
	"GET /api/exposure":              PermSensorsRead,
	"POST /api/exposure/run":         PermExposureRun,
	"GET /api/risk":                  PermRiskRead,
	"GET /api/assets":                PermAssetsRead,
	"GET /api/assets/{ip}":           PermAssetsRead,
	"GET /api/tls":                   PermTLSRead,
	"POST /api/tls/run":              PermTLSRun,
	"GET /api/groundtruth":           PermSensorsRead,
	"POST /api/groundtruth/run":      PermScanRun,
	"GET /api/users":                 PermUsersManage,
	"POST /api/users/{login}/admin":  PermUsersManage,
	"DELETE /api/users/{login}":      PermUsersManage,
	"POST /api/users/{login}/role":   PermUsersManage,
	"GET /api/rbac/users":            PermUsersManage,
	"GET /api/roles":                 PermRolesManage,
	"POST /api/roles":                PermRolesManage,
	"PUT /api/roles/{name}":          PermRolesManage,
	"DELETE /api/roles/{name}":       PermRolesManage,
	"GET /api/audit":                 PermAuditRead,
	"GET /api/inventory":             PermTargetsRead,
	"GET /api/inventory/diff":        PermTargetsRead,
	"GET /api/imports":               PermTargetsRead,
	"GET /api/targets":               PermTargetsRead,
	"GET /api/targets.txt":           PermTargetsRead,
	"POST /api/targets":              PermTargetsWrite,
	"DELETE /api/targets/{value}":    PermTargetsWrite,
	"POST /api/import":               PermTargetsWrite,
	"GET /api/overrides":             PermTargetsRead,
	"GET /api/overrides/{key}":       PermTargetsRead,
	"PUT /api/overrides/{key}":       PermOverridesWrite,
	"DELETE /api/overrides/{key}":    PermOverridesWrite,
	"GET /api/rbac/me":               "", // any logged-in operator
}

// publicRoutes bypass operator RBAC: account bootstrap and machine intake
// (which authenticates with its own bearer token).
var publicRoutes = map[string]bool{
	"POST /api/register": true, "POST /api/login": true, "POST /api/logout": true,
	"GET /api/me": true, "POST /events": true, "POST /logs": true, "POST /findings": true, "GET /health": true,
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = 200
	}
	return w.ResponseWriter.Write(b)
}
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// rbac wraps the router: it resolves the required permission from the matched
// pattern, answers 401/403, and records every successful state change in the
// audit log (who, what, when).
func (s *server) rbac(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		if pattern == "" || publicRoutes[pattern] {
			mux.ServeHTTP(w, r)
			return
		}
		perm, known := routePerms[pattern]
		if !known {
			http.Error(w, "forbidden: endpoint has no permission mapping", 403)
			return
		}
		if !s.auth.hasUsers() {
			http.Error(w, "setup required", 401)
			return
		}
		sess := s.auth.who(r)
		if sess == nil {
			http.Error(w, "authentication required", 401)
			return
		}
		role := s.auth.roleOf(sess.Login)
		if perm != "" && !s.roles.can(role, perm) {
			http.Error(w, "forbidden: missing permission "+perm, 403)
			return
		}
		sw := &statusWriter{ResponseWriter: w}
		mux.ServeHTTP(sw, r)
		if r.Method != http.MethodGet && sw.code > 0 && sw.code < 400 {
			s.audit.record(sess.Login, role, r.Method, r.URL.Path, sw.code)
		}
	})
}
