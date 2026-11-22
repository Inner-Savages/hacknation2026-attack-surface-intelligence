package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Inner-Savages/silence-on-the-wire/internal/atrest"
)

// call performs a request against the router with a session token.
func call(t *testing.T, h http.Handler, method, url, body, tok string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	if tok != "" {
		req = withAuth(req, tok)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// userWithRole registers an account, assigns the role and returns its session.
func userWithRole(t *testing.T, s *server, login, role string) string {
	t.Helper()
	u, err := s.auth.register(login, "User "+login, "haslo123")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.auth.setRole(login, role); err != nil {
		t.Fatal(err)
	}
	return s.auth.newSession(u).Token
}

func TestRoleMatrix(t *testing.T) {
	s, _, adminTok := testServer(t)
	h := s.routes()
	if _, err := s.store.AddEscalation(caseFromEnvelope([]byte(escalation("ev-1", "s1")), mustEnv(escalation("ev-1", "s1")))); err != nil {
		t.Fatal(err)
	}
	type tc struct {
		method, url, body string
		// expected allowed per role: viewer, analyst, editor, admin
		allow [4]bool
	}
	cases := []tc{
		{"GET", "/api/alerts", "", [4]bool{true, true, true, true}},
		{"GET", "/api/rules", "", [4]bool{true, true, true, true}},
		{"POST", "/api/alerts/ev-1/notes", `{"text":"x"}`, [4]bool{false, true, true, true}},
		{"POST", "/api/alerts/ev-1/status", `{"status":"zamkniety"}`, [4]bool{false, true, true, true}},
		{"POST", "/api/cases", `{"source":"10.1.1.1","event_type":"host_new"}`, [4]bool{false, false, true, true}},
		{"PUT", "/api/rules", `[]`, [4]bool{false, false, true, true}},
		{"GET", "/api/config", "", [4]bool{false, false, false, true}},
		{"POST", "/api/config", `{"rule_mode":false}`, [4]bool{false, false, false, true}},
		{"GET", "/api/users", "", [4]bool{false, false, false, true}},
		{"GET", "/api/roles", "", [4]bool{false, false, false, true}},
		{"GET", "/api/audit", "", [4]bool{false, false, false, true}},
		{"DELETE", "/api/cases/ev-1", "", [4]bool{false, false, true, true}}, // last: removes the case
	}
	toks := [4]string{
		userWithRole(t, s, "vera", "viewer"), userWithRole(t, s, "anna", "analyst"),
		userWithRole(t, s, "edek", "editor"), adminTok,
	}
	names := [4]string{"viewer", "analyst", "editor", "admin"}
	for _, c := range cases {
		for i, tok := range toks {
			if c.method == "DELETE" && c.url == "/api/cases/ev-1" && i >= 2 {
				// recreate between runs so editor and admin both hit a real case
				s.store.AddEscalation(caseFromEnvelope([]byte(escalation("ev-1", "s1")), mustEnv(escalation("ev-1", "s1"))))
			}
			w := call(t, h, c.method, c.url, c.body, tok)
			denied := w.Code == 403
			if c.allow[i] == denied {
				t.Errorf("%s %s as %s: code %d, allowed want %v", c.method, c.url, names[i], w.Code, c.allow[i])
			}
		}
	}
}

func mustEnv(raw string) *escalationEnvelope {
	var e escalationEnvelope
	json.Unmarshal([]byte(raw), &e)
	return &e
}

func TestViewerCannotWriteAnywhere(t *testing.T) {
	s, _, _ := testServer(t)
	h := s.routes()
	tok := userWithRole(t, s, "vera", "viewer")
	for _, r := range [][2]string{
		{"POST", "/api/alerts/x/status"}, {"POST", "/api/alerts/x/assign"}, {"POST", "/api/alerts/x/actions"},
		{"POST", "/api/alerts/x/analysis"}, {"POST", "/api/alerts/x/operator"}, {"PUT", "/api/rules"},
		{"POST", "/api/rules/apply"}, {"POST", "/api/config"}, {"POST", "/api/groundtruth/run"},
		{"POST", "/api/users/vera/role"}, {"DELETE", "/api/users/vera"}, {"POST", "/api/roles"},
	} {
		if w := call(t, h, r[0], r[1], `{}`, tok); w.Code != 403 {
			t.Errorf("viewer %s %s = %d, want 403", r[0], r[1], w.Code)
		}
	}
	// Unauthenticated requests are 401, not 403.
	if w := call(t, h, "GET", "/api/alerts", "", ""); w.Code != 401 {
		t.Errorf("anonymous = %d", w.Code)
	}
}

func TestMachineIntakeUnaffectedByRBAC(t *testing.T) {
	s, _, _ := testServer(t)
	h := s.routes()
	req := httptest.NewRequest("POST", "/events", strings.NewReader(escalation("m-1", "s9")))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 202 {
		t.Fatalf("intake with bearer token: %d", w.Code)
	}
	req = httptest.NewRequest("POST", "/events", strings.NewReader(escalation("m-2", "s9")))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("intake without token: %d", w.Code)
	}
}

func TestFirstAccountIsAdminOthersAnalyst(t *testing.T) {
	s, _, _ := testServer(t)
	if r := s.auth.roleOf("janek"); r != "admin" {
		t.Fatalf("first account role %q", r)
	}
	s.auth.register("ania", "Anna", "haslo123")
	if r := s.auth.roleOf("ania"); r != defaultRole {
		t.Fatalf("second account role %q", r)
	}
}

func TestCustomRoleLifecycle(t *testing.T) {
	s, _, adminTok := testServer(t)
	h := s.routes()
	w := call(t, h, "POST", "/api/roles", `{"name":"auditor","label":"Audytor","permissions":["cases:read","audit:read"]}`, adminTok)
	if w.Code != 201 {
		t.Fatalf("create role: %d %s", w.Code, w.Body)
	}
	if w := call(t, h, "POST", "/api/roles", `{"name":"x","permissions":["nope"]}`, adminTok); w.Code != 400 {
		t.Fatalf("unknown permission accepted: %d", w.Code)
	}
	if w := call(t, h, "POST", "/api/roles", `{"name":"viewer","permissions":[]}`, adminTok); w.Code != 400 {
		t.Fatalf("builtin overwritten: %d", w.Code)
	}
	u, _ := s.auth.register("audi", "Audi T", "haslo123")
	tok := s.auth.newSession(u).Token
	if w := call(t, h, "POST", "/api/users/audi/role", `{"role":"auditor"}`, adminTok); w.Code != 200 {
		t.Fatalf("assign: %d %s", w.Code, w.Body)
	}
	// Permission-based: auditor reads the audit log but cannot read config or write cases.
	if w := call(t, h, "GET", "/api/audit", "", tok); w.Code != 200 {
		t.Fatalf("auditor audit: %d", w.Code)
	}
	if w := call(t, h, "POST", "/api/alerts/x/notes", `{}`, tok); w.Code != 403 {
		t.Fatalf("auditor write: %d", w.Code)
	}
	// Role in use cannot be deleted; unused can.
	if w := call(t, h, "DELETE", "/api/roles/auditor", "", adminTok); w.Code != 409 {
		t.Fatalf("delete in-use role: %d", w.Code)
	}
	// Editing the role takes effect immediately for existing sessions.
	call(t, h, "PUT", "/api/roles/auditor", `{"permissions":["cases:read"]}`, adminTok)
	if w := call(t, h, "GET", "/api/audit", "", tok); w.Code != 403 {
		t.Fatalf("edited role still grants audit: %d", w.Code)
	}
	call(t, h, "POST", "/api/users/audi/role", `{"role":"viewer"}`, adminTok)
	if w := call(t, h, "DELETE", "/api/roles/auditor", "", adminTok); w.Code != 200 {
		t.Fatalf("delete unused role: %d", w.Code)
	}
	// Built-ins are immutable and the last admin keeps the admin role.
	if w := call(t, h, "PUT", "/api/roles/viewer", `{"permissions":["cases:update"]}`, adminTok); w.Code != 400 {
		t.Fatalf("builtin modified: %d", w.Code)
	}
	if w := call(t, h, "POST", "/api/users/janek/role", `{"role":"viewer"}`, adminTok); w.Code != 400 {
		t.Fatalf("last admin demoted: %d", w.Code)
	}
}

func TestAuditRecordsChangesNotReads(t *testing.T) {
	s, _, adminTok := testServer(t)
	dir := t.TempDir()
	s.audit = openAudit(dir)
	h := s.routes()
	tok := userWithRole(t, s, "edek", "editor")
	call(t, h, "GET", "/api/alerts", "", tok)
	call(t, h, "POST", "/api/cases", `{"source":"10.2.2.2","event_type":"host_new"}`, tok)
	call(t, h, "POST", "/api/alerts/none/status", `{"status":"zamkniety"}`, tok) // 404: not recorded
	call(t, h, "POST", "/api/config", `{"ai_api_key":"sk-TOPSECRET"}`, adminTok)
	recs := s.audit.tail(50)
	if len(recs) != 2 {
		t.Fatalf("want 2 audit records, got %+v", recs)
	}
	if recs[1].Actor != "edek" || recs[1].Role != "editor" || recs[1].Path != "/api/cases" {
		t.Fatalf("bad record %+v", recs[1])
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "changes-audit.jsonl"))
	if bytes.Contains(raw, []byte("TOPSECRET")) {
		t.Fatal("request body leaked into the audit log")
	}
}

func TestRBACMeEndpoint(t *testing.T) {
	s, _, _ := testServer(t)
	tok := userWithRole(t, s, "vera", "viewer")
	w := call(t, s.routes(), "GET", "/api/rbac/me", "", tok)
	var me struct {
		Role        string   `json:"role"`
		Permissions []string `json:"permissions"`
	}
	json.Unmarshal(w.Body.Bytes(), &me)
	if me.Role != "viewer" || len(me.Permissions) == 0 {
		t.Fatalf("%+v", me)
	}
	for _, p := range me.Permissions {
		if strings.HasSuffix(p, ":write") || strings.HasSuffix(p, ":update") || strings.HasSuffix(p, ":delete") {
			t.Fatalf("viewer has write permission %s", p)
		}
	}
}

// --- encryption at rest through the console stores --------------------------

func withKey(t *testing.T, b byte) {
	t.Helper()
	c, err := atrest.New(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	old := rest
	rest = c
	t.Cleanup(func() { rest = old })
}

func TestStoresEncryptedAtRest(t *testing.T) {
	withKey(t, 7)
	dir := t.TempDir()
	st, _ := openSettings(dir)
	if err := st.update(configPatch{AIAPIKey: strPtr("sk-VERYSECRET")}); err != nil {
		t.Fatal(err)
	}
	a, _ := openAuth(dir)
	if _, err := a.register("janek", "Janek", "haslo123"); err != nil {
		t.Fatal(err)
	}
	store, _ := openStore(dir)
	c := caseFromEnvelope([]byte(escalation("e-1", "s1")), mustEnv(escalation("e-1", "s1")))
	if _, err := store.AddEscalation(c); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"settings.json", "users.json", "cases/e-1.json", "audit.jsonl"} {
		raw, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("VERYSECRET")) || bytes.Contains(raw, []byte("janek")) || bytes.Contains(raw, []byte("10.0.4.17")) {
			t.Fatalf("%s contains plaintext: %.80q", f, raw)
		}
		if !bytes.HasPrefix(raw, []byte("ASIE")) {
			t.Fatalf("%s lacks the encryption header", f)
		}
	}
	// Reopen with the right key: everything is back.
	st2, err := openSettings(dir)
	if err != nil || st2.snapshot().AIAPIKey != "sk-VERYSECRET" {
		t.Fatalf("settings reopen: %v", err)
	}
	if a2, err := openAuth(dir); err != nil || !a2.hasUsers() {
		t.Fatalf("auth reopen: %v", err)
	}
	if s2, err := openStore(dir); err != nil || len(s2.ListCases()) != 1 {
		t.Fatalf("store reopen: %v", err)
	}
	// Wrong key: opening fails loudly instead of silently starting empty.
	withKey(t, 8)
	if _, err := openSettings(dir); err == nil {
		t.Fatal("settings opened with the wrong key")
	}
	if _, err := openAuth(dir); err == nil {
		t.Fatal("auth opened with the wrong key")
	}
	if _, err := openStore(dir); err == nil {
		t.Fatal("store opened with the wrong key")
	}
	// Corrupted ciphertext is rejected too.
	withKey(t, 7)
	p := filepath.Join(dir, "settings.json")
	raw, _ := os.ReadFile(p)
	raw[len(raw)-2] ^= 0xff
	os.WriteFile(p, raw, 0o600)
	if _, err := openSettings(dir); err == nil {
		t.Fatal("corrupted settings accepted")
	}
}

func TestLegacyPlaintextMigratesOnWrite(t *testing.T) {
	dir := t.TempDir()
	// Written by an older console version: plaintext users.json without roles.
	os.WriteFile(filepath.Join(dir, "users.json"), []byte(`[{"login":"old","name":"Old","salt":"s","hash":"h","admin":true,"created_at":"x"}]`), 0o600)
	withKey(t, 9)
	a, err := openAuth(dir)
	if err != nil || a.roleOf("old") != "admin" {
		t.Fatalf("legacy load: %v role=%q", err, a.roleOf("old"))
	}
	if _, err := a.register("newbie", "New", "haslo123"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "users.json"))
	if !atrest.IsEncrypted(raw) {
		t.Fatal("users.json not migrated to ciphertext on write")
	}
}

func strPtr(s string) *string { return &s }
