package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegistrationClosed(t *testing.T) {
	s, _, _ := testServer(t) // already has an admin
	s.registrationClosed = true
	h := s.routes()
	w := call(t, h, "POST", "/api/register", `{"login":"intruder","name":"In Truder","password":"sekret1"}`, "")
	if w.Code != 403 {
		t.Fatalf("closed registration: got %d, want 403", w.Code)
	}
	if s.auth.roleOf("intruder") != "" {
		t.Fatal("account was created despite closed registration")
	}
	// Login keeps working.
	if w := call(t, h, "POST", "/api/login", `{"login":"janek","password":"testowe1"}`, ""); w.Code != 200 {
		t.Fatalf("login: %d", w.Code)
	}
	s.registrationClosed = false
	if w := call(t, h, "POST", "/api/register", `{"login":"ania","name":"Anna Lis","password":"sekret1"}`, ""); w.Code != 200 {
		t.Fatalf("open registration: %d", w.Code)
	}
}

func TestRegistrationClosedAllowsFirstAccount(t *testing.T) {
	dir := t.TempDir()
	a, err := openAuth(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{auth: a, feed: newLiveFeed(10), registrationClosed: true}
	h := s.routes()
	if w := call(t, h, "POST", "/api/register", `{"login":"root1","name":"Root One","password":"sekret1"}`, ""); w.Code != 200 {
		t.Fatalf("first account must be allowed: %d", w.Code)
	}
	if w := call(t, h, "POST", "/api/register", `{"login":"root2","name":"Root Two","password":"sekret1"}`, ""); w.Code != 403 {
		t.Fatalf("second account must be refused: %d", w.Code)
	}
}

func TestSeedAccounts(t *testing.T) {
	dir := t.TempDir()
	pwf := filepath.Join(dir, "pw")
	os.WriteFile(pwf, []byte("adminpass1\n"), 0o600)
	t.Setenv("ASI_ADMIN_LOGIN", "boss")
	t.Setenv("ASI_ADMIN_PASSWORD_FILE", pwf)
	t.Setenv("ASI_VIEWER_LOGIN", "jury")
	t.Setenv("ASI_VIEWER_PASSWORD", "viewpass1")
	a, err := openAuth(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := seedAccounts(a); err != nil {
		t.Fatal(err)
	}
	if a.roleOf("boss") != "admin" || a.roleOf("jury") != "viewer" {
		t.Fatalf("roles: boss=%q jury=%q", a.roleOf("boss"), a.roleOf("jury"))
	}
	if _, err := a.login("boss", "adminpass1"); err != nil {
		t.Fatalf("admin login: %v", err)
	}
	// Idempotent: a changed env password does not overwrite an existing account.
	t.Setenv("ASI_VIEWER_PASSWORD", "other-pass")
	if err := seedAccounts(a); err != nil {
		t.Fatal(err)
	}
	if _, err := a.login("jury", "viewpass1"); err != nil {
		t.Fatalf("viewer password was reset: %v", err)
	}
	// The viewer is read-only through the full router.
	s, _, _ := testServer(t)
	tok := userWithRole(t, s, "jury2", "viewer")
	h := s.routes()
	if w := call(t, h, "GET", "/api/alerts", "", tok); w.Code != 200 {
		t.Fatalf("viewer read: %d", w.Code)
	}
	if w := call(t, h, "POST", "/api/exposure/run", `{}`, tok); w.Code != 403 {
		t.Fatalf("viewer write: %d", w.Code)
	}
}

func TestSeedAccountsNeedsPassword(t *testing.T) {
	t.Setenv("ASI_ADMIN_LOGIN", "boss")
	a, _ := openAuth(t.TempDir())
	if err := seedAccounts(a); err == nil {
		t.Fatal("expected error without password")
	}
}
