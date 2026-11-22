package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// auth manages console operator accounts. Passwords are stored as
// PBKDF2-HMAC-SHA256 (120k iterations, per-user salt) — no external
// dependencies. Sessions are random bearer tokens kept in memory; a restart
// simply asks operators to log in again.
type auth struct {
	mu       sync.Mutex
	path     string
	users    map[string]*user // key: lowercased login
	sessions map[string]*session
}

type user struct {
	Login     string `json:"login"`
	Name      string `json:"name"`
	Salt      string `json:"salt"`
	Hash      string `json:"hash"`
	Admin     bool   `json:"admin"`
	CreatedAt string `json:"created_at"`
}

type session struct {
	Token   string
	Login   string
	Name    string
	Admin   bool
	Expires time.Time
}

const (
	pbkdf2Rounds = 120_000
	sessionTTL   = 12 * time.Hour
)

func openAuth(dir string) (*auth, error) {
	a := &auth{
		path:     filepath.Join(dir, "users.json"),
		users:    map[string]*user{},
		sessions: map[string]*session{},
	}
	b, err := os.ReadFile(a.path)
	if os.IsNotExist(err) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	var list []*user
	if json.Unmarshal(b, &list) != nil {
		return nil, fmt.Errorf("corrupt users.json")
	}
	for _, u := range list {
		a.users[strings.ToLower(u.Login)] = u
	}
	return a, nil
}

func (a *auth) hasUsers() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.users) > 0
}

func pbkdf2Key(password, salt string, rounds int) []byte {
	// PBKDF2-HMAC-SHA256 with a single 32-byte block, per RFC 2898:
	// U1 = PRF(P, S || INT32_BE(1)), Ui = PRF(P, U_{i-1}), key = U1 ⊕ … ⊕ Uc.
	saltBytes, _ := base64.RawStdEncoding.DecodeString(salt)
	var block [4]byte
	binary.BigEndian.PutUint32(block[:], 1)
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(saltBytes)
	mac.Write(block[:])
	u := mac.Sum(nil)
	out := append([]byte{}, u...)
	for i := 1; i < rounds; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(nil)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a *auth) persistLocked() error {
	list := make([]*user, 0, len(a.users))
	for _, u := range a.users {
		list = append(list, u)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.path)
}

// register creates an account. The very first account becomes the admin.
func (a *auth) register(login, name, password string) (*user, error) {
	login = strings.TrimSpace(login)
	name = strings.TrimSpace(name)
	if len(login) < 3 || strings.ContainsAny(login, " \t\n") {
		return nil, fmt.Errorf("login musi mieć co najmniej 3 znaki, bez spacji")
	}
	if name == "" {
		return nil, fmt.Errorf("podaj imię i nazwisko operatora")
	}
	if len(password) < 6 {
		return nil, fmt.Errorf("hasło musi mieć co najmniej 6 znaków")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	key := strings.ToLower(login)
	if _, exists := a.users[key]; exists {
		return nil, fmt.Errorf("login jest już zajęty")
	}
	salt := randomToken()[:22]
	u := &user{
		Login: login, Name: name, Salt: salt,
		Hash:      base64.RawStdEncoding.EncodeToString(pbkdf2Key(password, salt, pbkdf2Rounds)),
		Admin:     len(a.users) == 0, // first operator administers the console
		CreatedAt: time.Now().Format(time.RFC3339),
	}
	a.users[key] = u
	if err := a.persistLocked(); err != nil {
		delete(a.users, key)
		return nil, err
	}
	return u, nil
}

// login verifies credentials and returns a fresh session.
func (a *auth) login(login, password string) (*session, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, ok := a.users[strings.ToLower(strings.TrimSpace(login))]
	if !ok {
		return nil, fmt.Errorf("błędny login lub hasło")
	}
	got := pbkdf2Key(password, u.Salt, pbkdf2Rounds)
	want, _ := base64.RawStdEncoding.DecodeString(u.Hash)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return nil, fmt.Errorf("błędny login lub hasło")
	}
	s := &session{Token: randomToken(), Login: u.Login, Name: u.Name, Admin: u.Admin, Expires: time.Now().Add(sessionTTL)}
	a.sessions[s.Token] = s
	return s, nil
}

// newSession issues a session for an already-authenticated user.
func (a *auth) newSession(u *user) *session {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := &session{Token: randomToken(), Login: u.Login, Name: u.Name, Admin: u.Admin, Expires: time.Now().Add(sessionTTL)}
	a.sessions[s.Token] = s
	return s
}

// who resolves the session for a request: cookie first, then the bearer
// header. Returns nil when there is no valid session.
func (a *auth) who(r *http.Request) *session {
	token := ""
	if c, err := r.Cookie("sotw_session"); err == nil {
		token = c.Value
	}
	if token == "" {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if token == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[token]
	if !ok || time.Now().After(s.Expires) {
		delete(a.sessions, token)
		return nil
	}
	return s
}

// list returns all accounts, admins first, for the operators panel.
func (a *auth) list() []*user {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*user, 0, len(a.users))
	for _, u := range a.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Admin != out[j].Admin {
			return out[i].Admin
		}
		return out[i].Login < out[j].Login
	})
	return out
}

// setAdmin grants or revokes the admin flag. The last remaining admin cannot
// be demoted — otherwise the console would be locked out of its settings.
func (a *auth) setAdmin(login string, admin bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, ok := a.users[strings.ToLower(strings.TrimSpace(login))]
	if !ok {
		return fmt.Errorf("nie ma takiego operatora")
	}
	if !admin && u.Admin {
		admins := 0
		for _, x := range a.users {
			if x.Admin {
				admins++
			}
		}
		if admins <= 1 {
			return fmt.Errorf("nie można odebrać uprawnień ostatniemu administratorowi")
		}
	}
	u.Admin = admin
	for _, s := range a.sessions {
		if s.Login == u.Login {
			s.Admin = admin
		}
	}
	return a.persistLocked()
}

func (a *auth) logout(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, token)
}
