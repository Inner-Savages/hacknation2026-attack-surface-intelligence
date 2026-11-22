package atrest

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testCipher(t *testing.T, b byte) *Cipher {
	t.Helper()
	c, err := New(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRoundTripAndNotPlaintext(t *testing.T) {
	c := testCipher(t, 1)
	plain := []byte(`{"ai_api_key":"sk-secret"}`)
	blob, err := c.Seal(plain, "settings.json")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("sk-secret")) || !IsEncrypted(blob) {
		t.Fatal("blob leaks plaintext or lacks header")
	}
	got, err := c.Open(blob, "settings.json")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip: %v %q", err, got)
	}
	// Fresh nonce per seal.
	blob2, _ := c.Seal(plain, "settings.json")
	if bytes.Equal(blob, blob2) {
		t.Fatal("nonce reuse")
	}
}

func TestWrongKeyAADAndCorruption(t *testing.T) {
	c := testCipher(t, 1)
	blob, _ := c.Seal([]byte("hello"), "a.json")
	if _, err := testCipher(t, 2).Open(blob, "a.json"); err != ErrDecrypt {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := c.Open(blob, "b.json"); err != ErrDecrypt {
		t.Fatalf("swapped file name accepted: %v", err)
	}
	bad := append([]byte{}, blob...)
	bad[len(bad)-1] ^= 0xff
	if _, err := c.Open(bad, "a.json"); err != ErrDecrypt {
		t.Fatalf("tampered blob accepted: %v", err)
	}
	if _, err := c.Open(blob[:len(magic)+3], "a.json"); err != ErrDecrypt {
		t.Fatalf("truncated blob accepted: %v", err)
	}
	if _, err := (*Cipher)(nil).Open(blob, "a.json"); err == nil {
		t.Fatal("encrypted file opened without a key")
	}
}

func TestFileLegacyPlaintextAndMigration(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "users.json")
	os.WriteFile(p, []byte(`[{"login":"a"}]`), 0o600)
	c := testCipher(t, 3)
	got, err := c.ReadFile(p)
	if err != nil || string(got) != `[{"login":"a"}]` {
		t.Fatalf("legacy read: %v %q", err, got)
	}
	if err := c.WriteFile(p, got, 0o600); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if !IsEncrypted(raw) || strings.Contains(string(raw), "login") {
		t.Fatal("file not migrated to ciphertext")
	}
	if got2, err := c.ReadFile(p); err != nil || string(got2) != string(got) {
		t.Fatalf("read after migration: %v", err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("tmp file left behind")
	}
}

func TestLines(t *testing.T) {
	c := testCipher(t, 4)
	l, _ := c.SealLine([]byte(`{"x":1}`), "audit")
	if strings.Contains(string(l), "x") && strings.Contains(string(l), `{"x"`) || bytes.Contains(l, []byte("\n")) {
		t.Fatal("bad line")
	}
	got, err := c.OpenLine(l, "audit")
	if err != nil || string(got) != `{"x":1}` {
		t.Fatalf("%v %q", err, got)
	}
	if got, _ := c.OpenLine([]byte(`{"old":1}`), "audit"); string(got) != `{"old":1}` {
		t.Fatal("plain line must pass through")
	}
}

func TestLoadKey(t *testing.T) {
	dir := t.TempDir()
	kf := filepath.Join(dir, "sub", "data.key")
	k1, src, err := LoadKey("", kf)
	if err != nil || len(k1) != 32 || !strings.Contains(src, "generated") {
		t.Fatalf("generate: %v %s", err, src)
	}
	if st, _ := os.Stat(kf); st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v", st.Mode())
	}
	k2, _, err := LoadKey("", kf)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatal("key not stable across restarts")
	}
	envKey := strings.Repeat("ab", 32)
	k3, src, err := LoadKey(envKey, kf)
	if err != nil || src != "env" || len(k3) != 32 {
		t.Fatalf("env: %v", err)
	}
	if _, _, err := LoadKey("short", kf); err == nil {
		t.Fatal("short env key accepted")
	}
}
