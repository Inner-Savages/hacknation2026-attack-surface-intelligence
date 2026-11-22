// Package atrest encrypts sensitive files at rest with AES-256-GCM (pure Go,
// no cgo). Files carry a magic header so legacy plaintext files stay readable
// and are migrated to the encrypted format on their next write.
package atrest

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// magic prefixes every encrypted blob: "ASIE" + format version 1.
var magic = []byte("ASIE\x01")

// ErrDecrypt is returned for a wrong key or a corrupted/tampered file.
var ErrDecrypt = errors.New("atrest: decryption failed (wrong key or corrupted data)")

// Cipher seals and opens data with a 256-bit key. A nil *Cipher is a valid
// "encryption disabled" cipher that passes data through unchanged.
type Cipher struct{ aead cipher.AEAD }

// New builds a Cipher from a 32-byte key.
func New(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("atrest: key must be 32 bytes, got %d", len(key))
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: g}, nil
}

// IsEncrypted reports whether data starts with the encrypted-format header.
func IsEncrypted(data []byte) bool { return bytes.HasPrefix(data, magic) }

// Seal encrypts plaintext. aad (e.g. the file name) is authenticated, so a
// blob cannot be swapped between files undetected.
func (c *Cipher) Seal(plain []byte, aad string) ([]byte, error) {
	if c == nil {
		return plain, nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append(append([]byte{}, magic...), nonce...)
	return c.aead.Seal(out, nonce, plain, []byte(aad)), nil
}

// Open decrypts a blob. Data without the header is returned as-is (legacy
// plaintext); encrypted data that fails authentication yields ErrDecrypt.
func (c *Cipher) Open(data []byte, aad string) ([]byte, error) {
	if !IsEncrypted(data) {
		return data, nil
	}
	if c == nil {
		return nil, errors.New("atrest: file is encrypted but no key is configured (set ASI_DATA_KEY)")
	}
	body := data[len(magic):]
	ns := c.aead.NonceSize()
	if len(body) < ns+c.aead.Overhead() {
		return nil, ErrDecrypt
	}
	plain, err := c.aead.Open(nil, body[:ns], body[ns:], []byte(aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

// WriteFile atomically writes (tmp + fsync + rename) the sealed data to path.
func (c *Cipher) WriteFile(path string, plain []byte, perm os.FileMode) error {
	blob, err := c.Seal(plain, filepath.Base(path))
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadFile reads and opens a file; plaintext legacy files are accepted.
func (c *Cipher) ReadFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return c.Open(b, filepath.Base(path))
}

// SealLine encrypts one append-only log record into a single text line
// ("ASIE1:" + base64), so JSONL files stay line-oriented.
func (c *Cipher) SealLine(plain []byte, aad string) ([]byte, error) {
	if c == nil {
		return plain, nil
	}
	blob, err := c.Seal(plain, aad)
	if err != nil {
		return nil, err
	}
	return []byte("ASIE1:" + base64.StdEncoding.EncodeToString(blob)), nil
}

// OpenLine reverses SealLine; plain lines pass through.
func (c *Cipher) OpenLine(line []byte, aad string) ([]byte, error) {
	s := strings.TrimSpace(string(line))
	if !strings.HasPrefix(s, "ASIE1:") {
		return []byte(s), nil
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "ASIE1:"))
	if err != nil {
		return nil, ErrDecrypt
	}
	return c.Open(blob, aad)
}

// LoadKey resolves the data key: the env var value (hex or base64, 32 bytes)
// wins; otherwise keyFile is read, or created with mode 0600 and a fresh
// random key when missing. It returns the key and where it came from.
func LoadKey(env, keyFile string) (key []byte, source string, err error) {
	if env = strings.TrimSpace(env); env != "" {
		k, err := decodeKey(env)
		if err != nil {
			return nil, "", fmt.Errorf("ASI_DATA_KEY: %w", err)
		}
		return k, "env", nil
	}
	if b, err := os.ReadFile(keyFile); err == nil {
		k, err := decodeKey(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", keyFile, err)
		}
		return k, keyFile, nil
	} else if !os.IsNotExist(err) {
		return nil, "", err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(k)+"\n"), 0o600); err != nil {
		return nil, "", err
	}
	return k, keyFile + " (generated)", nil
}

func decodeKey(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("key must be 32 bytes encoded as hex (64 chars) or base64")
}
