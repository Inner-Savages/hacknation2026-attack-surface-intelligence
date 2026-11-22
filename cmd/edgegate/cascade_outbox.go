package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// At-least-once delivery. A central 2xx is required before deleting an item;
// a crash between that response and deletion can produce a duplicate event_id.
type cascadeOutbox struct{ dir string }

func openCascadeOutbox(dir string) (*cascadeOutbox, error) {
	if dir == "" {
		return nil, fmt.Errorf("outbox-dir is required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &cascadeOutbox{dir}, nil
}
func (q *cascadeOutbox) path(id string) (string, error) {
	b, err := hex.DecodeString(id)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("invalid event id")
	}
	return filepath.Join(q.dir, id+".json"), nil
}
func (q *cascadeOutbox) sync() error {
	f, err := os.Open(q.dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (q *cascadeOutbox) read(id string) ([]byte, error) {
	path, err := q.path(id)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d struct {
		EventID string `json:"event_id"`
		Forward bool   `json:"forward"`
	}
	if json.Unmarshal(b, &d) != nil || !d.Forward || d.EventID != id {
		return nil, fmt.Errorf("corrupt outbox item %s", id)
	}
	return b, nil
}
func (q *cascadeOutbox) put(id string, b []byte) ([]byte, error) {
	path, err := q.path(id)
	if err != nil {
		return nil, err
	}
	if old, e := q.read(id); e == nil {
		return old, q.sync()
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	f, err := os.CreateTemp(q.dir, ".pending-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if n, e := f.Write(b); e != nil {
		return nil, e
	} else if n != len(b) {
		return nil, io.ErrShortWrite
	}
	if err = f.Sync(); err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	// Link publishes a complete file without overwriting an unacknowledged
	// version if another replay of this event races with us.
	if err = os.Link(f.Name(), path); err != nil {
		if os.IsExist(err) {
			if err = q.sync(); err != nil {
				return nil, err
			}
			return q.read(id)
		}
		return nil, err
	}
	if err = q.sync(); err != nil {
		return nil, err
	}
	return b, nil
}
func (q *cascadeOutbox) ack(id string) error {
	p, e := q.path(id)
	if e != nil {
		return e
	}
	if e = os.Remove(p); e != nil && !os.IsNotExist(e) {
		return e
	}
	return q.sync()
}
func (q *cascadeOutbox) deliver(client *http.Client, url string) (int, error) {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		id := e.Name()[:len(e.Name())-5]
		b, err := q.read(id)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return sent, err
		}
		if err = post(client, url, b); err != nil {
			return sent, err
		}
		if err = q.ack(id); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}
