package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// auditLog is the append-only "who changed what" journal for operator
// requests (case work, settings, rules, users, roles). Records contain the
// actor, role, method and path — never request bodies, so secrets stay out.
// Lines are encrypted at rest like the case audit log.
type auditLog struct {
	mu   sync.Mutex
	path string
}

type AuditRecord struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Role   string    `json:"role"`
	Method string    `json:"method"`
	Path   string    `json:"path"`
	Status int       `json:"status"`
}

func openAudit(dir string) *auditLog {
	return &auditLog{path: filepath.Join(dir, "changes-audit.jsonl")}
}

func (a *auditLog) record(actor, role, method, path string, status int) {
	if a.path == "" {
		return
	}
	b, _ := json.Marshal(AuditRecord{At: time.Now().UTC(), Actor: actor, Role: role, Method: method, Path: path, Status: status})
	if line, err := rest.SealLine(b, "changes-audit.jsonl"); err == nil {
		b = line
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(b, '\n'))
	f.Sync()
}

// tail returns the newest n records, newest first.
func (a *auditLog) tail(n int) []AuditRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.path == "" {
		return []AuditRecord{}
	}
	f, err := os.Open(a.path)
	if err != nil {
		return []AuditRecord{}
	}
	defer f.Close()
	var all []AuditRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		raw, err := rest.OpenLine(sc.Bytes(), "changes-audit.jsonl")
		if err != nil {
			continue
		}
		var rec AuditRecord
		if json.Unmarshal(raw, &rec) == nil {
			all = append(all, rec)
		}
	}
	out := []AuditRecord{}
	for i := len(all) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, all[i])
	}
	return out
}
