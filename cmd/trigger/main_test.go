package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/trigger"
)

// The shipper forwards findings to the console with the webhook token, and
// never blocks or fails the caller when the console is down.
func TestFindingShipper(t *testing.T) {
	type receipt struct {
		auth string
		body trigger.Finding
	}
	ch := make(chan receipt, 1)
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var f trigger.Finding
		if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		ch <- receipt{r.Header.Get("Authorization"), f}
		w.WriteHeader(http.StatusOK)
	}))
	defer console.Close()

	noop := func(string, ...any) {}
	s := &findingShipper{url: console.URL, token: "sekret", client: &http.Client{Timeout: 2 * time.Second}, logf: noop}
	f := trigger.Finding{Verdict: trigger.VerdictGone, Reason: "test"}
	s.ship(f) // must return at once even though delivery is async

	select {
	case got := <-ch:
		if got.auth != "Bearer sekret" {
			t.Fatalf("bad auth header: %q", got.auth)
		}
		if got.body.Verdict != trigger.VerdictGone {
			t.Fatalf("bad finding: %+v", got.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("console never received the finding")
	}

	// A dead console is logged and forgotten, not an error and not a hang.
	s.url = "http://127.0.0.1:1/unreachable"
	done := make(chan struct{})
	go func() { s.ship(f); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ship blocked on an unreachable console")
	}
}
