package sensor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type sink struct {
	mu      sync.Mutex
	batches [][]Event
	auth    []string
	fail    int // respond 500 to this many requests first
}

func (s *sink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auth = append(s.auth, r.Header.Get("Authorization"))
	if s.fail > 0 {
		s.fail--
		http.Error(w, "busy", http.StatusInternalServerError)
		return
	}
	var b []Event
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.batches = append(s.batches, b)
}

func (s *sink) events() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, b := range s.batches {
		n += len(b)
	}
	return n
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestWebhookBatchesAndAuthenticates(t *testing.T) {
	s := &sink{}
	srv := httptest.NewServer(s)
	defer srv.Close()
	w := NewWebhook(srv.URL, "s3cret", 100)
	w.BatchSize, w.Flush = 3, 50*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()

	for i := 0; i < 7; i++ {
		w.Send(Event{Type: ServiceNew, Port: uint16(i)})
	}
	waitFor(t, func() bool { return s.events() == 7 })
	cancel()
	<-done

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.batches) < 3 || len(s.batches[0]) != 3 {
		t.Fatalf("batches: %d, first %d", len(s.batches), len(s.batches[0]))
	}
	if s.auth[0] != "Bearer s3cret" || w.Sent() != 7 || w.Dropped() != 0 {
		t.Fatalf("auth %q sent %d dropped %d", s.auth[0], w.Sent(), w.Dropped())
	}
}

func TestWebhookRetriesUntilAccepted(t *testing.T) {
	s := &sink{fail: 2}
	srv := httptest.NewServer(s)
	defer srv.Close()
	w := NewWebhook(srv.URL, "", 10)
	w.Flush, w.MaxDelay = 10*time.Millisecond, 20*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	w.Send(Event{Type: HostNew})
	waitFor(t, func() bool { return s.events() == 1 })
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.auth) != 3 || s.auth[0] != "" {
		t.Fatalf("attempts %d auth %q", len(s.auth), s.auth)
	}
}

func TestWebhookDropsWhenQueueIsFull(t *testing.T) {
	w := NewWebhook("http://127.0.0.1:1/never", "", 2) // Run not started: nothing drains
	for i := 0; i < 5; i++ {
		w.Send(Event{Type: HostNew})
	}
	if w.Dropped() != 3 {
		t.Fatalf("dropped %d, want 3", w.Dropped())
	}
}

func TestWebhookFlushesOnShutdown(t *testing.T) {
	s := &sink{}
	srv := httptest.NewServer(s)
	defer srv.Close()
	w := NewWebhook(srv.URL, "", 10)
	w.Flush = time.Hour // never by timer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	w.Send(Event{Type: HostSilent})
	w.Send(Event{Type: HostBack})
	go func() { w.Run(ctx); close(done) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
	if s.events() != 2 {
		t.Fatalf("delivered %d of 2 on shutdown", s.events())
	}
}
