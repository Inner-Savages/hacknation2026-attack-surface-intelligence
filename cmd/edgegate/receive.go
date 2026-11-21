package main

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Local integration inbox, not an analytical model. A 202 means the exact
// envelope is durable. Repeated event_id deliveries preserve the first copy.
func inboxHandler(q *cascadeOutbox, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("POST /events", func(w http.ResponseWriter, r *http.Request) {
		if token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8*1024*1024))
		if err != nil {
			http.Error(w, "invalid body", 400)
			return
		}
		var d cascadeEnvelope
		if json.Unmarshal(b, &d) != nil || !d.Forward || d.EventID == "" {
			http.Error(w, "expected escalation envelope", 400)
			return
		}
		if _, err := q.path(d.EventID); err != nil {
			http.Error(w, "invalid event ID", 400)
			return
		}
		if _, err := q.put(d.EventID, b); err != nil {
			http.Error(w, "persistence failed", 503)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	return mux
}

func receive(args []string) error {
	fs := flag.NewFlagSet("receive", flag.ContinueOnError)
	addr := fs.String("listen", "127.0.0.1:18080", "HTTP bind address; use a TLS proxy outside the local Compose network")
	dir := fs.String("inbox-dir", "var/cascade50/inbox", "durable received envelopes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	q, err := openCascadeOutbox(*dir)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "integration inbox listening on %s (no central analytical model)\n", *addr)
	srv := &http.Server{Addr: *addr, Handler: inboxHandler(q, os.Getenv("ASI_CENTRAL_TOKEN")), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	return srv.ListenAndServe()
}
