// Command console is the operator web console for escalations produced by the
// cascade edge gate. It accepts the same delivery contract as the bundled
// receiver, keeps cases durable, and serves a fleet-scale UI for hundreds of
// edge sensors.
package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"
)

//go:embed static
var staticAssets embed.FS

func main() {
	listen := flag.String("listen", "127.0.0.1:18081", "HTTP bind address; use a TLS proxy outside the local network")
	dataDir := flag.String("data-dir", "var/console", "durable case store directory")
	demo := flag.Bool("demo", false, "seed a synthetic fleet and cases when the store is empty")
	fleet := flag.Int("demo-fleet", 137, "number of demo sensors to seed")
	offlineTTL := flag.Duration("offline-ttl", 90*time.Second, "sensor silence after which the fleet view marks it offline")
	operator := flag.String("operator", envOr("ASI_OPERATOR", "Janek Baumgart"), "name recorded for UI actions that do not pass an explicit actor")
	aiAuto := flag.Bool("ai-auto", true, "automatically run AI analysis on new escalations when an AI provider is configured")
	flag.Parse()

	store, err := openStore(*dataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	if *demo && len(store.ListCases()) == 0 {
		seedDemo(store, *fleet)
		log.Printf("demo fleet seeded: %d sensors, %d cases", *fleet, len(store.ListCases()))
	}
	feed := newLiveFeed(1000)
	// Every audited case event (alert, status, note, action, AI analysis)
	// also appears in the dashboard's live feed.
	store.OnAudit = func(e HistoryEntry, id string) {
		feed.Append(e.Kind, "", e.Actor+": "+e.Text, nil)
	}
	ai := aiFromEnv()
	if *demo {
		relightDemo(store)
	}
	store.markOffline(*offlineTTL)
	go func() {
		for range time.Tick(15 * time.Second) {
			if *demo {
				store.Heartbeat()
			}
			store.markOffline(*offlineTTL)
		}
	}()
	if *demo {
		startDemoLogs(feed, store)
	}

	sub, err := fs.Sub(staticAssets, "static")
	if err != nil {
		log.Fatal(err)
	}
	srv := &server{store: store, token: os.Getenv("ASI_CENTRAL_TOKEN"), demo: *demo, feed: feed, ai: ai, aiAuto: *aiAuto, operator: *operator}
	// Active verification loop: the trigger ships findings back to
	// POST /findings; the console's scan action requests verification
	// through the trigger when its URL is configured.
	srv.triggerURL = os.Getenv("ASI_TRIGGER_URL")
	if srv.triggerToken = os.Getenv("ASI_TRIGGER_TOKEN"); srv.triggerToken == "" {
		srv.triggerToken = os.Getenv("SOTW_WEBHOOK_TOKEN")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.Handle("/api/", srv.routes())
	mux.Handle("/events", srv.routes())
	mux.Handle("/logs", srv.routes())
	mux.Handle("/findings", srv.routes())
	mux.Handle("/", http.FileServer(http.FS(sub)))

	aiInfo := "disabled"
	if ai != nil {
		aiInfo = ai.modelName() + " @ " + ai.baseName()
	}
	fmt.Fprintf(os.Stderr, "operator console listening on %s (demo=%v, operator=%q, ai=%s)\n", *listen, *demo, *operator, aiInfo)
	srvHTTP := &http.Server{
		Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	log.Fatal(srvHTTP.ListenAndServe())
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
