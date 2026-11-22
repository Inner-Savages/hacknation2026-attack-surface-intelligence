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
	operator := flag.String("operator", envOr("ASI_OPERATOR", "Janek Baumgart"), "name recorded for machine-side actions without a session")
	aiAuto := flag.Bool("ai-auto", true, "automatically run AI analysis on new escalations when an AI provider is configured")
	aiOperator := flag.Bool("ai-operator", envOr("ASI_AI_OPERATOR", "") == "true", "let the configured LLM act as an autonomous, fully audited operator")
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
	userAuth, err := openAuth(*dataDir)
	if err != nil {
		log.Fatalf("open auth store: %v", err)
	}
	cfg, err := openSettings(*dataDir)
	if err != nil {
		log.Fatalf("open settings: %v", err)
	}
	rules, err := openRules(*dataDir)
	if err != nil {
		log.Fatalf("open rules: %v", err)
	}
	srv := &server{
		store: store, token: os.Getenv("ASI_CENTRAL_TOKEN"), demoData: *demo, feed: feed,
		operator: *operator, aiAuto: *aiAuto, aiOpDefault: *aiOperator, demoDefault: *demo,
		auth: userAuth, settings: cfg, rules: rules,
	}
	if *demo {
		relightDemo(store)
	}
	store.markOffline(*offlineTTL)
	go func() {
		for range time.Tick(15 * time.Second) {
			if srv.demoFeedOn() {
				store.Heartbeat()
			}
			store.markOffline(*offlineTTL)
		}
	}()
	if *demo {
		startDemoLogs(feed, store, srv.demoFeedOn)
		startDemoEscalations(store, srv.demoFeedOn, srv.triageNewCase)
	}
	// Operator mode enabled before a restart takes over the open backlog on
	// boot, exactly like flipping the toggle at runtime. Rule mode does the
	// same, synchronously — the engine is instant.
	if srv.ruleModeOn() {
		srv.applyRulesToOpen(100)
	} else if srv.aiOperatorOn() {
		go srv.backfillAIOperator(10)
	}

	sub, err := fs.Sub(staticAssets, "static")
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.Handle("/api/", srv.routes())
	mux.Handle("/events", srv.routes())
	mux.Handle("/logs", srv.routes())
	mux.Handle("/", http.FileServer(http.FS(sub)))

	aiInfo := "disabled"
	if ai := srv.aiClient(); ai != nil {
		aiInfo = ai.modelName() + " @ " + ai.baseName()
		if srv.aiOperatorOn() {
			aiInfo += " (operator mode)"
		}
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
