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
	flag.Parse()

	store, err := openStore(*dataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	if *demo && len(store.ListCases()) == 0 {
		seedDemo(store, *fleet)
		log.Printf("demo fleet seeded: %d sensors, %d cases", *fleet, len(store.ListCases()))
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

	sub, err := fs.Sub(staticAssets, "static")
	if err != nil {
		log.Fatal(err)
	}
	srv := &server{store: store, token: os.Getenv("ASI_CENTRAL_TOKEN"), demo: *demo}
	mux := http.NewServeMux()
	mux.Handle("/api/", srv.routes())
	mux.Handle("/events", srv.routes())
	mux.Handle("/", http.FileServer(http.FS(sub)))

	fmt.Fprintf(os.Stderr, "operator console listening on %s (demo=%v)\n", *listen, *demo)
	srvHTTP := &http.Server{
		Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	log.Fatal(srvHTTP.ListenAndServe())
}
