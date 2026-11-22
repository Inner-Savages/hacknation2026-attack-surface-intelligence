package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/edge/aiml"
)

// serve puts the cascade between the sensor and the trigger:
//
//	sensor -webhook-> POST /events (edgegate serve) -> cascade -> POST /events (trigger)
//
// Input and output use the sensor's event format, so the gate is optional:
// point the sensor's webhook at the gate or straight at the trigger.
// Forwarded events keep every original field and gain "score" and "reason".
// Verification events (something went silent or closed) are always
// forwarded, scored but never dropped: a model must not hide a service that
// disappeared.
type serveOptions struct {
	cascadeGateOptions
	Listen     string
	TriggerURL string
	Token      string // required from senders and sent to the trigger when set
	Queue      int
	// HostTTL bounds the feature extractor's per-host memory: hosts idle
	// longer than this (stream time) are evicted. <= 0 keeps hosts forever.
	HostTTL time.Duration
	// StateFile checkpoints the extractor's host table across restarts;
	// empty disables persistence. StateSaveInterval controls how often the
	// checkpoint is written (a final one is always attempted on shutdown).
	StateFile         string
	StateSaveInterval time.Duration
}

var verificationTypes = map[string]bool{"host_silent": true, "service_silent": true, "service_closed": true}

type gateServer struct {
	engine  *cascadeEngine
	opts    serveOptions
	outbox  *cascadeOutbox
	queue   chan []byte
	x       *aiml.Extractor // stateful per host: one worker, input order
	seen    atomic.Int64
	fwd     atomic.Int64
	passed  atomic.Int64
	dropped atomic.Int64
}

func serve(o serveOptions) error {
	if strings.TrimSpace(o.Sensor) == "" {
		return fmt.Errorf("sensor-id is required (fallback for events without a \"sensor\" field)")
	}
	if err := validateRemote(o.TriggerURL); err != nil {
		return fmt.Errorf("trigger-url: %w", err)
	}
	p, id, err := loadCascadePolicy(o.Policy)
	if err != nil {
		return err
	}
	g, err := newCascadeEngine(p, id, o.URLs, o.Timeout)
	if err != nil {
		return err
	}
	s, err := newGateServer(g, o)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go s.work(ctx, os.Stdout)
	go s.deliverLoop(ctx, time.Second)
	go s.stateLoop(ctx, o.StateSaveInterval)

	srv := &http.Server{Addr: o.Listen, Handler: s.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second}
	go func() {
		<-ctx.Done()
		shut, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = srv.Shutdown(shut)
	}()
	log.Printf("gate listening on %s, forwarding to %s (policy %s)", o.Listen, o.TriggerURL, id)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	// Final checkpoint: a restart should pick the baseline up where we left
	// it, not relearn the fleet from scratch.
	if err := s.saveState(); err != nil {
		log.Printf("final host-state checkpoint: %v", err)
	}
	log.Printf("gate stopped: events=%d forwarded=%d (verification passthrough %d) rejected-when-full=%d hosts=%d evicted=%d",
		s.seen.Load(), s.fwd.Load(), s.passed.Load(), s.dropped.Load(), s.x.Hosts(), s.x.Evicted())
	return nil
}

func newGateServer(g *cascadeEngine, o serveOptions) (*gateServer, error) {
	if o.Queue <= 0 {
		o.Queue = 4096
	}
	q, err := openCascadeOutbox(o.Outbox)
	if err != nil {
		return nil, err
	}
	x := aiml.NewExtractor()
	if o.HostTTL > 0 {
		x = aiml.NewExtractorWithTTL(o.HostTTL)
	}
	s := &gateServer{engine: g, opts: o, outbox: q, queue: make(chan []byte, o.Queue), x: x}
	if o.StateFile != "" {
		if n, err := s.loadState(); err == nil {
			if n > 0 {
				log.Printf("host-state checkpoint restored: %d hosts from %s", n, o.StateFile)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			// A corrupt or stale checkpoint must not stop the gate: start
			// fresh and let the next save overwrite it.
			log.Printf("ignoring host-state checkpoint %s: %v", o.StateFile, err)
		}
	}
	return s, nil
}

// loadState restores the extractor's host table from the checkpoint file.
func (s *gateServer) loadState() (int, error) {
	f, err := os.Open(s.opts.StateFile)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return s.x.LoadCheckpoint(f)
}

// saveState writes the host table atomically (tmp + rename), so a crash
// mid-save never leaves a torn checkpoint behind.
func (s *gateServer) saveState() error {
	if s.opts.StateFile == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.opts.StateFile), 0o755); err != nil {
		return err
	}
	tmp := s.opts.StateFile + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := s.x.SaveCheckpoint(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.opts.StateFile)
}

// stateLoop persists the host table periodically until shutdown.
func (s *gateServer) stateLoop(ctx context.Context, every time.Duration) {
	if s.opts.StateFile == "" || every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.saveState(); err != nil {
				log.Printf("host-state checkpoint: %v", err)
			}
		}
	}
}

func (s *gateServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int64{
			"queued": int64(len(s.queue)), "events": s.seen.Load(), "forwarded": s.fwd.Load(),
			"verification_passthrough": s.passed.Load(), "rejected_when_full": s.dropped.Load(),
			"hosts_tracked": int64(s.x.Hosts()), "hosts_evicted": s.x.Evicted(),
		})
	})
	mux.HandleFunc("POST /events", func(w http.ResponseWriter, r *http.Request) {
		if s.opts.Token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.opts.Token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		var batch []json.RawMessage
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&batch); err != nil {
			http.Error(w, "expected a JSON array of sensor events", http.StatusBadRequest)
			return
		}
		// All or nothing: a 503 makes the sensor retry the whole batch, and a
		// half-queued batch would then be scored twice.
		if len(batch) > cap(s.queue)-len(s.queue) {
			s.dropped.Add(int64(len(batch)))
			http.Error(w, "queue full, retry later", http.StatusServiceUnavailable)
			return
		}
		for _, e := range batch {
			s.queue <- []byte(e)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]int{"received": len(batch)})
	})
	return mux
}

// work scores queued events in arrival order and persists the ones to
// forward before acknowledging anything downstream.
func (s *gateServer) work(ctx context.Context, decisions interface{ Write([]byte) (int, error) }) {
	for {
		select {
		case <-ctx.Done():
			return
		case line := <-s.queue:
			s.process(line, decisions)
		}
	}
}

func (s *gateServer) process(line []byte, decisions interface{ Write([]byte) (int, error) }) {
	s.seen.Add(1)
	sensorID := s.opts.Sensor
	var probe struct {
		Sensor string `json:"sensor"`
		Type   string `json:"type"`
	}
	_ = json.Unmarshal(line, &probe)
	if probe.Sensor != "" {
		sensorID = probe.Sensor
	}
	d := s.engine.decide(sensorID, line, s.x)
	if b, err := json.Marshal(d); err == nil {
		_, _ = decisions.Write(append(b, '\n'))
	}
	forward, reason := d.Forward, d.Reason
	if !forward && verificationTypes[probe.Type] {
		forward, reason = true, "verification_passthrough"
		s.passed.Add(1)
	}
	if !forward {
		return
	}
	item, err := triggerItem(line, d, reason)
	if err != nil {
		log.Printf("cannot forward event %s: %v", d.EventID, err)
		return
	}
	if _, err := s.outbox.put(d.EventID, item); err != nil {
		log.Printf("persist %s: %v", d.EventID, err)
		return
	}
	s.fwd.Add(1)
}

// triggerItem is the original sensor event plus the gate's verdict. The
// extra keys are ignored by consumers that don't know them; event_id and
// forward also make it a valid outbox item.
func triggerItem(line []byte, d cascadeEnvelope, reason string) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	if score := decisionScore(d); score != nil {
		m["score"], _ = json.Marshal(*score)
	}
	m["reason"], _ = json.Marshal(reason)
	m["event_id"], _ = json.Marshal(d.EventID)
	m["forward"] = json.RawMessage("true")
	if d.Unresolved {
		m["unresolved"] = json.RawMessage("true")
	}
	return json.Marshal(m)
}

func decisionScore(d cascadeEnvelope) *float64 {
	if d.Remote != nil && d.Remote.Score != nil {
		return d.Remote.Score
	}
	return d.Fast.Score
}

// deliverLoop pushes outbox items to the trigger, each as a one-event array
// (the trigger's input format), deleting them only after a 2xx.
func (s *gateServer) deliverLoop(ctx context.Context, every time.Duration) {
	client := cascadeCentralClient()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, err := s.deliverOnce(client); err != nil {
			log.Printf("trigger unavailable, keeping events in outbox: %v", err)
		}
	}
}

func (s *gateServer) deliverOnce(client *http.Client) (int, error) {
	entries, err := os.ReadDir(s.outbox.dir)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		b, err := s.outbox.read(id)
		if err != nil {
			continue
		}
		body := append(append([]byte{'['}, b...), ']')
		if err := postWithToken(client, s.opts.TriggerURL, body, s.opts.Token); err != nil {
			return sent, err
		}
		if err := s.outbox.ack(id); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}
