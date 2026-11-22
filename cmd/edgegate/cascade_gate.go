package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/edge/aiml"
)

type cascadeModelClient struct {
	backend systemOneBackend
	client  *http.Client
}
type cascadeEngine struct {
	policy   *cascadePolicy
	policyID string
	clients  map[string]cascadeModelClient
}
type cascadeEnvelope struct {
	Event      aiml.Event                  `json:"event"`
	RawEvent   string                      `json:"raw_event,omitempty"`
	EventID    string                      `json:"event_id"`
	SensorID   string                      `json:"sensor_id"`
	Features   []float64                   `json:"features"`
	Forward    bool                        `json:"forward"`
	Unresolved bool                        `json:"unresolved"`
	Reason     string                      `json:"reason"`
	Model      string                      `json:"model"`
	PolicyID   string                      `json:"policy_sha256"`
	Budget     float64                     `json:"validation_budget"`
	Baseline   *float64                    `json:"baseline_anomaly"`
	Fast       aiml.CascadeDecision        `json:"fast_decision"`
	Remote     *aiml.CascadeDecision       `json:"remote_decision,omitempty"`
	Scores     map[string]modelObservation `json:"systemone_scores"`
	Errors     map[string]string           `json:"systemone_errors"`
}

// Safety checks supplement the unchanged benchmark prompt/client source, so
// the original real-inference cache remains reproducible after this upgrade.
type cascadeTransport struct {
	base     http.RoundTripper
	identity cascadeBackendIdentity
}

func (t cascadeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp, nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(raw) > 1024*1024 {
		return nil, fmt.Errorf("model reply exceeds 1 MiB")
	}
	if err = validateSystemOneSafety(raw); err != nil {
		return nil, err
	}
	var v struct {
		Model   string `json:"model"`
		Routing struct {
			Model string `json:"model"`
		} `json:"routing"`
		Usage struct {
			Questions []string `json:"truncated_questions"`
		} `json:"usage"`
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if len(v.Usage.Questions) > 0 {
		return nil, fmt.Errorf("truncated model question")
	}
	if v.Model != t.identity.Model || (t.identity.Routing != "" && v.Routing.Model != t.identity.Routing) {
		return nil, fmt.Errorf("model/routing does not match calibrated policy")
	}
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	return resp, nil
}

func newCascadeEngine(p *cascadePolicy, id string, urls map[string]string, timeout time.Duration) (*cascadeEngine, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("model timeout must be positive")
	}
	g := &cascadeEngine{p, id, map[string]cascadeModelClient{}}
	for _, name := range p.Cascade.Remote {
		if err := validateSystemOneURL(urls[name]); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		b := systemOneBackend{Name: name, URL: urls[name], Token: os.Getenv("ASI_" + strings.ToUpper(name) + "_TOKEN"), Expected: p.Backends[name].Model}
		client := &http.Client{Timeout: timeout, Transport: cascadeTransport{http.DefaultTransport, p.Backends[name]}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		g.clients[name] = cascadeModelClient{b, client}
	}
	return g, nil
}

func (g *cascadeEngine) decide(sensor string, line []byte, x *aiml.Extractor) cascadeEnvelope {
	d := cascadeEnvelope{SensorID: sensor, EventID: sourceDigest(append(append([]byte(sensor), 0), line...)), Model: g.policy.Kind, PolicyID: g.policyID, Budget: g.policy.Budget, Scores: map[string]modelObservation{}, Errors: map[string]string{}}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&d.Event)
	if err == nil {
		if trailing := decoder.Decode(new(interface{})); trailing != io.EOF {
			err = fmt.Errorf("trailing event data")
		}
	}
	if err == nil {
		err = aiml.ValidateEvent(d.Event)
	}
	if err == nil {
		_, err = time.Parse(time.RFC3339Nano, d.Event.Time)
	}
	if err == nil && (net.ParseIP(d.Event.IP) == nil || d.Event.Port < 0 || d.Event.Port > 65535) {
		err = fmt.Errorf("invalid event address/port")
	}
	if err != nil {
		d.RawEvent = string(line)
		d.Forward = true
		d.Unresolved = true
		d.Reason = "fail_open_invalid_event"
		d.Errors["event"] = err.Error()
		return d
	}
	d.Features = x.Features(d.Event) // every event, including those not forwarded
	scores := map[string]float64{"tree": g.policy.Tree.Score(d.Features), "gnb": g.policy.GNB.Score(d.Features)}
	d.Fast = g.policy.Cascade.Early(scores)
	d.Forward, d.Unresolved, d.Reason = d.Fast.Forward, d.Fast.Unresolved, d.Fast.Reason
	if d.Forward {
		return d
	} // no HTTP, and no later stage can veto this
	baseline := g.policy.Baseline.Anomaly(d.Event)
	d.Baseline = &baseline
	type reply struct {
		name        string
		observation modelObservation
		err         error
	}
	ch := make(chan reply, len(g.policy.Cascade.Remote))
	for _, name := range g.policy.Cascade.Remote {
		mc := g.clients[name]
		name := name
		go func() { p, e := mc.backend.Predict(mc.client, d.Event, d.Features, baseline); ch <- reply{name, p, e} }()
	}
	for range g.policy.Cascade.Remote {
		r := <-ch
		if r.err != nil {
			d.Errors[r.name] = r.err.Error()
		} else {
			d.Scores[r.name] = r.observation
			scores[r.name] = r.observation.Score
		}
	}
	r := g.policy.Cascade.AfterRemote(scores)
	d.Remote = &r
	d.Forward, d.Unresolved, d.Reason = r.Forward, r.Unresolved, r.Reason
	return d
}

type cascadeGateOptions struct {
	Policy, Sensor, Input, Outbox, Central string
	Follow                                 bool
	Timeout                                time.Duration
	URLs                                   map[string]string
}

func cascadeGate(o cascadeGateOptions) error {
	if strings.TrimSpace(o.Sensor) == "" {
		return fmt.Errorf("sensor-id is required")
	}
	if o.Follow && o.Input == "" {
		return fmt.Errorf("-follow requires an append-only -input file")
	}
	p, id, err := loadCascadePolicy(o.Policy)
	if err != nil {
		return err
	}
	g, err := newCascadeEngine(p, id, o.URLs, o.Timeout)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var input io.Reader = os.Stdin
	if o.Input != "" {
		f, e := os.Open(o.Input)
		if e != nil {
			return e
		}
		defer f.Close()
		info, e := f.Stat()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("input must be a regular append-only file")
		}
		input = f
		if o.Follow {
			input = &cascadeFollowReader{ctx: ctx, f: f, path: o.Input, info: info}
		}
	}
	return runCascadeStream(ctx, g, o, input, os.Stdout)
}

func runCascadeStream(ctx context.Context, g *cascadeEngine, o cascadeGateOptions, input io.Reader, output io.Writer) error {
	if o.Central != "" {
		if err := validateRemote(o.Central); err != nil {
			return err
		}
	}
	q, err := openCascadeOutbox(o.Outbox)
	if err != nil {
		return err
	}
	client := cascadeCentralClient()
	x := aiml.NewExtractor()
	s := bufio.NewScanner(input)
	s.Buffer(make([]byte, 65536), 4*1024*1024)
	seen, forwarded, unresolved := 0, 0, 0
	for s.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		d := g.decide(o.Sensor, append([]byte{}, s.Bytes()...), x)
		b, err := json.Marshal(d)
		if err != nil {
			return err
		}
		var pending []byte
		if d.Forward {
			// Durable before stdout or network. Even a broken output pipe must
			// leave the escalation available for retry.
			pending, err = q.put(d.EventID, b)
			if err != nil {
				return fmt.Errorf("persist escalation: %w", err)
			}
			forwarded++
		}
		if n, e := output.Write(append(b, '\n')); e != nil {
			return fmt.Errorf("decision output: %w", e)
		} else if n != len(b)+1 {
			return io.ErrShortWrite
		}
		if d.Unresolved {
			unresolved++
			log.Printf("unresolved event %s: %s", d.EventID, d.Reason)
		}
		if d.Forward && o.Central != "" {
			if err = post(client, o.Central, pending); err != nil {
				log.Printf("central unavailable; retained %s in outbox: %v", d.EventID, err)
			} else if err = q.ack(d.EventID); err != nil {
				return err
			}
		}
		seen++
	}
	if err = s.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	log.Printf("cascade policy=%s events=%d forwarded=%d unresolved=%d; 50%% is a calibration target, not a drop quota", g.policyID, seen, forwarded, unresolved)
	return nil
}

// Follow the durable sensor output, never the sensor's stdout pipe. Rotation
// and truncation are explicit errors: silently tailing a replacement would
// lose history and invalidate the calibrated feature stream.
type cascadeFollowReader struct {
	ctx  context.Context
	f    *os.File
	path string
	info os.FileInfo
}

func (r *cascadeFollowReader) Read(p []byte) (int, error) {
	for {
		n, err := r.f.Read(p)
		if n > 0 || err != io.EOF {
			return n, err
		}
		info, e := os.Stat(r.path)
		if e != nil {
			return 0, e
		}
		pos, e := r.f.Seek(0, io.SeekCurrent)
		if e != nil {
			return 0, e
		}
		if !os.SameFile(r.info, info) || info.Size() < pos {
			return 0, fmt.Errorf("input rotated/truncated; replay a complete stream from a new file")
		}
		select {
		case <-r.ctx.Done():
			return 0, r.ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func cascadeCentralClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
