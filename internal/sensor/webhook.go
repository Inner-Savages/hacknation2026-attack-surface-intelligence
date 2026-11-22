package sensor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// Webhook delivers events to an HTTP endpoint (POST, JSON array) in
// batches. Send never blocks the capture path: when the queue is full the
// event is dropped and counted. Failed batches are retried with backoff.
type Webhook struct {
	URL       string
	Token     string        // sent as "Authorization: Bearer <token>" when set
	BatchSize int           // default 100
	Flush     time.Duration // max wait before sending a partial batch; default 1s
	MaxDelay  time.Duration // retry backoff ceiling; default 30s
	Client    *http.Client
	Logf      func(format string, args ...any)

	queue   chan Event
	dropped atomic.Int64
	sent    atomic.Int64
}

// NewWebhook creates a webhook with a queue of the given size.
func NewWebhook(url, token string, queue int) *Webhook {
	if queue <= 0 {
		queue = 1024
	}
	return &Webhook{URL: url, Token: token, queue: make(chan Event, queue)}
}

// Send queues an event without blocking.
func (w *Webhook) Send(e Event) {
	select {
	case w.queue <- e:
	default:
		w.dropped.Add(1)
	}
}

// Dropped is the number of events lost to a full queue.
func (w *Webhook) Dropped() int64 { return w.dropped.Load() }

// Sent is the number of events delivered.
func (w *Webhook) Sent() int64 { return w.sent.Load() }

func (w *Webhook) logf(format string, args ...any) {
	if w.Logf != nil {
		w.Logf(format, args...)
	}
}

// Run delivers queued events until ctx ends, then makes one last attempt
// (bounded by a short timeout) to flush what is left.
func (w *Webhook) Run(ctx context.Context) {
	size, flush, maxDelay := w.BatchSize, w.Flush, w.MaxDelay
	if size <= 0 {
		size = 100
	}
	if flush <= 0 {
		flush = time.Second
	}
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second
	}
	var batch []Event
	timer := time.NewTimer(flush)
	defer timer.Stop()
	for {
		select {
		case e := <-w.queue:
			batch = append(batch, e)
			if len(batch) < size {
				continue
			}
		case <-timer.C:
		case <-ctx.Done():
			batch = append(batch, w.drain()...)
			if len(batch) > 0 {
				final, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				if err := w.post(final, batch); err != nil {
					w.logf("webhook: %d events lost on shutdown: %v", len(batch), err)
				}
				cancel()
			}
			return
		}
		if len(batch) > 0 {
			w.deliver(ctx, batch, maxDelay)
			batch = nil
		}
		timer.Reset(flush)
	}
}

// deliver retries one batch until it is accepted or ctx ends.
func (w *Webhook) deliver(ctx context.Context, batch []Event, maxDelay time.Duration) {
	delay := time.Second
	for attempt := 1; ; attempt++ {
		err := w.post(ctx, batch)
		if err == nil {
			return
		}
		if attempt == 1 || attempt%10 == 0 {
			w.logf("webhook: %v (retrying, %d events waiting)", err, len(batch))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, maxDelay)
	}
}

func (w *Webhook) drain() []Event {
	var out []Event
	for {
		select {
		case e := <-w.queue:
			out = append(out, e)
		default:
			return out
		}
	}
}

func (w *Webhook) post(ctx context.Context, batch []Event) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.Token != "" {
		req.Header.Set("Authorization", "Bearer "+w.Token)
	}
	c := w.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: HTTP %d", w.URL, resp.StatusCode)
	}
	w.sent.Add(int64(len(batch)))
	return nil
}
