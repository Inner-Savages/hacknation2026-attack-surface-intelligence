// Package traffic generates gentle, realistic background traffic in a lab so
// that a passive sensor has something to observe: HTTP GETs against web
// services and TCP connects that read a server banner. It never logs in,
// never sends payloads beyond an optional fixed greeting, and is meant only
// for local test environments.
package traffic

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Target is one endpoint to poke:
//
//	http://gitea:3000/          GET, body discarded
//	https://npm:443/            GET, certificate not verified (lab only)
//	tcp://gitea:22              connect, read the banner if the server speaks first
//	tcp://redis:6379?send=PING%0D%0A   connect, send bytes, read the reply
type Target struct {
	Raw  string
	Kind string // "http" or "tcp"
	URL  string // for http
	Addr string // host:port for tcp
	Send []byte // optional greeting for tcp
}

// ParseTargets reads a comma- or whitespace-separated list of targets.
func ParseTargets(s string) ([]Target, error) {
	var out []Target
	for _, raw := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", raw, err)
		}
		if u.Hostname() == "" || (u.Scheme == "tcp" && u.Port() == "") {
			return nil, fmt.Errorf("target %q: need scheme://host:port", raw)
		}
		switch u.Scheme {
		case "http", "https":
			out = append(out, Target{Raw: raw, Kind: "http", URL: raw})
		case "tcp":
			t := Target{Raw: raw, Kind: "tcp", Addr: u.Host}
			if s := u.Query().Get("send"); s != "" {
				t.Send = []byte(s)
			}
			out = append(out, t)
		default:
			return nil, fmt.Errorf("target %q: scheme must be http, https or tcp", raw)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	return out, nil
}

// Result describes one probe.
type Result struct {
	Target string
	OK     bool
	Detail string // status code, banner line or error
	Took   time.Duration
}

func (r Result) String() string {
	status := "ok"
	if !r.OK {
		status = "fail"
	}
	return fmt.Sprintf("%-4s %-45s %6dms  %s", status, r.Target, r.Took.Milliseconds(), r.Detail)
}

// Prober runs probes with a shared HTTP client.
type Prober struct {
	Timeout time.Duration
	client  *http.Client
}

// NewProber creates a prober; timeout bounds each probe.
func NewProber(timeout time.Duration) *Prober {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // lab services use self-signed certs
		DisableKeepAlives: true,                                  // every request is a fresh handshake the sensor can see
	}
	return &Prober{
		Timeout: timeout,
		client: &http.Client{
			Transport: tr,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

// Probe pokes one target once.
func (p *Prober) Probe(ctx context.Context, t Target) Result {
	start := time.Now()
	var r Result
	switch t.Kind {
	case "http":
		r = p.probeHTTP(ctx, t)
	default:
		r = p.probeTCP(ctx, t)
	}
	r.Target, r.Took = t.Raw, time.Since(start)
	return r
}

func (p *Prober) probeHTTP(ctx context.Context, t Target) Result {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
	if err != nil {
		return Result{Detail: err.Error()}
	}
	req.Header.Set("User-Agent", "sotw-traffic/1 (lab background traffic)")
	resp, err := p.client.Do(req)
	if err != nil {
		return Result{Detail: shortErr(err)}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 256<<10))
	return Result{OK: true, Detail: resp.Status}
}

func (p *Prober) probeTCP(ctx context.Context, t Target) Result {
	d := net.Dialer{Timeout: p.Timeout}
	conn, err := d.DialContext(ctx, "tcp", t.Addr)
	if err != nil {
		return Result{Detail: shortErr(err)}
	}
	defer conn.Close()
	if len(t.Send) > 0 {
		if _, err := conn.Write(t.Send); err != nil {
			return Result{OK: true, Detail: "connected, send failed: " + shortErr(err)}
		}
	}
	// Server-first protocols (SSH, FTP, SMTP) greet immediately; others stay
	// silent, which is fine: the handshake alone is what we want to generate.
	_ = conn.SetReadDeadline(time.Now().Add(min(p.Timeout, 2*time.Second)))
	line, err := bufio.NewReader(io.LimitReader(conn, 512)).ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		if err != nil && !isTimeout(err) && err != io.EOF {
			return Result{OK: true, Detail: "connected, " + shortErr(err)}
		}
		return Result{OK: true, Detail: "connected"}
	}
	return Result{OK: true, Detail: "banner: " + printable(line)}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s) > 80 {
		return s[i+2:]
	}
	return s
}

func printable(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '.'
		}
	}
	if len(b) > 80 {
		b = append(b[:77], "..."...)
	}
	return string(b)
}
