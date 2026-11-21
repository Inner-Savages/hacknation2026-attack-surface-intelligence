package traffic

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseTargets(t *testing.T) {
	ts, err := ParseTargets("http://web:80/, tcp://gitea:22\n tcp://redis:6379?send=PING%0D%0A https://npm:443/")
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 4 {
		t.Fatalf("got %d targets", len(ts))
	}
	if ts[1].Kind != "tcp" || ts[1].Addr != "gitea:22" || ts[1].Send != nil {
		t.Errorf("tcp target: %+v", ts[1])
	}
	if string(ts[2].Send) != "PING\r\n" {
		t.Errorf("send = %q", ts[2].Send)
	}
	if ts[3].Kind != "http" {
		t.Errorf("https target: %+v", ts[3])
	}
}

func TestParseTargetsRejectsBadInput(t *testing.T) {
	for _, s := range []string{"", "ftp://x:21", "tcp://nohost", "gitea:22", "tcp://:22"} {
		if _, err := ParseTargets(s); err == nil {
			t.Errorf("%q: expected error", s)
		}
	}
}

func TestProbeHTTP(t *testing.T) {
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.UserAgent()
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	r := NewProber(time.Second).Probe(context.Background(), Target{Raw: srv.URL, Kind: "http", URL: srv.URL})
	if !r.OK || r.Detail != "418 I'm a teapot" {
		t.Fatalf("got %+v", r)
	}
	if !strings.HasPrefix(ua, "sotw-traffic/") {
		t.Errorf("user agent %q", ua)
	}
}

// listen starts a TCP server that runs handle for each connection.
func listen(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	return ln.Addr().String()
}

func TestProbeTCPReadsServerFirstBanner(t *testing.T) {
	addr := listen(t, func(c net.Conn) { c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n")) })
	r := NewProber(time.Second).Probe(context.Background(), Target{Raw: "tcp://" + addr, Kind: "tcp", Addr: addr})
	if !r.OK || r.Detail != "banner: SSH-2.0-OpenSSH_9.6" {
		t.Fatalf("got %+v", r)
	}
}

func TestProbeTCPSilentServerIsStillOK(t *testing.T) {
	addr := listen(t, func(c net.Conn) { time.Sleep(3 * time.Second) })
	r := NewProber(300*time.Millisecond).Probe(context.Background(), Target{Raw: "tcp://" + addr, Kind: "tcp", Addr: addr})
	if !r.OK || r.Detail != "connected" {
		t.Fatalf("got %+v", r)
	}
	if r.Took > time.Second {
		t.Errorf("silent server held the probe for %v", r.Took)
	}
}

func TestProbeTCPSendsGreeting(t *testing.T) {
	addr := listen(t, func(c net.Conn) {
		line, _ := bufio.NewReader(c).ReadString('\n')
		if line == "PING\r\n" {
			c.Write([]byte("+PONG\r\n"))
		}
	})
	r := NewProber(time.Second).Probe(context.Background(), Target{Raw: "tcp://" + addr, Kind: "tcp", Addr: addr, Send: []byte("PING\r\n")})
	if !r.OK || r.Detail != "banner: +PONG" {
		t.Fatalf("got %+v", r)
	}
}

func TestProbeClosedPortFails(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	r := NewProber(time.Second).Probe(context.Background(), Target{Raw: "tcp://" + addr, Kind: "tcp", Addr: addr})
	if r.OK || !strings.Contains(r.Detail, "refused") {
		t.Fatalf("got %+v", r)
	}
}
