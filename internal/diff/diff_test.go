package diff

import (
	"strings"
	"testing"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

var args = []string{"-sT", "-sV", "-p", "80,443,8787"}

func scan(at time.Time, targets []string, hosts ...result.Host) *result.Scan {
	return &result.Scan{StartedAt: at, Targets: targets, Settings: result.Settings{NmapArgs: args}, Hosts: hosts}
}

func host(addr string, svcs ...result.Service) result.Host {
	return result.Host{Address: addr, State: "up", Services: svcs}
}

func svc(port int, name, product string) result.Service {
	return result.Service{Port: port, Proto: "tcp", State: "open", Name: name, Product: product}
}

func withHTTP(s result.Service, title, server string, tech ...result.Tech) result.Service {
	s.HTTP = &result.HTTP{Status: 200, Title: title, FinalURL: "http://x/", Headers: map[string][]string{"server": {server}, "date": {time.Now().String()}}}
	s.Tech = tech
	return s
}

var t0 = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

// The CBI AGH quickstart: 8787 is stopped between scans.
func TestServiceGoneAndBack(t *testing.T) {
	targets := []string{"127.0.0.1"}
	all := host("127.0.0.1", svc(2223, "ssh", "OpenSSH"), svc(8787, "http", "nginx"))
	without := host("127.0.0.1", svc(2223, "ssh", "OpenSSH"))

	d := Compare(scan(t0, targets, all), scan(t0.Add(time.Minute), targets, without))
	if d.Summary != (Summary{GoneServices: 1}) || d.Hosts[0].Kind != Changed || d.Hosts[0].Services[0].Port != 8787 || d.Hosts[0].Services[0].Kind != Gone {
		t.Fatalf("gone: %+v", d)
	}
	back := Compare(scan(t0, targets, without), scan(t0.Add(2*time.Minute), targets, all))
	if back.Summary != (Summary{NewServices: 1}) || back.Hosts[0].Services[0].Kind != New {
		t.Fatalf("back: %+v", back)
	}
}

func TestHostsNewGoneAndNotScanned(t *testing.T) {
	old := scan(t0, []string{"10.0.0.1", "10.0.0.2", "10.0.0.9"},
		host("10.0.0.1", svc(80, "http", "nginx")), host("10.0.0.2", svc(22, "ssh", "OpenSSH")), host("10.0.0.9"))
	cur := scan(t0, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, // 10.0.0.9 not a target any more
		host("10.0.0.1", svc(80, "http", "nginx")), host("10.0.0.3", svc(443, "https", "")))
	// 10.0.0.2 was a target and is down now -> gone.
	d := Compare(old, cur)
	want := Summary{NewHosts: 1, GoneHosts: 1, NewServices: 1, GoneServices: 1}
	if d.Summary != want {
		t.Fatalf("summary %+v, want %+v", d.Summary, want)
	}
	if d.Hosts[0].Address != "10.0.0.2" || d.Hosts[0].Kind != Gone || d.Hosts[1].Address != "10.0.0.3" || d.Hosts[1].Kind != New {
		t.Fatalf("hosts: %+v", d.Hosts)
	}
	if len(d.Warnings) != 1 || !strings.Contains(d.Warnings[0], "1 host(s)") {
		t.Fatalf("warnings: %v", d.Warnings)
	}
}

func TestServiceChangesIgnoreVolatileFields(t *testing.T) {
	targets := []string{"127.0.0.1"}
	nginx := result.Tech{Name: "nginx", Version: "1.25.0"}
	setup := result.Tech{Name: "Setup / installation page"}
	gitea := result.Tech{Name: "Gitea"}
	old := scan(t0, targets, host("127.0.0.1", withHTTP(svc(3001, "http", "Golang net/http server"), "Installation - Gitea", "nginx/1.25.0", gitea, nginx, setup)))
	cur := scan(t0, targets, host("127.0.0.1", withHTTP(svc(3001, "http", "Golang net/http server"), "Gitea: Git with a cup of tea", "nginx/1.27.1", gitea, result.Tech{Name: "nginx", Version: "1.27.1"})))

	d := Compare(old, cur)
	if d.Summary != (Summary{ChangedServices: 1}) {
		t.Fatalf("summary: %+v", d.Summary)
	}
	got := map[string]string{}
	for _, f := range d.Hosts[0].Services[0].Changes {
		got[f.Field] = f.Old + " -> " + f.New
	}
	want := map[string]string{
		"http.title":         "Installation - Gitea -> Gitea: Git with a cup of tea",
		"http.header.server": "nginx/1.25.0 -> nginx/1.27.1",
		"tech.nginx":         "1.25.0 -> 1.27.1",
		"tech":               "Setup / installation page -> ",
	}
	if len(got) != len(want) {
		t.Fatalf("changes %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
}

func TestNoChangesAndSettingsWarning(t *testing.T) {
	targets := []string{"127.0.0.1"}
	a := scan(t0, targets, host("127.0.0.1", svc(80, "http", "nginx")))
	b := scan(t0, targets, host("127.0.0.1", svc(80, "http", "nginx")))
	if d := Compare(a, b); !d.Summary.Empty() || len(d.Warnings) != 0 || !strings.Contains(d.Text(), "no changes") {
		t.Fatalf("expected no changes: %+v", d)
	}
	b.Settings.NmapArgs = []string{"-sT", "-p", "80"}
	if d := Compare(a, b); len(d.Warnings) != 1 || !strings.Contains(d.Warnings[0], "different nmap settings") {
		t.Fatalf("warnings: %v", d.Warnings)
	}
}

func TestClosedPortsDoNotCountAsServices(t *testing.T) {
	targets := []string{"127.0.0.1"}
	closed := svc(8080, "http-proxy", "")
	closed.State = "closed"
	d := Compare(scan(t0, targets, host("127.0.0.1", svc(80, "http", "nginx"), closed)), scan(t0, targets, host("127.0.0.1", svc(80, "http", "nginx"))))
	if !d.Summary.Empty() {
		t.Fatalf("closed port must be ignored: %+v", d)
	}
}

func TestText(t *testing.T) {
	targets := []string{"127.0.0.1", "10.0.0.3"}
	d := Compare(
		scan(t0, targets, host("127.0.0.1", svc(8787, "http", "nginx"), withHTTP(svc(3001, "http", ""), "Installation - Gitea", "x"))),
		scan(t0.Add(time.Minute), targets, host("127.0.0.1", withHTTP(svc(3001, "http", ""), "Gitea", "x")), host("10.0.0.3", svc(80, "http", "nginx"))),
	)
	out := d.Text()
	for _, want := range []string{
		"+ host 10.0.0.3\n  + 80/tcp http nginx\n",
		"~ 127.0.0.1\n",
		"  ~ 3001/tcp http \"Gitea\"\n      http.title: \"Installation - Gitea\" -> \"Gitea\"\n",
		"  - 8787/tcp http nginx\n",
		"1 new hosts, 0 gone hosts, 1 new services, 1 gone services, 1 changed services",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text missing %q in:\n%s", want, out)
		}
	}
}
