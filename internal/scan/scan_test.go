package scan

import (
	"context"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTargetsExpandDedupAndOrder(t *testing.T) {
	var tg Targets
	if err := tg.AddList("10.0.0.2, 10.0.0.0/30 example.COM 10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.2", "10.0.0.0", "10.0.0.1", "10.0.0.3", "example.com"}
	if !reflect.DeepEqual(tg.Items(), want) {
		t.Fatalf("got %v, want %v", tg.Items(), want)
	}
}

func TestTargetsReader(t *testing.T) {
	var tg Targets
	err := tg.AddReader(strings.NewReader("# lab\n172.28.0.10 172.28.0.11 # web\n\nweb-cms.lab\n"))
	if err != nil || tg.Len() != 3 {
		t.Fatalf("got %v, %v", tg.Items(), err)
	}
	if err := tg.AddReader(strings.NewReader("ok.lab\nnot a host!\n")); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("expected line number in error, got %v", err)
	}
}

func TestTargetsRejectsHugeRangesAndJunk(t *testing.T) {
	for _, s := range []string{"10.0.0.0/8", "fd00::/64", "10.0.0.0/33", "-rf", "a..b", "x;rm", "172.28.0.10-12", "10.0.0.1-255", "999.1.1.1"} {
		var tg Targets
		if err := tg.Add(s); err == nil {
			t.Errorf("%q: expected error", s)
		}
	}
	var tg Targets
	if err := tg.Add("10.0.0.0/12"); err != nil || tg.Len() != 1<<20 {
		t.Fatalf("/12: %v, %d", err, tg.Len())
	}
}

func TestTargetsAllowList(t *testing.T) {
	var tg Targets
	_ = tg.AddList("172.28.0.10 lab.host 10.1.1.1")
	allow := []netip.Prefix{netip.MustParsePrefix("172.28.0.0/24")}
	if err := tg.CheckAllowed(allow); err == nil || !strings.Contains(err.Error(), "10.1.1.1") {
		t.Fatalf("expected 10.1.1.1 rejected, got %v", err)
	}
	if err := tg.CheckAllowed(nil); err != nil {
		t.Fatal(err)
	}
}

func TestOptionsArgsAndValidation(t *testing.T) {
	o := Options{Ports: "22,80,8000-8100", MaxRate: 300, SkipDiscovery: true}
	got := strings.Join(o.Args(), " ")
	for _, want := range []string{"-sT", "-sV", "-oX -", "-iL -", "-p 22,80,8000-8100", "--max-rate 300", "-Pn", "--version-intensity 5"} {
		if !strings.Contains(got, want) {
			t.Errorf("args %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "--script") || strings.Contains(got, "-sC") || strings.Contains(got, "-O") {
		t.Errorf("args must not run NSE or OS detection: %q", got)
	}
	if got := strings.Join(Options{}.Args(), " "); !strings.Contains(got, "--top-ports 1000") {
		t.Errorf("default ports: %q", got)
	}
	if got := strings.Join(Options{SYN: true}.Args(), " "); !strings.HasPrefix(got, "-sS") {
		t.Errorf("SYN: %q", got)
	}
	for _, bad := range []Options{{Ports: "80 --script vuln"}, {Ports: "80;id"}, {VersionIntensity: 10}, {MaxRate: -1}, {VersionMode: "turbo"}, {VersionWait: time.Millisecond}} {
		if bad.Validate() == nil {
			t.Errorf("%+v: expected validation error", bad)
		}
	}
}

func TestParseXMLFromAGHLab(t *testing.T) {
	data, err := os.ReadFile("testdata/agh-custom-network.xml")
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := ParseXML(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].Address != "127.0.0.1" || hosts[0].State != "up" {
		t.Fatalf("hosts: %+v", hosts)
	}
	byPort := map[int]string{}
	for _, s := range hosts[0].Services {
		byPort[s.Port] = s.State + " " + s.Name + " " + s.Product + " " + s.Version
	}
	want := map[int]string{
		2223:  "open ssh OpenSSH 10.3",
		5673:  "open amqp Advanced Message Queue Protocol ",
		8787:  "open http nginx ",
		15432: "open postgresql PostgreSQL DB 9.6.0 or later",
		15673: "open http Cowboy httpd ",
		9:     "closed discard  ",
	}
	for port, w := range want {
		if byPort[port] != w {
			t.Errorf("port %d: got %q, want %q", port, byPort[port], w)
		}
	}
}

func TestScannerChunksInParallelAndRecordsFailures(t *testing.T) {
	var tg Targets
	_ = tg.AddList("10.0.0.0/29 fail.test")
	var progress int
	s := Scanner{
		Options:   Options{Binary: "testdata/fake-nmap.sh"},
		ChunkSize: 3,
		Parallel:  2,
		Progress:  func(Progress) { progress++ },
	}
	res, err := s.Scan(context.Background(), &tg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Chunks) != 3 || progress != 3 {
		t.Fatalf("chunks %d, progress calls %d", len(res.Chunks), progress)
	}
	if len(res.Hosts) != 6 { // last chunk (10.0.0.6, 10.0.0.7, fail.test) fails as a whole
		t.Fatalf("hosts: %d", len(res.Hosts))
	}
	if res.Hosts[0].Address != "10.0.0.0" || res.Hosts[5].Address != "10.0.0.5" {
		t.Fatalf("hosts not sorted: %s .. %s", res.Hosts[0].Address, res.Hosts[5].Address)
	}
	if res.Chunks[2].Error == "" || !strings.Contains(res.Chunks[2].Error, "failure requested") {
		t.Fatalf("chunk error not recorded: %+v", res.Chunks[2])
	}
	if res.Chunks[0].HostsUp != 3 || res.Chunks[0].Duration <= 0 {
		t.Fatalf("chunk stats: %+v", res.Chunks[0])
	}
}

func TestParseXMLExtraPortsTellLiveFromAbsent(t *testing.T) {
	xml := func(addr, state string) []byte {
		return []byte(`<nmaprun><host><status state="up" reason="user-set"/><address addr="` + addr + `" addrtype="ipv4"/>` +
			`<ports><extraports state="` + state + `" count="100"/></ports></host></nmaprun>`)
	}
	live, _ := ParseXML(xml("172.28.0.100", "closed"))
	gone, _ := ParseXML(xml("172.28.0.250", "filtered"))
	if len(live[0].ExtraPorts) != 1 || live[0].ExtraPorts[0].Count != 100 || !live[0].Responded() {
		t.Fatalf("live: %+v", live[0])
	}
	if gone[0].Responded() {
		t.Fatalf("absent host must not count as responding: %+v", gone[0])
	}
}
