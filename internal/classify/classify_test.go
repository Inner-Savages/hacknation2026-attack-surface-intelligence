package classify

import "testing"

func TestClassifyOUI(t *testing.T) {
	cases := []struct {
		mac    string
		class  string
		vendor string
	}{
		{"44:19:b6:10:20:30", Camera, "Hikvision"},
		{"3C:E3:8B:AA:BB:CC", Camera, "Dahua"},
		{"00:11:0a:00:00:01", Printer, "Hewlett-Packard"},
		{"b8:27:eb:12:34:56", IoT, "Raspberry Pi"},
		{"24:5a:4c:de:ad:be", Network, "Ubiquiti"},
		{"00:0c:29:11:22:33", Server, "VMware"},
		{"00:0b:82:44:55:66", Phone, "Grandstream"},
	}
	for _, tc := range cases {
		out := Classify(Input{MAC: tc.mac})
		if out.Class != tc.class {
			t.Errorf("MAC %s: class = %q, want %q (vendor %q)", tc.mac, out.Class, tc.class, out.Vendor)
		}
		if out.Vendor != tc.vendor {
			t.Errorf("MAC %s: vendor = %q, want %q", tc.mac, out.Vendor, tc.vendor)
		}
		if out.Confidence < 0.8 {
			t.Errorf("MAC %s: confidence %v below the OUI weight", tc.mac, out.Confidence)
		}
		if len(out.Reasons) == 0 || out.Reasons[0].Source != "OUI" {
			t.Errorf("MAC %s: expected OUI evidence, got %+v", tc.mac, out.Reasons)
		}
	}
}

func TestClassifyUnknownMAC(t *testing.T) {
	// A locally administered address that is not Docker's matches no vendor
	// and must not fabricate a classification by itself.
	out := Classify(Input{MAC: "02:11:22:33:44:55"})
	if out.Vendor != "" || out.Class != Unknown {
		t.Errorf("non-Docker locally administered MAC: got %+v, want unknown", out)
	}
	// Docker's 02:42 prefix is a platform signal: container.
	out = Classify(Input{MAC: "02:42:ac:11:00:02"})
	if out.Class != Container || out.Vendor != "Docker" {
		t.Errorf("Docker MAC: got %+v, want kontener/Docker", out)
	}
}

func TestClassifyPorts(t *testing.T) {
	cases := []struct {
		ports []int
		class string
	}{
		{[]int{9100, 80}, Printer},
		{[]int{554, 80}, Camera},
		{[]int{1883}, IoT},
		{[]int{22, 3306}, Database},
		{[]int{22}, Server},
		{[]int{3389}, Workstation},
		{[]int{5060}, Phone},
		{[]int{80, 443}, Web},
	}
	for _, tc := range cases {
		out := Classify(Input{Ports: tc.ports})
		if out.Class != tc.class {
			t.Errorf("ports %v: class = %q, want %q (reasons %+v)", tc.ports, out.Class, tc.class, out.Reasons)
		}
	}
}

func TestClassifyBanner(t *testing.T) {
	out := Classify(Input{Banners: []string{"HP HTTP Server; HP LaserJet 400 - jetdirect"}})
	if out.Class != Printer {
		t.Errorf("jetdirect banner: class = %q, want %q", out.Class, Printer)
	}

	out = Classify(Input{TLSSubjects: []string{"CN=Hikvision IP Camera, O=Hikvision"}})
	if out.Class != Camera {
		t.Errorf("TLS subject: class = %q, want %q", out.Class, Camera)
	}
	if out.Reasons[0].Source != "TLS" {
		t.Errorf("TLS evidence source = %q, want TLS", out.Reasons[0].Source)
	}
}

func TestClassifyCombinedSignals(t *testing.T) {
	// OUI + RTSP port + ONVIF banner: the classic camera, high confidence.
	out := Classify(Input{
		MAC:     "44:19:b6:01:02:03",
		Ports:   []int{554, 80},
		Banners: []string{"RTSP/1.0 Server (ONVIF)"},
	})
	if out.Class != Camera {
		t.Fatalf("combined: class = %q, want kamera", out.Class)
	}
	if out.Confidence < 0.9 {
		t.Errorf("combined: confidence %v, want >= 0.9", out.Confidence)
	}
	if len(out.Reasons) < 3 {
		t.Errorf("combined: %d reasons, want >= 3 independent sources", len(out.Reasons))
	}
}

func TestClassifyConflictingSignals(t *testing.T) {
	// A stronger OUI outvotes a lone generic port.
	out := Classify(Input{MAC: "b8:27:eb:00:00:01", Ports: []int{9100}})
	if out.Class != IoT {
		t.Errorf("conflict: class = %q, want iot (OUI 0.8 beats port 0.65)", out.Class)
	}
}

func TestClassifyEmpty(t *testing.T) {
	out := Classify(Input{})
	if out.Class != Unknown || out.Confidence != 0 || len(out.Reasons) != 0 {
		t.Errorf("empty input: got %+v, want unknown with no evidence", out)
	}
}

const dockerMAC = "02:42:ac:1d:0a:02"

func TestClassifyLabHosts(t *testing.T) {
	cases := []struct {
		name   string
		in     Input
		class  string
		vendor string
		source string // evidence source that must be present
	}{
		{"docker only", Input{MAC: dockerMAC}, Container, "Docker", "MAC"},
		{"docker ssh only", Input{MAC: dockerMAC, IP: "172.29.10.7", Ports: []int{22}}, Container, "Docker", "MAC"},
		{"postgres", Input{MAC: dockerMAC, Ports: []int{22, 5432}}, Database, "Docker", "port"},
		{"rabbitmq", Input{MAC: dockerMAC, Ports: []int{5672, 15672}}, Broker, "Docker", "port"},
		{"gitea by port", Input{MAC: dockerMAC, Ports: []int{22, 3000}}, Git, "Docker", "port"},
		{"gitea by title", Input{MAC: dockerMAC, Ports: []int{3000}, Titles: []string{"Gitea: Git with a cup of tea"}}, Git, "Docker", "tytuł HTTP"},
		{"web 8080", Input{MAC: dockerMAC, Ports: []int{8080}}, Web, "Docker", "port"},
		{"web 80+443", Input{MAC: dockerMAC, Ports: []int{80, 443}}, Web, "Docker", "port"},
		{"redis", Input{MAC: dockerMAC, Ports: []int{6379}}, Cache, "Docker", "port"},
		{"ftp", Input{MAC: dockerMAC, Ports: []int{21}}, FileServer, "Docker", "port"},
		{"elasticsearch", Input{MAC: dockerMAC, Ports: []int{9200}}, Database, "Docker", "port"},
		{"flask product", Input{MAC: dockerMAC, Ports: []int{5000}, Products: []string{"Gunicorn 20.1.0"}}, Web, "Docker", "produkt"},
		{"gateway ssh", Input{MAC: dockerMAC, IP: "172.29.10.1", Ports: []int{22}}, Gateway, "Docker", "topologia"},
		{"gateway silent", Input{MAC: dockerMAC, IP: "172.29.11.1"}, Gateway, "Docker", "topologia"},
		{"gateway not with db", Input{MAC: dockerMAC, IP: "172.29.10.1", Ports: []int{22, 5432}}, Database, "Docker", "port"},
		{".1 non-docker vendor MAC is not a bridge", Input{MAC: "b8:27:eb:00:00:01", IP: "10.0.0.1", Ports: []int{22}}, IoT, "Raspberry Pi", "OUI"},
		{"scan product only", Input{Products: []string{"PostgreSQL DB 15.4"}}, Database, "", "produkt"},
		{"scan product rabbit", Input{Products: []string{"RabbitMQ"}, Ports: []int{5672}}, Broker, "", "produkt"},
		{"vsftpd", Input{Products: []string{"vsftpd 3.0.5"}}, FileServer, "", "produkt"},
		{"duplicate port from sensor+scan counts once", Input{Ports: []int{5432, 5432}}, Database, "", "port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := Classify(tc.in)
			if out.Class != tc.class {
				t.Fatalf("class = %q, want %q (reasons %+v)", out.Class, tc.class, out.Reasons)
			}
			if out.Vendor != tc.vendor {
				t.Errorf("vendor = %q, want %q", out.Vendor, tc.vendor)
			}
			found := false
			for _, ev := range out.Reasons {
				if ev.Source == tc.source {
					found = true
				}
			}
			if !found {
				t.Errorf("no %q evidence in %+v", tc.source, out.Reasons)
			}
			if out.Confidence <= 0 {
				t.Errorf("confidence = %v, want > 0", out.Confidence)
			}
		})
	}
}

func TestClassifyContainerContextKept(t *testing.T) {
	// A role label still carries the Docker fact as evidence.
	out := Classify(Input{MAC: dockerMAC, Ports: []int{5432}})
	last := out.Reasons[len(out.Reasons)-1]
	if last.Source != "MAC" {
		t.Errorf("last reason = %+v, want the Docker MAC context", last)
	}
	// The duplicate port must not double the weight.
	one := Classify(Input{Ports: []int{5432}})
	two := Classify(Input{Ports: []int{5432, 5432}})
	if one.Confidence != two.Confidence {
		t.Errorf("duplicate port changed confidence: %v vs %v", one.Confidence, two.Confidence)
	}
}
