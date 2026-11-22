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
	// Locally administered address (U/L bit set) matches no vendor and must
	// not fabricate a classification by itself.
	out := Classify(Input{MAC: "02:42:ac:11:00:02"})
	if out.Vendor != "" {
		t.Errorf("locally administered MAC: vendor = %q, want empty", out.Vendor)
	}
	if out.Class != Unknown {
		t.Errorf("no other signals: class = %q, want %q", out.Class, Unknown)
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
		{[]int{22, 3306}, Server},
		{[]int{3389}, Workstation},
		{[]int{5060}, Phone},
		{[]int{80, 443}, Unknown}, // generic web says nothing
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
