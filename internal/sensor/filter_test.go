package sensor

import (
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// Compiles DefaultBPF with libpcap and checks it against the same frames the
// decoder tests use: everything the decoder learns from must pass, plain
// established traffic must not.
func TestDefaultBPF(t *testing.T) {
	bpf, err := pcap.NewBPF(layers.LinkTypeEthernet, DefaultSnapLen, DefaultBPF)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	const srv, cli = "172.28.0.10", "172.28.0.100"
	syn := func(c *layers.TCP) { c.SYN = true }
	synAck := func(c *layers.TCP) { c.SYN, c.ACK = true, true }
	rstAck := func(c *layers.TCP) { c.RST, c.ACK = true, true }
	ack := func(c *layers.TCP) { c.ACK = true }
	psh := func(c *layers.TCP) { c.ACK, c.PSH = true, true }
	finAck := func(c *layers.TCP) { c.FIN, c.ACK = true, true }
	cases := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"client SYN", tcpFrame(t, cli, srv, 40000, 80, syn, nil), true},
		{"server SYN-ACK", tcpFrame(t, srv, cli, 80, 40000, synAck, nil), true},
		{"RST to closed port", tcpFrame(t, srv, cli, 8080, 40000, rstAck, nil), true},
		{"HTTP response head", tcpFrame(t, srv, cli, 80, 40000, psh, []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")), true},
		{"bare ACK", tcpFrame(t, cli, srv, 40000, 80, ack, nil), false},
		{"client GET", tcpFrame(t, cli, srv, 40000, 80, psh, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")), false},
		{"response body segment", tcpFrame(t, srv, cli, 80, 40000, ack, []byte("<html><body>...</body></html>")), false},
		{"FIN", tcpFrame(t, srv, cli, 80, 40000, finAck, nil), false},
	}
	for _, tc := range cases {
		ci := gopacket.CaptureInfo{CaptureLength: len(tc.frame), Length: len(tc.frame)}
		if got := bpf.Matches(ci, tc.frame); got != tc.want {
			t.Errorf("%s: matches=%v, want %v", tc.name, got, tc.want)
		}
	}
}
