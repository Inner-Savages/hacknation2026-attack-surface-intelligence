package sensor

import (
	"net"
	"net/netip"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var labNet = []netip.Prefix{netip.MustParsePrefix("172.28.0.0/24")}

func tcpFrame(t *testing.T, src, dst string, sport, dport uint16, flags func(*layers.TCP), payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0a},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 0x64},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), Window: 512}
	flags(tcp)
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func decodeOne(t *testing.T, frame []byte) []Observation {
	t.Helper()
	return NewDecoder(labNet).Decode(frame, t0)
}

func serviceObs(obs []Observation) *Observation {
	for i := range obs {
		if obs[i].Port != 0 {
			return &obs[i]
		}
	}
	return nil
}

func TestDecodeSynAckIsOpenPort(t *testing.T) {
	obs := decodeOne(t, tcpFrame(t, "172.28.0.10", "172.28.0.100", 80, 40000,
		func(c *layers.TCP) { c.SYN, c.ACK, c.Seq, c.Ack = true, true, 1000, 1 }, nil))
	s := serviceObs(obs)
	if s == nil || s.Signal != SignalOpen || s.Port != 80 || s.IP != web {
		t.Fatalf("got %+v", obs)
	}
	if obs[0].Signal != SignalSeen || obs[0].MAC != "02:00:00:00:00:0a" {
		t.Fatalf("host observation missing: %+v", obs[0])
	}
}

func TestDecodeRstAnsweringSynIsClosed(t *testing.T) {
	obs := decodeOne(t, tcpFrame(t, "172.28.0.20", "172.28.0.100", 80, 40000,
		func(c *layers.TCP) { c.RST, c.ACK, c.Seq, c.Ack = true, true, 0, 1 }, nil))
	if s := serviceObs(obs); s == nil || s.Signal != SignalClosed {
		t.Fatalf("got %+v", obs)
	}
}

func TestDecodeMidConnectionRstIsIgnored(t *testing.T) {
	obs := decodeOne(t, tcpFrame(t, "172.28.0.20", "172.28.0.100", 80, 40000,
		func(c *layers.TCP) { c.RST, c.ACK, c.Seq = true, true, 123456 }, nil))
	if s := serviceObs(obs); s != nil {
		t.Fatalf("expected no service observation, got %+v", s)
	}
}

func TestDecodeClientSynIsNotAService(t *testing.T) {
	obs := decodeOne(t, tcpFrame(t, "172.28.0.100", "172.28.0.10", 40000, 80,
		func(c *layers.TCP) { c.SYN = true }, nil))
	if s := serviceObs(obs); s != nil {
		t.Fatalf("client SYN produced service: %+v", s)
	}
}

func TestDecodeHTTPResponseBanner(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nServer: nginx/1.31.9\r\nX-Powered-By: PHP/8.1.2\r\n" +
		"Set-Cookie: wordpress_test_cookie=WP%20Cookie%20check; path=/\r\nX-Env: staging\r\n\r\n<html>"
	obs := decodeOne(t, tcpFrame(t, "172.28.0.11", "172.28.0.100", 80, 40000,
		func(c *layers.TCP) { c.ACK, c.PSH, c.Seq = true, true, 5000 }, []byte(resp)))
	s := serviceObs(obs)
	if s == nil || s.Banner == nil {
		t.Fatalf("got %+v", obs)
	}
	want := "http; server=nginx/1.31.9; powered_by=PHP/8.1.2; cookies=wordpress_test_cookie; x-env: staging"
	if got := s.Banner.Fingerprint(); got != want {
		t.Fatalf("fingerprint\n got %q\nwant %q", got, want)
	}
}

func TestDecodeIgnoresHostsOutsideWatchedNets(t *testing.T) {
	obs := decodeOne(t, tcpFrame(t, "8.8.8.8", "172.28.0.100", 443, 40000,
		func(c *layers.TCP) { c.SYN, c.ACK = true, true }, nil))
	if len(obs) != 0 {
		t.Fatalf("expected nothing, got %+v", obs)
	}
}

func TestDecodeARP(t *testing.T) {
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 0x30},
		DstMAC: layers.EthernetBroadcast, EthernetType: layers.EthernetTypeARP}
	arp := &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
		SourceHwAddress: []byte{2, 0, 0, 0, 0, 0x30}, SourceProtAddress: []byte{172, 28, 0, 30},
		DstHwAddress: []byte{0, 0, 0, 0, 0, 0}, DstProtAddress: []byte{172, 28, 0, 1}}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, arp); err != nil {
		t.Fatal(err)
	}
	obs := decodeOne(t, buf.Bytes())
	if len(obs) != 1 || obs[0].IP != netip.MustParseAddr("172.28.0.30") || obs[0].MAC != "02:00:00:00:00:30" {
		t.Fatalf("got %+v", obs)
	}
}
