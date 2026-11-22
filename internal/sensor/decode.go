package sensor

import (
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Decoder turns raw Ethernet frames into observations about hosts inside
// the scope. Not safe for concurrent use (reuses buffers).
type Decoder struct {
	scope   Scope
	parser  *gopacket.DecodingLayerParser
	eth     layers.Ethernet
	arp     layers.ARP
	ip4     layers.IPv4
	tcp     layers.TCP
	payload gopacket.Payload
	decoded []gopacket.LayerType
}

// NewDecoder reports only on addresses inside scope.
func NewDecoder(scope Scope) *Decoder {
	d := &Decoder{scope: scope}
	d.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&d.eth, &d.arp, &d.ip4, &d.tcp, &d.payload)
	d.parser.IgnoreUnsupported = true // UDP, IPv6, ICMP...: skipped for now
	return d
}

// Decode returns the observations carried by one frame.
func (d *Decoder) Decode(frame []byte, ts time.Time) []Observation {
	// Errors here mean truncated/odd frames; whatever decoded is still usable.
	_ = d.parser.DecodeLayers(frame, &d.decoded)

	var out []Observation
	var src netip.Addr
	var mac string
	for _, lt := range d.decoded {
		switch lt {
		case layers.LayerTypeEthernet:
			mac = d.eth.SrcMAC.String()
		case layers.LayerTypeARP:
			ip, ok := netip.AddrFromSlice(d.arp.SourceProtAddress)
			if ok && d.scope.Contains(ip.Unmap()) {
				out = append(out, Observation{Time: ts, IP: ip.Unmap(), MAC: mac, Signal: SignalSeen})
			}
		case layers.LayerTypeIPv4:
			ip, ok := netip.AddrFromSlice(d.ip4.SrcIP)
			if ok && d.scope.Contains(ip.Unmap()) {
				src = ip.Unmap()
				out = append(out, Observation{Time: ts, IP: src, MAC: mac, Signal: SignalSeen})
			}
		case layers.LayerTypeTCP:
			if !src.IsValid() {
				continue
			}
			if o, ok := d.tcpObservation(src, ts); ok {
				out = append(out, o)
			}
		}
	}
	return out
}

// tcpObservation reads service state from the server side of a connection:
//   - SYN+ACK            -> port open
//   - RST+ACK with seq 0 -> reply to a SYN on a closed port (Linux/BSD stacks)
//   - payload "HTTP/1.x" -> port open, with banner
func (d *Decoder) tcpObservation(src netip.Addr, ts time.Time) (Observation, bool) {
	t := &d.tcp
	o := Observation{Time: ts, IP: src, Port: uint16(t.SrcPort), Proto: "tcp"}
	switch {
	case t.SYN && t.ACK:
		o.Signal = SignalOpen
	case t.RST && t.ACK && t.Seq == 0:
		o.Signal = SignalClosed
	case len(t.Payload) > 0:
		b := ParseHTTPResponse(t.Payload)
		if b == nil {
			return o, false
		}
		o.Signal, o.Banner = SignalOpen, b
	default:
		return o, false
	}
	return o, true
}
