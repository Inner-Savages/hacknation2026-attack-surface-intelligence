package sensor

// DefaultBPF lets through only packets the decoder can learn from, so the
// kernel drops the bulk of established-connection traffic before it reaches
// userspace:
//   - ARP (host presence),
//   - TCP with SYN or RST set (handshakes and closed-port replies),
//   - TCP whose payload starts with "HTTP" (0x48545450): response heads with banners.
//
// The payload offset is the TCP data offset: (tcp[12] & 0xf0) >> 2 bytes.
// Trade-off: a host that only exchanges long-lived established traffic is
// "seen" again only at its next handshake.
const DefaultBPF = "arp or (tcp and (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0 or tcp[((tcp[12] & 0xf0) >> 2):4] = 0x48545450))"

// DefaultSnapLen is enough for the HTTP response head we parse; the body is
// never needed.
const DefaultSnapLen = 2048
