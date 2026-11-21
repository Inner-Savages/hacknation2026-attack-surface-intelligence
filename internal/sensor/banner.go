package sensor

import (
	"bytes"
	"sort"
	"strings"
)

// Banner is what the sensor learns about a service from its responses.
// Only fields that are stable across requests (not per-path) go into the
// fingerprint, so browsing different URLs does not look like a change.
type Banner struct {
	Protocol  string   `json:"protocol"`
	Server    string   `json:"server,omitempty"`
	PoweredBy string   `json:"powered_by,omitempty"`
	Cookies   []string `json:"cookies,omitempty"` // cookie names only, never values
	Extra     []string `json:"extra,omitempty"`   // other notable headers, "Name: value"
}

// notable headers worth tracking for change detection and later fingerprinting.
var notableHeaders = map[string]bool{
	"x-env": true, "x-generator": true, "x-aspnet-version": true,
	"x-drupal-cache": true, "x-jenkins": true, "via": true,
}

// Fingerprint is a stable string for comparing banners; "" for nil.
func (b *Banner) Fingerprint() string {
	if b == nil {
		return ""
	}
	parts := []string{b.Protocol}
	if b.Server != "" {
		parts = append(parts, "server="+b.Server)
	}
	if b.PoweredBy != "" {
		parts = append(parts, "powered_by="+b.PoweredBy)
	}
	// Cookie names are kept in the banner but left out of the fingerprint:
	// many apps set a cookie on some responses only (Gitea's i_like_gitea is
	// on / but not on 404s), so their presence would look like a change.
	parts = append(parts, b.Extra...)
	return strings.Join(parts, "; ")
}

// ParseHTTPResponse extracts a banner from the first segment of an HTTP/1.x
// response. It returns nil when the payload is not a response head.
func ParseHTTPResponse(payload []byte) *Banner {
	if !bytes.HasPrefix(payload, []byte("HTTP/1.")) {
		return nil
	}
	head := payload
	if i := bytes.Index(payload, []byte("\r\n\r\n")); i >= 0 {
		head = payload[:i]
	}
	lines := strings.Split(string(head), "\r\n")
	b := &Banner{Protocol: "http"}
	cookies := map[string]bool{}
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name, value = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)
		switch {
		case name == "server":
			b.Server = value
		case name == "x-powered-by":
			b.PoweredBy = value
		case name == "set-cookie":
			if n, _, ok := strings.Cut(value, "="); ok && n != "" {
				cookies[strings.TrimSpace(n)] = true
			}
		case notableHeaders[name]:
			b.Extra = append(b.Extra, name+": "+value)
		}
	}
	for c := range cookies {
		b.Cookies = append(b.Cookies, c)
	}
	sort.Strings(b.Cookies)
	sort.Strings(b.Extra)
	return b
}
