package result

import "time"

// HTTP is what the prober learned from a web service. Only GET requests
// were sent: the page, its redirects (same host only) and the favicon.
type HTTP struct {
	URL        string              `json:"url"`
	FinalURL   string              `json:"final_url"`
	Status     int                 `json:"status"`
	Title      string              `json:"title,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"` // lower-case names
	Cookies    []Cookie            `json:"cookies,omitempty"`
	Redirects  []Redirect          `json:"redirects,omitempty"`
	TLS        *TLS                `json:"tls,omitempty"`
	Favicon    *Favicon            `json:"favicon,omitempty"`
	BodySize   int                 `json:"body_size"`
	BodySHA256 string              `json:"body_sha256,omitempty"`
	Duration   Duration            `json:"duration"`
	Error      string              `json:"error,omitempty"`

	// Body is the (size-limited) response body of the final page, kept in
	// memory for fingerprinting and never written to the result file.
	Body []byte `json:"-"`
}

// Cookie records a cookie's name and flags, never its value.
type Cookie struct {
	Name     string `json:"name"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site,omitempty"`
}

// Redirect is one hop of a redirect chain.
type Redirect struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Location string `json:"location"`
}

// TLS describes the certificate and session of an HTTPS service.
type TLS struct {
	Version    string    `json:"version"`
	Cipher     string    `json:"cipher"`
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	DNSNames   []string  `json:"dns_names,omitempty"`
	IPs        []string  `json:"ips,omitempty"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed"`
	Expired    bool      `json:"expired"`
	SHA256     string    `json:"sha256"` // certificate fingerprint
}

// Favicon identifies a site icon. Hash is the Shodan-compatible mmh3 hash
// (http.favicon.hash), so results can be matched against public queries.
type Favicon struct {
	URL  string `json:"url"`
	Hash int32  `json:"mmh3"`
	MD5  string `json:"md5"`
	Size int    `json:"size"`
}
