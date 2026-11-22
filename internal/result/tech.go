package result

// Tech is a technology recognized on a service by fingerprinting.
type Tech struct {
	Name       string   `json:"name"`
	Category   string   `json:"category,omitempty"` // cms, server, app, database, iot, ...
	Version    string   `json:"version,omitempty"`
	Confidence float64  `json:"confidence"`     // 0..1
	Tags       []string `json:"tags,omitempty"` // admin-panel, staging, ...
	Evidence   []string `json:"evidence"`
	Vulns      []Vuln   `json:"vulns,omitempty"` // CVEs affecting this exact version, EPSS-ranked
}

// Vuln is one known vulnerability affecting a detected product version,
// ranked by exploitation probability rather than severity alone.
type Vuln struct {
	CVE        string  `json:"cve"`
	CVSS       float64 `json:"cvss,omitempty"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile,omitempty"` // EPSS percentile 0..1
	KEV        bool    `json:"kev,omitempty"`        // CISA Known Exploited Vulnerabilities
	Summary    string  `json:"summary,omitempty"`
}

// Page is a fetched HTTP resource used as fingerprinting evidence
// (e.g. /wp-login.php). Body is size-limited and never serialized.
type Page struct {
	Path    string
	Status  int
	Headers map[string][]string // lower-case names
	Title   string
	Body    []byte
}
