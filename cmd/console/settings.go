package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// settings holds console configuration that operators can change at runtime
// from the UI. It is persisted next to the case store; environment variables
// (ASI_AI_*, -demo) provide the defaults, settings override them.
type settings struct {
	mu   sync.Mutex
	path string

	// DemoFeed switches the synthetic demo log generator on and off. Switching
	// it off puts the console in live mode: only real events from the edge.
	DemoFeed *bool `json:"demo_feed,omitempty"`
	// AIOperator lets the configured LLM act as an autonomous operator
	// (statuses, notes, non-destructive actions) with full audit visibility.
	AIOperator *bool `json:"ai_operator,omitempty"`
	// RuleMode replaces the model stack (Bayesian stage, decision tree,
	// basal/laya/kev backends, LLM operator) with the deterministic rule
	// engine for when the models digest too slowly.
	RuleMode *bool `json:"rule_mode,omitempty"`
	// AI provider overrides; empty strings mean "fall back to environment".
	AIBaseURL string `json:"ai_base_url,omitempty"`
	AIModel   string `json:"ai_model,omitempty"`
	AIAPIKey  string `json:"ai_api_key,omitempty"` // write-only in API responses

	// Ground truth: periodic active control scans of passively silent
	// hosts. Without them a host that stops speaking is indistinguishable
	// from a host that is off (the silent_stealth observability gap).
	GTEnabled     *bool `json:"gt_enabled,omitempty"`      // default on
	GTIntervalMin int   `json:"gt_interval_min,omitempty"` // default 360 (6 h)
	GTSilentMin   int   `json:"gt_silent_min,omitempty"`   // default 60: silence that qualifies for a scan
	GTSampleSize  int   `json:"gt_sample_size,omitempty"`  // default 50 hosts per run

	// CVELookup enriches detected services with CVEs from NVD ranked by
	// EPSS (KEV flagged). Default on; NVD_API_KEY raises the rate limit.
	CVELookup *bool `json:"cve_lookup,omitempty"`

	// Exposure correlates the inside view with what internet-wide scanners
	// (Shodan/Censys) see of the public IP. Default OFF: it queries an
	// external API, so it is opt-in. The key is write-only in API
	// responses; env SHODAN_API_KEY / CENSYS_API_ID+CENSYS_API_SECRET
	// provide the fallback.
	ExposureEnabled     *bool  `json:"exposure_enabled,omitempty"`
	ExposureProvider    string `json:"exposure_provider,omitempty"`     // shodan (default) | censys
	ExposureAPIKey      string `json:"exposure_api_key,omitempty"`      // censys: "api-id:api-secret"
	ExposurePublicIP    string `json:"exposure_public_ip,omitempty"`    // empty = autodetect egress IP
	ExposureIntervalMin int    `json:"exposure_interval_min,omitempty"` // default 360 (6 h)

	// TLS certificate monitoring over the certificates captured by control
	// scans. Default ON: it is pure arithmetic over data the console
	// already holds (no external calls).
	TLSEnabled     *bool `json:"tls_enabled,omitempty"`
	TLSIntervalMin int   `json:"tls_interval_min,omitempty"` // default 60 (1 h)
}

func openSettings(dir string) (*settings, error) {
	s := &settings{path: filepath.Join(dir, "settings.json")}
	b, err := rest.ReadFile(s.path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(b, s) != nil {
		// Corrupt settings should not take the console down; start fresh.
		return &settings{path: s.path}, nil
	}
	return s, nil
}

func (s *settings) saveLocked() error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return rest.WriteFile(s.path, b, 0o600)
}

// configPatch is a partial update from the UI: nil fields keep their current
// values, so the form can change one setting without resending the others.
type configPatch struct {
	DemoFeed   *bool   `json:"demo_feed"`
	AIOperator *bool   `json:"ai_operator"`
	RuleMode   *bool   `json:"rule_mode"`
	AIBaseURL  *string `json:"ai_base_url"`
	AIModel    *string `json:"ai_model"`
	AIAPIKey   *string `json:"ai_api_key"`

	GTEnabled     *bool `json:"gt_enabled"`
	GTIntervalMin *int  `json:"gt_interval_min"`
	GTSilentMin   *int  `json:"gt_silent_min"`
	GTSampleSize  *int  `json:"gt_sample_size"`
	CVELookup     *bool `json:"cve_lookup"`

	ExposureEnabled     *bool   `json:"exposure_enabled"`
	ExposureProvider    *string `json:"exposure_provider"`
	ExposureAPIKey      *string `json:"exposure_api_key"`
	ExposurePublicIP    *string `json:"exposure_public_ip"`
	ExposureIntervalMin *int    `json:"exposure_interval_min"`
	TLSEnabled          *bool   `json:"tls_enabled"`
	TLSIntervalMin      *int    `json:"tls_interval_min"`
}

// update applies the non-nil fields of the patch and persists the result.
func (s *settings) update(p configPatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.DemoFeed != nil {
		s.DemoFeed = p.DemoFeed
	}
	if p.AIOperator != nil {
		s.AIOperator = p.AIOperator
	}
	if p.RuleMode != nil {
		s.RuleMode = p.RuleMode
	}
	if p.AIBaseURL != nil {
		s.AIBaseURL = *p.AIBaseURL
	}
	if p.AIModel != nil {
		s.AIModel = *p.AIModel
	}
	if p.AIAPIKey != nil {
		s.AIAPIKey = *p.AIAPIKey
	}
	if p.GTEnabled != nil {
		s.GTEnabled = p.GTEnabled
	}
	if p.GTIntervalMin != nil && *p.GTIntervalMin >= 0 {
		s.GTIntervalMin = *p.GTIntervalMin
	}
	if p.GTSilentMin != nil && *p.GTSilentMin >= 0 {
		s.GTSilentMin = *p.GTSilentMin
	}
	if p.GTSampleSize != nil && *p.GTSampleSize >= 0 {
		s.GTSampleSize = *p.GTSampleSize
	}
	if p.CVELookup != nil {
		s.CVELookup = p.CVELookup
	}
	if p.ExposureEnabled != nil {
		s.ExposureEnabled = p.ExposureEnabled
	}
	if p.ExposureProvider != nil {
		s.ExposureProvider = *p.ExposureProvider
	}
	if p.ExposureAPIKey != nil {
		s.ExposureAPIKey = *p.ExposureAPIKey
	}
	if p.ExposurePublicIP != nil {
		s.ExposurePublicIP = *p.ExposurePublicIP
	}
	if p.ExposureIntervalMin != nil && *p.ExposureIntervalMin >= 0 {
		s.ExposureIntervalMin = *p.ExposureIntervalMin
	}
	if p.TLSEnabled != nil {
		s.TLSEnabled = p.TLSEnabled
	}
	if p.TLSIntervalMin != nil && *p.TLSIntervalMin >= 0 {
		s.TLSIntervalMin = *p.TLSIntervalMin
	}
	return s.saveLocked()
}

func (s *settings) snapshot() settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return settings{
		DemoFeed: s.DemoFeed, AIOperator: s.AIOperator, RuleMode: s.RuleMode,
		AIBaseURL: s.AIBaseURL, AIModel: s.AIModel, AIAPIKey: s.AIAPIKey,
		GTEnabled: s.GTEnabled, GTIntervalMin: s.GTIntervalMin,
		GTSilentMin: s.GTSilentMin, GTSampleSize: s.GTSampleSize,
		CVELookup:           s.CVELookup,
		ExposureEnabled:     s.ExposureEnabled,
		ExposureProvider:    s.ExposureProvider,
		ExposureAPIKey:      s.ExposureAPIKey,
		ExposurePublicIP:    s.ExposurePublicIP,
		ExposureIntervalMin: s.ExposureIntervalMin,
		TLSEnabled:          s.TLSEnabled,
		TLSIntervalMin:      s.TLSIntervalMin,
	}
}

// aiClient resolves the effective AI configuration: settings override the
// environment. Returns nil when AI is not configured at all.
func (s *settings) aiClient() *AIClient {
	snap := s.snapshot()
	base := firstNonEmpty(snap.AIBaseURL, os.Getenv("ASI_AI_BASE_URL"))
	key := firstNonEmpty(snap.AIAPIKey, os.Getenv("ASI_AI_API_KEY"))
	model := firstNonEmpty(snap.AIModel, os.Getenv("ASI_AI_MODEL"))
	if base == "" && key == "" {
		return nil
	}
	if base == "" {
		base = "https://api.openai.com/v1"
	}
	if model == "" {
		model = "gpt-4o-mini"
	}
	return newAIClient(base, key, model)
}

func firstNonEmpty(v ...string) string {
	for _, x := range v {
		if x != "" {
			return x
		}
	}
	return ""
}
