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
}

func openSettings(dir string) (*settings, error) {
	s := &settings{path: filepath.Join(dir, "settings.json")}
	b, err := os.ReadFile(s.path)
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
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
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
	return s.saveLocked()
}

func (s *settings) snapshot() settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return settings{
		DemoFeed: s.DemoFeed, AIOperator: s.AIOperator, RuleMode: s.RuleMode,
		AIBaseURL: s.AIBaseURL, AIModel: s.AIModel, AIAPIKey: s.AIAPIKey,
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
