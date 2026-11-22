package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/edge/aiml"
)

// Shared wire protocol for Basal, Laya and Kev. A backend can use a vendor
// runtime, but the sensor, gate and comparator never depend on that runtime.
// Do not assume different models' probabilities are mutually calibrated.
type systemOneBackend struct {
	Name     string
	URL      string
	Token    string
	Expected string
}

type modelObservation struct {
	Score         float64 `json:"score"`
	ReportedModel string  `json:"reported_model,omitempty"`
	LatencyMS     float64 `json:"latency_ms"`
}

func validateSystemOneURL(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" || u.Path != "/v1/systemone" {
		return fmt.Errorf("invalid System One endpoint; expected http(s)://host:port/v1/systemone")
	}
	if u.Scheme == "https" {
		return nil
	}
	// These three names refer to *private*, isolated Docker Compose services.
	// Never allow arbitrary public HTTP endpoints for telemetry.
	host := strings.ToLower(u.Hostname())
	if u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "basal" || host == "laya" || host == "kev") {
		return nil
	}
	return fmt.Errorf("System One HTTP is allowed only on loopback or named local Docker services; use HTTPS elsewhere")
}

func (b systemOneBackend) Predict(client *http.Client, e aiml.Event, features []float64, baseline float64) (modelObservation, error) {
	if len(features) < 23 {
		return modelObservation{}, fmt.Errorf("expected at least 23 extracted features")
	}
	state := map[string]interface{}{
		"event":                         e,
		"baseline_anomaly":              baseline,
		"recent_host_events_5m":         features[16],
		"recent_new_services_5m":        features[17],
		"recent_fingerprint_changes_5m": features[18],
		"recent_silent_5m":              features[19],
		"recent_distinct_ports_5m":      features[21],
		"host_seen_before":              features[22] > 0,
		"risky_port":                    features[8] > 0,
		"unusual_banner":                features[12] > 0,
	}
	payload := map[string]interface{}{
		"state": state,
		"lang":  "en",
		"questions": map[string]interface{}{
			"attack": map[string]interface{}{
				"type":         "noul",
				"instructions": "Should this passive network-monitoring event be forwarded for centralized security investigation? Treat unexpected service exposure, risky ports, host changes and correlated bursts as suspicious. Silence alone is not evidence of compromise. If evidence is uncertain, prefer investigation.",
				"criteria":     map[string]string{"true": "Escalate for investigation", "false": "Likely routine observation"},
			},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return modelObservation{}, err
	}
	req, err := http.NewRequest(http.MethodPost, b.URL, bytes.NewReader(raw))
	if err != nil {
		return modelObservation{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if b.Token != "" {
		req.Header.Set("Authorization", "Bearer "+b.Token)
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return modelObservation{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
	if err != nil {
		return modelObservation{}, err
	}
	if len(body) > 1024*1024 {
		return modelObservation{}, fmt.Errorf("response exceeded 1 MiB")
	}
	if resp.StatusCode != http.StatusOK {
		return modelObservation{}, fmt.Errorf("%s HTTP %d: %s", b.Name, resp.StatusCode, string(body))
	}
	var out struct {
		Model   string `json:"model"`
		Routing struct {
			Model string `json:"model"`
		} `json:"routing"`
		Answers map[string]struct {
			Noul *float64 `json:"noul"`
		} `json:"answers"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return modelObservation{}, fmt.Errorf("%s invalid JSON: %w", b.Name, err)
	}
	a, ok := out.Answers["attack"]
	if !ok || a.Noul == nil || math.IsNaN(*a.Noul) || math.IsInf(*a.Noul, 0) || *a.Noul < 0 || *a.Noul > 1 {
		return modelObservation{}, fmt.Errorf("%s response missing valid attack.noul", b.Name)
	}
	name := strings.TrimSpace(out.Model)
	if name == "" {
		name = strings.TrimSpace(out.Routing.Model)
	}
	if b.Expected != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(b.Expected)) {
		return modelObservation{}, fmt.Errorf("%s unexpected reported model %q (expected substring %q)", b.Name, name, b.Expected)
	}
	return modelObservation{Score: *a.Noul, ReportedModel: name, LatencyMS: float64(time.Since(start).Microseconds()) / 1000}, nil
}

func configuredBackends(basalURL, layaURL, kevURL string, basalExpected string) ([]systemOneBackend, error) {
	specs := []struct{ name, url, tokenEnv, expected string }{
		{"basal", basalURL, "ASI_BASAL_TOKEN", basalExpected},
		{"laya", layaURL, "ASI_LAYA_TOKEN", ""},
		{"kev", kevURL, "ASI_KEV_TOKEN", ""},
	}
	ret := []systemOneBackend{}
	for _, s := range specs {
		if s.url == "" {
			continue
		}
		if err := validateSystemOneURL(s.url); err != nil {
			return nil, fmt.Errorf("%s: %w", s.name, err)
		}
		ret = append(ret, systemOneBackend{Name: s.name, URL: s.url, Token: os.Getenv(s.tokenEnv), Expected: s.expected})
	}
	return ret, nil
}
