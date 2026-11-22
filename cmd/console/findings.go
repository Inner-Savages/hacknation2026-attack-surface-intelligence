package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// findingPayload mirrors trigger.Finding (internal/trigger): the console
// parses only the fields it correlates evidence on, everything else rides
// along in the raw envelope stored on the case.
type findingPayload struct {
	Time   time.Time `json:"time"`
	Target struct {
		IP   string `json:"ip"`
		Port int    `json:"port,omitempty"`
	} `json:"target"`
	Kind    string  `json:"kind"`
	Verdict string  `json:"verdict"`
	Score   float64 `json:"score,omitempty"`
	Reason  string  `json:"reason,omitempty"`
	Events  []struct {
		Time string `json:"time"`
		Type string `json:"type"`
		IP   string `json:"ip"`
		Port int    `json:"port,omitempty"`
	} `json:"events"`
	Services []struct {
		Port    int      `json:"port"`
		Name    string   `json:"name,omitempty"`
		Product string   `json:"product,omitempty"`
		Version string   `json:"version,omitempty"`
		Title   string   `json:"title,omitempty"`
		Tech    []string `json:"tech,omitempty"`
	} `json:"services,omitempty"`
	Changes *struct {
		Summary struct {
			NewServices     int `json:"new_services"`
			GoneServices    int `json:"gone_services"`
			ChangedServices int `json:"changed_services"`
		} `json:"summary"`
	} `json:"changes,omitempty"`
	Error string `json:"error,omitempty"`
}

// verdictExplain renders the trigger's verdict in operator language: the
// active scan either corroborates the passive signal or refutes it.
func verdictExplain(f *findingPayload) string {
	switch f.Verdict {
	case "still-open":
		return "port nadal odpowiada — aktywna weryfikacja OBNALA ciszę pasywną (usługa żyje)"
	case "gone-confirmed":
		return "port nie odpowiada — aktywna weryfikacja POTWIERDZIŁA zniknięcie usługi"
	case "still-up":
		return "host odpowiada na innych portach — aktywna weryfikacja OBNALA ciszę pasywną (host żyje)"
	case "down-confirmed":
		return "host nie odpowiada — aktywna weryfikacja POTWIERDZIŁA niedostępność"
	case "scanned":
		return "celowany skan aktywny zakończony"
	case "error":
		return "skan aktywny nie powiódł się: " + f.Error
	}
	return "werdykt: " + f.Verdict
}

// evidenceText builds the human-readable evidence summary attached to the
// correlated case: verdict, open services with recognized technologies and
// the diff against the previous scan of the same target.
func evidenceText(f *findingPayload) string {
	var b strings.Builder
	b.WriteString(verdictExplain(f))
	if len(f.Services) > 0 {
		var svcs []string
		for _, s := range f.Services {
			label := strconv.Itoa(s.Port) + "/" + s.Name
			if s.Product != "" {
				label += " " + s.Product
				if s.Version != "" {
					label += " " + s.Version
				}
			}
			if len(s.Tech) > 0 {
				label += " [" + strings.Join(s.Tech, ", ") + "]"
			}
			svcs = append(svcs, label)
		}
		b.WriteString(". Otwarte usługi: " + strings.Join(svcs, "; "))
	}
	if f.Changes != nil {
		c := f.Changes.Summary
		b.WriteString(fmt.Sprintf(". Zmiany od poprzedniego skanu celu: +%d -%d ~%d usług", c.NewServices, c.GoneServices, c.ChangedServices))
	}
	if f.Reason != "" {
		b.WriteString(fmt.Sprintf(". Ocena edge: %.2f (%s)", f.Score, f.Reason))
	}
	return b.String()
}

// intakeFindings accepts active-verification findings from the trigger
// (bearer token, same contract as the gate's intake) and correlates each
// one with the open case for the same host — or opens a case when the
// finding arrived without one, so verified evidence is never orphaned.
func (s *server) intakeFindings(w http.ResponseWriter, r *http.Request) {
	if s.token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) != 1 {
		http.Error(w, "unauthorized", 401)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4*1024*1024))
	if err != nil {
		http.Error(w, "invalid body", 400)
		return
	}
	var f findingPayload
	if json.Unmarshal(raw, &f) != nil || f.Target.IP == "" || f.Verdict == "" {
		http.Error(w, "expected a trigger finding", 400)
		return
	}
	c, found := s.correlateFinding(&f, raw)
	target := f.Target.IP
	if f.Target.Port > 0 {
		target += ":" + strconv.Itoa(f.Target.Port)
	}
	if found {
		s.feed.Append("verify", c.SensorID, "Aktywna weryfikacja "+target+": "+verdictExplain(&f), raw)
	} else {
		s.feed.Append("verify", "trigger", "Aktywna weryfikacja "+target+" otwiera nową sprawę: "+verdictExplain(&f), raw)
	}
	writeJSON(w, 200, map[string]interface{}{"case": c.EventID, "correlated": found})
}

// correlateFinding attaches the finding's evidence to the newest open case
// about the host (preferring a port match), or opens a new case from the
// finding. The history entry and note carry the same audit weight as a
// human's or the AI operator's work.
func (s *server) correlateFinding(f *findingPayload, raw []byte) (*Case, bool) {
	c, found := s.findOpenCase(f.Target.IP, f.Target.Port)
	if !found {
		sum := sha256.Sum256(raw)
		eventType, eventTime := f.Kind, f.Time.Format(time.RFC3339Nano)
		if len(f.Events) > 0 {
			eventType, eventTime = f.Events[len(f.Events)-1].Type, f.Events[len(f.Events)-1].Time
		}
		target := "—"
		if f.Target.Port > 0 {
			target = "tcp:" + strconv.Itoa(f.Target.Port)
		}
		reason := f.Reason
		if reason == "" {
			reason = "trigger_finding"
		}
		nc := &Case{
			EventID: "fx-" + hex.EncodeToString(sum[:8]), Received: time.Now(), Envelope: append([]byte{}, raw...),
			SensorID: "trigger", EventType: eventType, EventTime: eventTime,
			Source: f.Target.IP, Target: target, Score: f.Score, Reason: reason, Status: StatusNew,
		}
		if _, err := s.store.AddEscalation(nc); err != nil {
			s.feed.Append("verify", "trigger", "Nie udało się utworzyć sprawy z findingu: "+err.Error(), nil)
			return nc, false
		}
		c = nc
	}
	text := evidenceText(f)
	who := "aktywna weryfikacja (trigger)"
	_ = s.store.mutate(c.EventID, func(c *Case) (HistoryEntry, error) {
		c.Notes = append(c.Notes, Note{At: time.Now(), Actor: who, Text: text})
		return HistoryEntry{At: time.Now(), Kind: "verify", Actor: who, Text: "Aktywna weryfikacja: " + verdictExplain(f)}, nil
	})
	out, _ := s.store.Get(c.EventID)
	return out, found
}

// findOpenCase returns the newest open case about ip, preferring one whose
// derived target carries the finding's port.
func (s *server) findOpenCase(ip string, port int) (*Case, bool) {
	var best *Case
	suffix := ":" + strconv.Itoa(port)
	for _, c := range s.store.ListCases() {
		if c.Status != StatusNew && c.Status != StatusVerify {
			continue
		}
		if c.Source != ip {
			continue
		}
		if best == nil || c.Received.After(best.Received) || (port > 0 && strings.HasSuffix(c.Target, suffix) && !strings.HasSuffix(best.Target, suffix)) {
			best = c
		}
	}
	return best, best != nil
}

// requestVerification asks the trigger for a targeted active scan of the
// case's host (and port, when the case has one): the console's "scan"
// action becomes a real request for active verification, not only a record
// of intent. A synthetic sensor event drives the trigger's normal policy
// (allow list, debounce, cooldown), so an operator cannot turn the console
// into a scan amplifier. Best-effort: failures land in the live feed.
func (s *server) requestVerification(c *Case) {
	if s.triggerURL == "" {
		return
	}
	typ := "host_new" // ScanHost: no port on the case
	if port := caseTargetPort(c.Target); port > 0 {
		typ = "service_new" // ScanService on that port
	}
	event := map[string]interface{}{
		"time": time.Now().UTC().Format(time.RFC3339Nano), "type": typ,
		"ip": c.Source, "port": caseTargetPort(c.Target), "proto": "tcp",
		"source": "console", "sensor": c.SensorID,
	}
	body, err := json.Marshal([]map[string]interface{}{event})
	if err != nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "POST", s.triggerURL, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if s.triggerToken != "" {
			req.Header.Set("Authorization", "Bearer "+s.triggerToken)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			s.feed.Append("verify", c.SensorID, "Zlecenie skanu dla "+c.Source+" nie dotarło do triggera: "+err.Error(), nil)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			s.feed.Append("verify", c.SensorID, fmt.Sprintf("Trigger odrzucił zlecenie skanu dla %s (HTTP %d)", c.Source, resp.StatusCode), nil)
			return
		}
		s.feed.Append("verify", c.SensorID, "Zlecono triggerowi celowany skan "+c.Source+" — finding skoreluje się ze sprawą", nil)
	}()
}

// caseTargetPort parses the port out of the derived target ("tcp:22").
func caseTargetPort(target string) int {
	parts := strings.Split(target, ":")
	if len(parts) < 2 {
		return 0
	}
	p, _ := strconv.Atoi(parts[len(parts)-1])
	return p
}
