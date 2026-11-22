package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// operatorDecision is the structured verdict the LLM operator returns for one
// escalation. Everything it does is applied through the same store mutations
// a human uses, so every AI action lands in the audit log, the case history
// and the live feed under the actor "AI · <model> (operator)".
type operatorDecision struct {
	Threat     string `json:"threat"`     // "none", "low", "medium", "high"
	Status     string `json:"status"`     // one of the case statuses, or "" to leave unchanged
	Note       string `json:"note"`       // short Polish justification, always required
	Action     string `json:"action"`     // "", observe, scan, reanalyze, isolate
	Confidence string `json:"confidence"` // "niska", "średnia", "wysoka"
}

// decide asks the model to act as the SOC operator: assess whether the
// observed traffic looks dangerous and choose the next operator action. The
// model answers with a single JSON object; anything unparseable fails closed
// (no action taken, only an advisory note would be kept).
func (a *AIClient) decide(ctx context.Context, envelope json.RawMessage, logs []LogEntry) (*operatorDecision, error) {
	var sb strings.Builder
	sb.WriteString("Koperta eskalacji (cascadeEnvelope):\n")
	env := envelope
	if len(env) > 12000 {
		env = env[:12000]
	}
	sb.Write(env)
	if len(logs) > 0 {
		sb.WriteString("\n\nOstatnie logi z sensora (najstarsze → najnowsze):\n")
		for _, e := range logs {
			fmt.Fprintf(&sb, "%s %s\n", e.At.Format(time.RFC3339), e.Text)
		}
	}
	reqBody, _ := json.Marshal(map[string]interface{}{
		"model": a.model,
		"messages": []chatMessage{
			{
				Role: "system",
				Content: "Jesteś autonomicznym operatorem SOC konsoli 'Silence on the Wire' — pasywnego monitoringu sieci. " +
					"Oceniasz eskalacje z bramki edge i logi sensora, a następnie podejmujesz działania operatorskie. " +
					"Odpowiadasz WYŁĄCZNIE jednym obiektem JSON (bez markdown, bez komentarza) o polach:\n" +
					`{"threat":"none|low|medium|high","status":"do_weryfikacji|potwierdzony|falszywy_alarm|zamkniety|","note":"...","action":"|observe|scan|reanalyze|isolate|reconnect","confidence":"niska|średnia|wysoka"}` + "\n" +
					"Zasady: 'note' to zwięzłe uzasadnienie po polsku (1-3 zdania), zawsze wymagane. " +
					"Status 'potwierdzony' tylko przy threat medium/high. " +
					"'falszywy_alarm' gdy zdarzenie wygląda na znany, nieszkodliwy ruch (aktualizacje, drukarki, kontrolery). " +
					"Akcja 'isolate' (odcięcie hosta) — tylko przy threat high i wysokiej pewności; system i tak wymaga dla niej potwierdzenia przez człowieka. " +
					"Akcja 'reconnect' przywraca hosta do sieci — wybierz ją, gdy host był odcięty, a zagrożenie minęło lub okazało się fałszywe. " +
					"Przy niskiej pewności wybierz status 'do_weryfikacji' i akcję 'observe' albo 'scan'. " +
					"Nie wymyślaj faktów spoza danych wejściowych.",
			},
			{Role: "user", Content: sb.String()},
		},
		"temperature": 0.1,
	})
	raw, err := a.chat(ctx, reqBody)
	if err != nil {
		return nil, err
	}
	var d operatorDecision
	raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(raw, "```"), "```json"))
	if json.Unmarshal([]byte(raw), &d) != nil || strings.TrimSpace(d.Note) == "" {
		return nil, fmt.Errorf("model nie zwrócił poprawnej decyzji JSON")
	}
	d.Threat = strings.ToLower(strings.TrimSpace(d.Threat))
	d.Action = strings.ToLower(strings.TrimSpace(d.Action))
	return &d, nil
}

// runAIOperator lets the configured LLM triage one case as an autonomous
// operator. Destructive isolation is never executed by the AI: it is armed
// and left for a human's mandatory confirmation, exactly like a human
// operator arming it.
func (s *server) runAIOperator(ctx context.Context, c *Case) {
	client := s.settings.aiClient()
	if client == nil {
		return
	}
	who := "AI · " + client.modelName() + " (operator)"
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	d, err := client.decide(ctx, c.Envelope, s.feed.matching(c, 40))
	if err != nil {
		s.feed.Append("ai", c.SensorID, "Operator AI nie podjął decyzji: "+err.Error(), nil)
		return
	}
	err = s.store.mutate(c.EventID, func(c *Case) (HistoryEntry, error) {
		var did []string
		if validStatus(d.Status) && d.Status != c.Status {
			did = append(did, "status: "+labelStatus(c.Status)+" → "+labelStatus(d.Status))
			c.Status = d.Status
		}
		c.Notes = append(c.Notes, Note{
			At: time.Now(), Actor: who,
			Text: fmt.Sprintf("OCENA ZAGROŻENIA: %s (pewność: %s)\n%s", threatLabel(d.Threat), d.Confidence, d.Note),
		})
		switch d.Action {
		case "":
		case "isolate":
			// The AI may only arm isolation; a human must confirm, so the
			// most destructive action always keeps a person in the loop.
			c.PendingAction = "isolate"
			did = append(did, "zarekomendowano odcięcie hosta od sieci — oczekuje na potwierdzenie człowieka")
		default:
			if label, ok := validActions[d.Action]; ok {
				c.Actions = append(c.Actions, ActionRecord{At: time.Now(), Action: d.Action, Actor: who, Executed: true})
				did = append(did, label+operatorDemoSuffix(s))
			}
		}
		text := "Decyzja operatora AI: zagrożenie " + threatLabel(d.Threat)
		if len(did) > 0 {
			text += " — " + strings.Join(did, "; ")
		}
		return HistoryEntry{At: time.Now(), Kind: "ai", Actor: who, Text: text}, nil
	})
	if err != nil {
		s.feed.Append("ai", c.SensorID, "Operator AI nie mógł zapisać decyzji: "+err.Error(), nil)
	}
}

func operatorDemoSuffix(s *server) string {
	if s.demoData {
		return " (tryb demo — ruch sieciowy niezmieniony)"
	}
	return ""
}

func threatLabel(t string) string {
	switch t {
	case "none":
		return "brak"
	case "low":
		return "niskie"
	case "medium":
		return "średnie"
	case "high":
		return "WYSOKIE"
	}
	return t
}
