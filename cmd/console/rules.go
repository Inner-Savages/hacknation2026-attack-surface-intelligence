package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rule is one deterministic triage rule. The rule engine replaces the model
// stack (Bayesian stage, decision tree, basal/laya/kev backends) when those
// digest too slowly: with rule mode enabled the console triages every new
// escalation against the ordered rule list — instantly, offline, with the
// same audit trail a human or the AI operator would leave.
//
// Rules are evaluated in list order; the first match wins. Empty condition
// fields match everything. Destructive isolation is only ever armed — a
// human confirms, exactly like with the AI operator.
type Rule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`

	// Conditions (all must match; empty means "any").
	EventTypes []string `json:"event_types,omitempty"`
	Ports      []int    `json:"ports,omitempty"`
	IPMatch    string   `json:"ip_match,omitempty"` // CIDR or substring of the source host
	SensorID   string   `json:"sensor_id,omitempty"`
	Reasons    []string `json:"reasons,omitempty"`
	MinScore   *float64 `json:"min_score,omitempty"`
	Unresolved *bool    `json:"unresolved,omitempty"`

	// Outcome applied to the case.
	SetStatus string `json:"set_status,omitempty"` // case status, "" = leave
	Action    string `json:"action,omitempty"`     // observe, scan, reanalyze, isolate (armed only)
	Assign    string `json:"assign,omitempty"`
	Note      string `json:"note,omitempty"` // free-text justification recorded on the case
}

// ruleStore keeps the ordered rule list durable next to the case store.
type ruleStore struct {
	mu    sync.Mutex
	path  string
	rules []*Rule
}

func openRules(dir string) (*ruleStore, error) {
	rs := &ruleStore{path: filepath.Join(dir, "rules.json"), rules: []*Rule{}}
	b, err := os.ReadFile(rs.path)
	if os.IsNotExist(err) {
		// First run: seed the starter rules so the engine is useful out of
		// the box. The list is persisted, so operators can edit or delete it.
		if err := rs.replace(defaultRules()); err != nil {
			return nil, err
		}
		return rs, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(b, &rs.rules) != nil {
		return nil, fmt.Errorf("corrupt rules.json")
	}
	return rs, nil
}

// defaultRules ports the heuristics the edge bakes into its feature
// extractor (internal/edge/aiml/model.go: the risky_port and
// management_port classifications) into editable console rules, and adds
// coverage for the gate's fail-open escalation path. Ordered: the first
// match wins, so specific verdicts come before generic ones. Destructive
// isolation is only ever armed — a human confirms.
func defaultRules() []*Rule {
	score06, score09 := 0.6, 0.9
	unresolved := true
	return []*Rule{
		{
			Name: "Fail-open — niekompletny sygnał modeli", Enabled: true,
			Unresolved: &unresolved,
			SetStatus:  StatusVerify, Action: "observe",
			Note: "Eskalacja fail-open: model nie dostarczył pełnego sygnału (powód zaczyna się od fail_open) — wzmocniona obserwacja do czasu weryfikacji człowieka.",
		},
		{
			Name: "C2/backdoor — porty 4444, 1337, 6667", Enabled: true,
			EventTypes: []string{"service_new", "service_changed"},
			Ports:      []int{4444, 1337, 6667},
			SetStatus:  StatusVerify, Action: "isolate",
			Note: "Port typowy dla C2/backdoora (Metasploit, IRC) — reguła uzbraja odcięcie hosta, potwierdza je człowiek.",
		},
		{
			Name: "Zarządzanie wystawione — Telnet/RDP/VNC/WinRM/Docker", Enabled: true,
			EventTypes: []string{"service_new", "service_changed"},
			Ports:      []int{23, 3389, 5900, 5985, 2375},
			SetStatus:  StatusVerify, Action: "scan",
			Note: "Usługa zarządcza na porcie wrażliwym (klasyfikacja edge: management_port) — zlecono aktywny skan i weryfikację.",
		},
		{
			Name: "Wysoka ocena modeli ≥ 0.9", Enabled: true,
			MinScore:  &score09,
			SetStatus: StatusVerify, Action: "scan",
			Note: "Bardzo wysoka ocena modeli — priorytetowa weryfikacja z aktywnym skanem hosta.",
		},
		{
			Name: "Porty ryzykowne przy ocenie ≥ 0.6 — FTP/SSH/SMB/proxy", Enabled: true,
			EventTypes: []string{"service_new", "service_changed"},
			Ports:      []int{21, 22, 445, 8080, 8443, 8888},
			MinScore:   &score06,
			SetStatus:  StatusVerify,
			Note:       "Port z listy risky_port edge przy podniesionej ocenie — eskalacja do weryfikacji.",
		},
		{
			Name: "Nowy host w sieci", Enabled: true,
			EventTypes: []string{"host_new"},
			Action:     "observe",
			Note:       "Nowy host w sieci — wzmocniona obserwacja do czasu ustalenia baseline'u.",
		},
	}
}

func (rs *ruleStore) list() []*Rule {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := make([]*Rule, len(rs.rules))
	copy(out, rs.rules)
	return out
}

// replace swaps the whole ordered list atomically and persists it.
func (rs *ruleStore) replace(rules []*Rule) error {
	for i, r := range rules {
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("reguła %d: nazwa jest wymagana", i+1)
		}
		if r.SetStatus != "" && !validStatus(r.SetStatus) {
			return fmt.Errorf("reguła %q: nieznany status %q", r.Name, r.SetStatus)
		}
		if r.Action != "" {
			if _, ok := validActions[r.Action]; !ok {
				return fmt.Errorf("reguła %q: nieznana akcja %q", r.Name, r.Action)
			}
		}
		if r.IPMatch != "" && strings.Contains(r.IPMatch, "/") {
			if _, _, err := net.ParseCIDR(r.IPMatch); err != nil {
				return fmt.Errorf("reguła %q: niepoprawny CIDR %q", r.Name, r.IPMatch)
			}
		}
		if r.ID == "" {
			r.ID = "r" + strconv.FormatInt(time.Now().UnixNano(), 36) + strconv.Itoa(i)
		}
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	b, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	tmp := rs.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, rs.path); err != nil {
		return err
	}
	rs.rules = rules
	return nil
}

// match returns the first enabled rule whose conditions all hold for the
// case, or nil.
func (rs *ruleStore) match(c *Case) *Rule {
	for _, r := range rs.list() {
		if r.Enabled && ruleMatches(r, c) {
			return r
		}
	}
	return nil
}

func ruleMatches(r *Rule, c *Case) bool {
	if len(r.EventTypes) > 0 && !contains(r.EventTypes, c.EventType) {
		return false
	}
	if len(r.Ports) > 0 && !containsInt(r.Ports, casePort(c)) {
		return false
	}
	if r.IPMatch != "" && !ipMatches(r.IPMatch, c.Source) {
		return false
	}
	if r.SensorID != "" && r.SensorID != c.SensorID {
		return false
	}
	if len(r.Reasons) > 0 && !reasonMatches(r.Reasons, c.Reason) {
		return false
	}
	if r.MinScore != nil && c.Score < *r.MinScore {
		return false
	}
	if r.Unresolved != nil && c.Unresolved != *r.Unresolved {
		return false
	}
	return true
}

// casePort parses the destination port out of the derived target ("tcp:22").
func casePort(c *Case) int {
	parts := strings.Split(c.Target, ":")
	if len(parts) < 2 {
		return 0
	}
	p, _ := strconv.Atoi(parts[len(parts)-1])
	return p
}

func ipMatches(pattern, ip string) bool {
	if strings.Contains(pattern, "/") {
		_, ipnet, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		return ipnet.Contains(net.ParseIP(ip))
	}
	return strings.Contains(ip, pattern)
}

// reasonMatches accepts a rule when any listed fragment appears in the
// case's escalation reason — gate reasons like
// "fail_open_missing_or_invalid_signal:kev" carry a parameter, so exact
// equality would never catch the whole family.
func reasonMatches(patterns []string, reason string) bool {
	for _, p := range patterns {
		if p != "" && strings.Contains(reason, p) {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// applyRules runs the deterministic engine on one case. Everything the rule
// does is recorded through the same audited mutation as human and AI
// operator actions, under the actor "silnik reguł · <nazwa>".
func (s *server) applyRules(c *Case) bool {
	r := s.rules.match(c)
	if r == nil {
		return false
	}
	who := "silnik reguł · " + r.Name
	err := s.store.mutate(c.EventID, func(c *Case) (HistoryEntry, error) {
		var did []string
		if r.SetStatus != "" && r.SetStatus != c.Status {
			did = append(did, "status: "+labelStatus(c.Status)+" → "+labelStatus(r.SetStatus))
			c.Status = r.SetStatus
		}
		if r.Assign != "" && r.Assign != c.Assignee {
			c.Assignee = r.Assign
			did = append(did, "przypisano do "+r.Assign)
		}
		note := strings.TrimSpace(r.Note)
		if note != "" {
			c.Notes = append(c.Notes, Note{At: time.Now(), Actor: who, Text: note})
		}
		switch r.Action {
		case "":
		case "isolate":
			// Hard rules may only arm isolation; a human always confirms.
			c.PendingAction = "isolate"
			did = append(did, "reguła uzbroiła odcięcie hosta — oczekuje na potwierdzenie człowieka")
		default:
			label := validActions[r.Action]
			c.Actions = append(c.Actions, ActionRecord{At: time.Now(), Action: r.Action, Actor: who, Executed: true})
			did = append(did, label+operatorDemoSuffix(s))
		}
		text := "Reguła „" + r.Name + "” dopasowana"
		if len(did) > 0 {
			text += " — " + strings.Join(did, "; ")
		}
		return HistoryEntry{At: time.Now(), Kind: "rule", Actor: who, Text: text}, nil
	})
	if err != nil {
		s.feed.Append("rule", c.SensorID, "Silnik reguł nie mógł zapisać decyzji: "+err.Error(), nil)
		return false
	}
	return true
}

// applyRulesToOpen applies the engine to every open case (used when rule
// mode is switched on or the operator asks to re-run the rules).
func (s *server) applyRulesToOpen(limit int) (triaged, scanned int) {
	for _, c := range s.store.ListCases() {
		if scanned >= limit {
			break
		}
		if c.Status == StatusClosed || c.Status == StatusFalseAlarm || c.Status == StatusConfirmed {
			continue
		}
		scanned++
		if s.applyRules(c) {
			triaged++
		}
	}
	return triaged, scanned
}
