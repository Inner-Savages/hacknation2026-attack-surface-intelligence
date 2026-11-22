package sigimport

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Inner-Savages/silence-on-the-wire/internal/fingerprint"
)

// nucleiTemplate is the subset of a nuclei detection template we can
// translate. Both the modern "http" and the legacy "requests" blocks are
// accepted.
type nucleiTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name string `yaml:"name"`
		Tags string `yaml:"tags"`
	} `yaml:"info"`
	HTTP     []nucleiRequest `yaml:"http"`
	Requests []nucleiRequest `yaml:"requests"`
}

type nucleiRequest struct {
	Method            string            `yaml:"method"`
	Path              []string          `yaml:"path"`
	MatchersCondition string            `yaml:"matchers-condition"`
	Matchers          []nucleiMatcher   `yaml:"matchers"`
	Extractors        []nucleiExtractor `yaml:"extractors"`
}

type nucleiMatcher struct {
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part"`
	Name      string   `yaml:"name"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	DSL       []string `yaml:"dsl"`
	Status    []int    `yaml:"status"`
	Condition string   `yaml:"condition"`
}

type nucleiExtractor struct {
	Type  string   `yaml:"type"`
	Part  string   `yaml:"part"`
	Group int      `yaml:"group"`
	Regex []string `yaml:"regex"`
}

// faviconHashRe finds the mmh3 favicon comparison inside a nuclei DSL
// expression, in either operand order, with optional quoting and sign.
var faviconHashRe = regexp.MustCompile(`["']?(-?\d+)["']?\s*==\s*mmh3\(base64_py\(body\)\)|mmh3\(base64_py\(body\)\)\s*==\s*["']?(-?\d+)["']?`)

// dslBodyRegexRe matches the regex("...", body) form used by the bulk
// WordPress plugin/theme detection templates.
var dslBodyRegexRe = regexp.MustCompile(`^regex\("((?:[^"\\]|\\.)*)",\s*body\)$`)

// ImportNuclei walks dir recursively for *.yaml nuclei templates and
// converts the technology detections.
func (im *Importer) ImportNuclei(dir string) (Stats, error) {
	var st Stats
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return st, err
	}
	if len(files) == 0 {
		return st, fmt.Errorf("no *.yaml files under %s (expected a nuclei-templates checkout)", dir)
	}
	sort.Strings(files)
	for _, f := range files {
		if err := im.importNucleiFile(f, &st); err != nil {
			return st, err
		}
	}
	return st, nil
}

func (im *Importer) importNucleiFile(path string, st *Stats) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	for {
		var tpl nucleiTemplate
		err := dec.Decode(&tpl)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		reqs := tpl.HTTP
		if len(reqs) == 0 {
			reqs = tpl.Requests
		}
		if tpl.Info.Name == "" || len(reqs) == 0 {
			continue // not an http technology detection
		}
		sig, extras, skipped := convertNuclei(tpl, reqs)
		st.MatchersSkipped += skipped
		im.add(sig, st)
		for i := range extras {
			im.add(extras[i], st)
		}
	}
}

func convertNuclei(tpl nucleiTemplate, reqs []nucleiRequest) (fingerprint.Signature, []fingerprint.Signature, int) {
	skipped := 0
	var extras []fingerprint.Signature
	sig := fingerprint.Signature{
		Name:     nucleiName(tpl.Info.Name),
		Category: "app",
	}
	for _, t := range strings.Split(tpl.Info.Tags, ",") {
		if t = strings.TrimSpace(t); t != "" {
			sig.Tags = append(sig.Tags, t)
		}
	}

	for _, req := range reqs {
		// Matchers of one request are built aside first: when the request
		// demands AND between matchers and some of them cannot be
		// translated, the kept ones are necessary-but-not-sufficient
		// evidence and importing them would cause false positives.
		var reqMatch []fingerprint.Matcher
		reqSkipped := 0

		path, hasPath := nucleiPath(req.Path)
		pathIdx := -1
		if hasPath && path != "/" {
			reqMatch = append(reqMatch, fingerprint.Matcher{Path: path, Weight: 0.5})
			pathIdx = len(reqMatch) - 1
		}

		needConjunction := false
		for _, m := range req.Matchers {
			switch m.Type {
			case "status":
				// A status is only evidence together with a fetched path.
				if pathIdx >= 0 && len(m.Status) > 0 {
					reqMatch[pathIdx].Status = m.Status[0]
				}
			case "word":
				switch m.Part {
				case "", "body":
					if len(m.Words) == 0 {
						continue
					}
					if strings.EqualFold(m.Condition, "and") && len(m.Words) > 1 {
						// Our noisy-OR cannot express "all of these"; emit
						// separate matchers and require at least two via
						// min_confidence (0.5+0.5 -> 0.75).
						needConjunction = true
						for _, w := range m.Words {
							reqMatch = append(reqMatch, fingerprint.Matcher{Body: regexp.QuoteMeta(w), Weight: 0.5})
						}
					} else {
						quoted := make([]string, len(m.Words))
						for i, w := range m.Words {
							quoted[i] = regexp.QuoteMeta(w)
						}
						reqMatch = append(reqMatch, fingerprint.Matcher{Body: strings.Join(quoted, "|"), Weight: 0.7})
					}
				default:
					reqSkipped++ // header/raw parts have no 1:1 subject here
				}
			case "regex":
				if m.Part != "" && m.Part != "body" {
					reqSkipped++
					continue
				}
				for _, r := range m.Regex {
					reqMatch = append(reqMatch, fingerprint.Matcher{Body: r, Weight: 0.7})
				}
			case "dsl":
				// A named dsl matcher made of regex("...", body)
				// expressions is how the bulk WordPress plugin/theme
				// templates encode one detection per entry: each becomes
				// its own signature instead of being dropped.
				if m.Name != "" {
					var pats []string
					for _, expr := range m.DSL {
						if dm := dslBodyRegexRe.FindStringSubmatch(expr); dm != nil {
							pats = append(pats, strings.ReplaceAll(dm[1], `\"`, `"`))
						}
					}
					if len(pats) > 0 {
						extras = append(extras, fingerprint.Signature{
							Name:     extraName(tpl.ID, m.Name),
							Category: "app",
							Tags:     sig.Tags,
							Match:    []fingerprint.Matcher{{Body: strings.Join(pats, "|"), Weight: 0.8}},
						})
						continue
					}
				}
				for _, expr := range m.DSL {
					if h, ok := faviconHash(expr); ok {
						reqMatch = append(reqMatch, fingerprint.Matcher{Favicon: &h, Weight: 0.9})
					} else if !statusCodeDSL(expr) {
						reqSkipped++ // other DSL helpers need the nuclei runtime
					}
				}
			default:
				reqSkipped++
			}
		}

		for _, ex := range req.Extractors {
			if ex.Type != "regex" || (ex.Part != "" && ex.Part != "body") || ex.Group <= 0 {
				skipped++
				continue
			}
			for _, r := range ex.Regex {
				attached := false
				for i := range reqMatch {
					if reqMatch[i].Body == r && reqMatch[i].Version == 0 {
						reqMatch[i].Version = ex.Group
						attached = true
						break
					}
				}
				if !attached {
					// Version-only evidence, like the hand-written files.
					reqMatch = append(reqMatch, fingerprint.Matcher{Body: r, Version: ex.Group, Weight: 0.2})
				}
			}
		}

		if strings.EqualFold(req.MatchersCondition, "and") && reqSkipped > 0 {
			// The untranslated matchers were load-bearing.
			skipped += reqSkipped + len(reqMatch)
			continue
		}
		skipped += reqSkipped
		sig.Match = append(sig.Match, reqMatch...)

		if needConjunction && sig.MinConfidence < 0.7 {
			sig.MinConfidence = 0.7
		}
	}
	return sig, extras, skipped
}

// statusCodeDSL reports whether the expression only asserts the response
// status, which the engine already checks on fetched pages.
func statusCodeDSL(expr string) bool {
	e := strings.ReplaceAll(expr, " ", "")
	return strings.HasPrefix(e, "status_code==") && !strings.Contains(e, "&&") && !strings.Contains(e, "||")
}

// extraName derives a signature name for a named dsl sub-matcher, e.g.
// template "wordpress-plugin-detect" + matcher "contact-form-7" becomes
// "Wordpress Plugin Contact Form 7".
func extraName(templateID, matcherName string) string {
	base := strings.TrimSuffix(strings.TrimSuffix(templateID, "-detection"), "-detect")
	words := strings.FieldsFunc(base+"-"+matcherName, func(r rune) bool { return r == '-' || r == '_' })
	for i, w := range words {
		if w != "" {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// nucleiName strips the boilerplate suffix from template titles.
func nucleiName(name string) string {
	name = strings.TrimSpace(name)
	for _, suffix := range []string{" Detection", " Detect"} {
		if strings.HasSuffix(name, suffix) {
			name = strings.TrimSpace(strings.TrimSuffix(name, suffix))
		}
	}
	return strings.TrimSpace(strings.TrimSuffix(name, "-"))
}

// nucleiPath resolves the first static request path; only {{BaseURL}} is
// substituted, anything more dynamic is dropped.
func nucleiPath(paths []string) (string, bool) {
	if len(paths) == 0 {
		return "", false
	}
	p := strings.ReplaceAll(paths[0], "{{BaseURL}}", "")
	if strings.Contains(p, "{{") {
		return "", false
	}
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "", false
	}
	return p, true
}

// faviconHash extracts the mmh3 favicon hash from a DSL expression.
func faviconHash(expr string) (int32, bool) {
	m := faviconHashRe.FindStringSubmatch(expr)
	if m == nil {
		return 0, false
	}
	raw := m[1]
	if raw == "" {
		raw = m[2]
	}
	n, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return 0, false
	}
	return int32(n), true
}
