// Package sigimport translates third-party technology signatures into the
// YAML format understood by internal/fingerprint. It supports Wappalyzer
// (webappanalyzer) JSON files and nuclei detection templates, without
// adopting either engine: the output is plain signature YAML that the
// scanner loads with -signatures.
//
// Evidence that needs a JavaScript runtime, the DOM or DNS (Wappalyzer
// js/dom/dns/xhr, nuclei DSL helpers other than the favicon mmh3 hash) has
// no counterpart in our passive model and is skipped with a counter in the
// report instead of being approximated.
package sigimport

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Inner-Savages/silence-on-the-wire/internal/fingerprint"
)

// Stats counts what an import run did with the source signatures.
type Stats struct {
	Considered       int `yaml:"considered"`
	Imported         int `yaml:"imported"`
	SkipNoEvidence   int `yaml:"skipped_no_mappable_evidence"`
	SkipDuplicate    int `yaml:"skipped_duplicate"`
	MatchersSkipped  int `yaml:"matchers_skipped"`
	MatchersImported int `yaml:"matchers_imported"`
}

func (s Stats) String() string {
	return fmt.Sprintf("considered %d, imported %d, skipped (no mappable evidence %d, duplicate %d); matchers: imported %d, skipped %d",
		s.Considered, s.Imported, s.SkipNoEvidence, s.SkipDuplicate, s.MatchersImported, s.MatchersSkipped)
}

// Options tune the conversion.
type Options struct {
	// MinConfidence is set on every imported signature (default 0.5).
	MinConfidence float64
	// MaxWeight caps imported matcher weights: third-party confidence 100
	// would otherwise make a single weak match decisive (default 0.95).
	MaxWeight float64
	// Reserved names already taken (e.g. the built-in signatures); a
	// colliding import is skipped as a duplicate. Matched case-insensitively.
	Reserved []string
}

func (o *Options) defaults() {
	if o.MinConfidence == 0 {
		o.MinConfidence = 0.5
	}
	if o.MaxWeight == 0 {
		o.MaxWeight = 0.95
	}
}

// Importer accumulates converted signatures and deduplicates by name.
type Importer struct {
	opts Options
	seen map[string]bool
	sigs []fingerprint.Signature
}

// NewImporter creates an Importer.
func NewImporter(opts Options) *Importer {
	opts.defaults()
	seen := map[string]bool{}
	for _, n := range opts.Reserved {
		seen[strings.ToLower(n)] = true
	}
	return &Importer{opts: opts, seen: seen}
}

// Signatures returns the converted signatures sorted by name.
func (im *Importer) Signatures() []fingerprint.Signature {
	out := make([]fingerprint.Signature, len(im.sigs))
	copy(out, im.sigs)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// add validates and records a converted signature. It reports false when
// the signature is a duplicate or has no usable matcher left.
func (im *Importer) add(sig fingerprint.Signature, st *Stats) bool {
	st.Considered++
	if sig.Name == "" || im.seen[strings.ToLower(sig.Name)] {
		st.SkipDuplicate++
		return false
	}
	kept := sig.Match[:0]
	for _, m := range sig.Match {
		if m.Weight <= 0 {
			m.Weight = 0.6
		}
		if m.Weight > im.opts.MaxWeight {
			m.Weight = im.opts.MaxWeight
		}
		if !compiles(m.Value) || !compiles(m.Cookie) || !compiles(m.Title) || !compiles(m.Body) {
			// Go uses RE2; lookaheads and backreferences found in the wild
			// cannot be honoured, so the matcher is dropped, not guessed.
			st.MatchersSkipped++
			continue
		}
		kept = append(kept, m)
		st.MatchersImported++
	}
	if len(kept) == 0 {
		st.SkipNoEvidence++
		return false
	}
	sig.Match = kept
	if sig.MinConfidence == 0 {
		sig.MinConfidence = im.opts.MinConfidence
	}
	im.seen[strings.ToLower(sig.Name)] = true
	im.sigs = append(im.sigs, sig)
	st.Imported++
	return true
}

// compiles reports whether src is a valid pattern for the engine, which
// compiles everything case-insensitively.
func compiles(src string) bool {
	if src == "" {
		return true
	}
	_, err := regexp.Compile("(?i)" + src)
	return err == nil
}

// Marshal renders the signatures as one YAML document with a header
// comment describing provenance.
func Marshal(sigs []fingerprint.Signature, source string) ([]byte, error) {
	body, err := yaml.Marshal(sigs)
	if err != nil {
		return nil, err
	}
	header := fmt.Sprintf("# Imported from %s by sigimport.\n# Do not edit by hand: re-run the importer against newer sources instead.\n", source)
	return append([]byte(header), body...), nil
}

// BuiltinNames loads the built-in signature names so imports do not
// shadow them.
func BuiltinNames() ([]string, error) {
	e, err := fingerprint.NewEngine()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, s := range e.Signatures() {
		names = append(names, s.Name)
	}
	return names, nil
}

// weight converts a third-party 0-100 confidence to our (0,1] weight.
func weight(conf int) float64 {
	if conf <= 0 {
		conf = 100
	}
	if conf > 100 {
		conf = 100
	}
	return float64(conf) / 100
}

// slugify turns a display name into a lowercase tag.
func slugify(s string) string {
	var b strings.Builder
	lastDash := true // trims leading dashes
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case !lastDash:
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}
