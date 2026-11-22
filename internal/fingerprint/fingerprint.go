// Package fingerprint recognizes technologies on scanned services using
// signatures: weighted pieces of evidence (a header, a cookie name, a
// title or body pattern, a favicon hash, the nmap product, or a page at a
// fixed path fetched with GET). Signatures detect presence of components;
// they never try logins or exploits.
//
// Confidence combines matched evidence as a noisy-OR: 1 - Π(1 - weight).
package fingerprint

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

//go:embed signatures/*.yaml
var builtin embed.FS

// Signature describes one technology.
type Signature struct {
	Name          string    `yaml:"name"`
	Category      string    `yaml:"category,omitempty"`
	Tags          []string  `yaml:"tags,omitempty"`
	MinConfidence float64   `yaml:"min_confidence,omitempty"` // default 0.5
	Match         []Matcher `yaml:"match"`
}

// Matcher is one piece of evidence. Exactly one subject is set: header,
// cookie, title, body, favicon, nmap_product, nmap_service or path. With
// path, the other fields (status, title, body, header) are conditions on
// the fetched page.
type Matcher struct {
	Header      string  `yaml:"header,omitempty"`  // header name (lower-case); Value is an optional regex on its value
	Value       string  `yaml:"value,omitempty"`   // regex
	Cookie      string  `yaml:"cookie,omitempty"`  // regex on cookie names
	Title       string  `yaml:"title,omitempty"`   // regex
	Body        string  `yaml:"body,omitempty"`    // regex
	Favicon     *int32  `yaml:"favicon,omitempty"` // Shodan mmh3 hash
	NmapProduct string  `yaml:"nmap_product,omitempty"`
	NmapService string  `yaml:"nmap_service,omitempty"`
	Path        string  `yaml:"path,omitempty"`   // e.g. /wp-login.php
	Status      int     `yaml:"status,omitempty"` // for path; default 200
	Version     int     `yaml:"version,omitempty"`
	NmapVersion bool    `yaml:"nmap_version,omitempty"` // take the version nmap reported
	Weight      float64 `yaml:"weight,omitempty"`       // default 0.6

	value, cookie, title, body, product, service *regexp.Regexp
}

// Engine holds compiled signatures.
type Engine struct {
	sigs []Signature
}

// Fetcher fetches a page at a fixed path of a web service.
type Fetcher interface {
	FetchPath(ctx context.Context, h *result.Host, s *result.Service, path string) (*result.Page, error)
}

// NewEngine loads the built-in signatures plus any extra files.
func NewEngine(extra ...string) (*Engine, error) {
	e := &Engine{}
	files, _ := fs.Glob(builtin, "signatures/*.yaml")
	sort.Strings(files)
	for _, f := range files {
		data, _ := builtin.ReadFile(f)
		if err := e.load(f, data); err != nil {
			return nil, err
		}
	}
	for _, f := range extra {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if err := e.load(f, data); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// Signatures returns the loaded signatures.
func (e *Engine) Signatures() []Signature { return e.sigs }

func (e *Engine) load(name string, data []byte) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // typos in signature files are errors, not silent no-ops
	var sigs []Signature
	if err := dec.Decode(&sigs); err != nil && err != io.EOF {
		return fmt.Errorf("%s: %w", name, err)
	}
	for i := range sigs {
		if err := sigs[i].compile(); err != nil {
			return fmt.Errorf("%s: signature %q: %w", name, sigs[i].Name, err)
		}
	}
	e.sigs = append(e.sigs, sigs...)
	return nil
}

func (s *Signature) compile() error {
	if s.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(s.Match) == 0 {
		return fmt.Errorf("at least one match is required")
	}
	if s.MinConfidence == 0 {
		s.MinConfidence = 0.5
	}
	for i := range s.Match {
		m := &s.Match[i]
		if m.Weight == 0 {
			m.Weight = 0.6
		}
		if m.Weight < 0 || m.Weight > 1 {
			return fmt.Errorf("match %d: weight must be in (0, 1]", i+1)
		}
		// With a path or a header, title/body are extra conditions on that
		// page; on their own, each of them is a subject.
		subjects := count(m.Header != "", m.Cookie != "", m.Favicon != nil, m.NmapProduct != "", m.NmapService != "", m.Path != "")
		if m.Path == "" && m.Header == "" {
			subjects += count(m.Title != "", m.Body != "")
		}
		if subjects != 1 {
			return fmt.Errorf("match %d: needs exactly one of header, cookie, title, body, favicon, nmap_product, nmap_service, path", i+1)
		}
		if m.Path != "" && !strings.HasPrefix(m.Path, "/") {
			return fmt.Errorf("match %d: path must start with /", i+1)
		}
		m.Header = strings.ToLower(m.Header)
		for _, c := range []struct {
			src string
			dst **regexp.Regexp
		}{{m.Value, &m.value}, {m.Cookie, &m.cookie}, {m.Title, &m.title}, {m.Body, &m.body}, {m.NmapProduct, &m.product}, {m.NmapService, &m.service}} {
			if c.src == "" {
				continue
			}
			re, err := regexp.Compile("(?i)" + c.src)
			if err != nil {
				return fmt.Errorf("match %d: %w", i+1, err)
			}
			*c.dst = re
		}
	}
	return nil
}

func count(flags ...bool) int {
	n := 0
	for _, f := range flags {
		if f {
			n++
		}
	}
	return n
}

// Paths lists the distinct paths that signatures want fetched.
func (e *Engine) Paths() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range e.sigs {
		for _, m := range s.Match {
			if m.Path != "" && !seen[m.Path] {
				seen[m.Path] = true
				out = append(out, m.Path)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Identify returns the technologies recognized on one service. pages maps
// path -> fetched page (missing paths simply don't match).
func (e *Engine) Identify(svc *result.Service, pages map[string]*result.Page) []result.Tech {
	var out []result.Tech
	for _, s := range e.sigs {
		miss := 1.0
		var evidence []string
		version, versionWeight := "", 0.0
		for _, m := range s.Match {
			ok, ev, ver := m.match(svc, pages)
			if !ok {
				continue
			}
			miss *= 1 - m.Weight
			evidence = append(evidence, ev)
			if ver != "" && m.Weight > versionWeight {
				version, versionWeight = ver, m.Weight
			}
		}
		conf := 1 - miss
		if len(evidence) == 0 || conf+1e-9 < s.MinConfidence {
			continue
		}
		out = append(out, result.Tech{
			Name: s.Name, Category: s.Category, Version: version, Tags: s.Tags,
			Confidence: float64(int(conf*100+0.5)) / 100, Evidence: evidence,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Confidence > out[j].Confidence })
	return out
}

func (m *Matcher) match(svc *result.Service, pages map[string]*result.Page) (bool, string, string) {
	switch {
	case m.product != nil:
		if sub := m.product.FindStringSubmatch(svc.Product); sub != nil {
			return true, "nmap product " + svc.Product, m.versionOf(sub, svc.Version)
		}
	case m.service != nil:
		if m.service.MatchString(svc.Name) {
			return true, "nmap service " + svc.Name, m.versionOf(nil, svc.Version)
		}
	case m.Path != "":
		p := pages[m.Path]
		if p == nil {
			return false, "", ""
		}
		want := m.Status
		if want == 0 {
			want = 200
		}
		if p.Status != want {
			return false, "", ""
		}
		ok, ver := m.pageConditions(p.Headers, p.Title, p.Body)
		if ok {
			return true, fmt.Sprintf("path %s %d", m.Path, p.Status), ver
		}
	default:
		h := svc.HTTP
		if h == nil || h.Error != "" {
			return false, "", ""
		}
		switch {
		case m.cookie != nil:
			for _, c := range h.Cookies {
				if m.cookie.MatchString(c.Name) {
					return true, "cookie " + c.Name, ""
				}
			}
		case m.Favicon != nil:
			if h.Favicon != nil && h.Favicon.Hash == *m.Favicon {
				return true, fmt.Sprintf("favicon %d", h.Favicon.Hash), ""
			}
		default:
			if ok, ver := m.pageConditions(h.Headers, h.Title, h.Body); ok {
				return true, m.describe(), ver
			}
		}
	}
	return false, "", ""
}

// pageConditions checks header/title/body conditions against a page.
func (m *Matcher) pageConditions(headers map[string][]string, title string, body []byte) (bool, string) {
	ver := ""
	if m.Header != "" {
		vals, ok := headers[m.Header]
		if !ok {
			return false, ""
		}
		if m.value != nil {
			found := false
			for _, v := range vals {
				if sub := m.value.FindStringSubmatch(v); sub != nil {
					found, ver = true, m.versionOf(sub, "")
					break
				}
			}
			if !found {
				return false, ""
			}
		}
	}
	if m.title != nil {
		sub := m.title.FindStringSubmatch(title)
		if sub == nil {
			return false, ""
		}
		if v := m.versionOf(sub, ""); v != "" {
			ver = v
		}
	}
	if m.body != nil {
		sub := m.body.FindSubmatch(body)
		if sub == nil {
			return false, ""
		}
		strs := make([]string, len(sub))
		for i, b := range sub {
			strs[i] = string(b)
		}
		if v := m.versionOf(strs, ""); v != "" {
			ver = v
		}
	}
	return true, ver
}

func (m *Matcher) versionOf(sub []string, nmapVersion string) string {
	if m.NmapVersion {
		return nmapVersion
	}
	if m.Version > 0 && m.Version < len(sub) {
		return sub[m.Version]
	}
	return ""
}

func (m *Matcher) describe() string {
	switch {
	case m.Header != "" && m.Value != "":
		return "header " + m.Header + " ~ " + m.Value
	case m.Header != "":
		return "header " + m.Header
	case m.Title != "":
		return "title ~ " + m.Title
	default:
		return "body ~ " + m.Body
	}
}

// Run fingerprints every open service in the scan, fetching signature paths
// from web services through f (nil disables path checks).
func (e *Engine) Run(ctx context.Context, s *result.Scan, f Fetcher, parallel int) {
	if parallel <= 0 {
		parallel = 8
	}
	paths := e.Paths()
	var wg sync.WaitGroup
	sem := make(chan struct{}, parallel)
	for i := range s.Hosts {
		h := &s.Hosts[i]
		for j := range h.Services {
			svc := &h.Services[j]
			if svc.State != "open" {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				pages := map[string]*result.Page{}
				if f != nil && svc.HTTP != nil && svc.HTTP.Error == "" && len(paths) > 0 {
					// Apps that answer every URL with the same page (front
					// controllers, SPAs) would make every path check pass:
					// fetch a path that cannot exist and ignore look-alikes.
					baseline, _ := f.FetchPath(ctx, h, svc, notFoundPath())
					for _, p := range paths {
						if ctx.Err() != nil {
							return
						}
						if page, err := f.FetchPath(ctx, h, svc, p); err == nil && !SoftNotFound(baseline, page) {
							pages[p] = page
						}
					}
				}
				svc.Tech = e.Identify(svc, pages)
			}()
		}
	}
	wg.Wait()
}

// notFoundPath returns a random path no real application serves.
func notFoundPath() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "/sotw-not-found-" + hex.EncodeToString(b)
}

// SoftNotFound reports whether page is just the catch-all answer seen for a
// path that does not exist: a 200 with the same title and a length within
// 20% (pages often embed the requested URL, so bodies are not identical).
func SoftNotFound(baseline, page *result.Page) bool {
	if baseline == nil || page == nil || baseline.Status != 200 || page.Status != 200 {
		return false
	}
	if baseline.Title != page.Title {
		return false
	}
	a, b := float64(len(baseline.Body)), float64(len(page.Body))
	return math.Abs(a-b) <= 0.2*math.Max(a, b)
}
