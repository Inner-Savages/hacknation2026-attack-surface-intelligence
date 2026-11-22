package sigimport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Inner-Savages/silence-on-the-wire/internal/fingerprint"
)

// wappCategories maps Wappalyzer numeric category IDs to slugs (from
// categories.json of webappanalyzer).
var wappCategories = map[int]string{
	1: "cms", 2: "message-boards", 3: "database-managers", 4: "documentation",
	5: "widgets", 6: "ecommerce", 7: "photo-galleries", 8: "wikis",
	9: "hosting-panels", 10: "analytics", 11: "blogs", 12: "javascript-frameworks",
	13: "issue-trackers", 14: "video-players", 15: "comment-systems", 16: "security",
	17: "font-scripts", 18: "web-frameworks", 19: "miscellaneous", 20: "editors",
	21: "lms", 22: "web-servers", 23: "caching", 24: "rich-text-editors",
	25: "javascript-graphics", 26: "mobile-frameworks", 27: "programming-languages",
	28: "operating-systems", 29: "search-engines", 30: "webmail", 31: "cdn",
	32: "marketing-automation", 33: "web-server-extensions", 34: "databases",
	35: "maps", 36: "advertising", 37: "network-devices", 38: "media-servers",
	39: "webcams", 41: "payment-processors", 42: "tag-managers", 44: "ci",
	45: "control-systems", 46: "remote-access", 47: "development",
	48: "network-storage", 49: "feed-readers", 50: "dms", 51: "page-builders",
	52: "live-chat", 53: "crm", 54: "seo", 55: "accounting", 56: "cryptominers",
	57: "static-site-generator", 58: "user-onboarding", 59: "javascript-libraries",
	60: "containers", 62: "paas", 63: "iaas", 64: "reverse-proxies",
	65: "load-balancers", 66: "ui-frameworks", 67: "cookie-compliance",
	68: "accessibility", 69: "authentication", 70: "ssl-tls-certificate-authorities",
	71: "affiliate-programs", 72: "appointment-scheduling", 73: "surveys",
	74: "a-b-testing", 75: "email", 76: "personalisation", 77: "retargeting",
	78: "rum", 79: "geolocation", 80: "wordpress-themes", 81: "shopify-themes",
	82: "drupal-themes", 83: "browser-fingerprinting", 84: "loyalty-rewards",
	85: "feature-management", 86: "segmentation", 87: "wordpress-plugins",
	88: "hosting", 89: "translation", 90: "reviews", 91: "buy-now-pay-later",
	92: "performance", 93: "reservations-delivery", 94: "referral-marketing",
	95: "digital-asset-management", 96: "content-curation", 97: "customer-data-platform",
	98: "cart-abandonment", 99: "shipping-carriers", 100: "shopify-apps",
	101: "recruitment-staffing", 102: "returns", 103: "livestreaming",
	104: "ticket-booking", 105: "augmented-reality", 106: "cross-border-ecommerce",
	107: "fulfilment", 108: "ecommerce-frontends", 109: "domain-parking",
	110: "form-builders", 111: "fundraising-donations", 112: "artificial-intelligence",
}

// wappTech is one technology object from a webappanalyzer JSON file. Only
// keys with evidence we can express are mapped; js/dom/dns/xhr need a
// browser or resolver and are counted as skipped.
type wappTech struct {
	Cats      []int             `json:"cats"`
	Headers   map[string]string `json:"headers"`
	Cookies   map[string]string `json:"cookies"`
	HTML      wappPatterns      `json:"html"`
	Meta      map[string]string `json:"meta"`
	ScriptSrc wappPatterns      `json:"scriptSrc"`
	Scripts   wappPatterns      `json:"scripts"`
	URL       wappPatterns      `json:"url"`
	JS        json.RawMessage   `json:"js"`
	DOM       json.RawMessage   `json:"dom"`
	DNS       json.RawMessage   `json:"dns"`
	XHR       wappPatterns      `json:"xhr"`
}

// wappPatterns accepts the Wappalyzer "string or list of strings" shape.
type wappPatterns []string

func (p *wappPatterns) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*p = []string{s}
		return nil
	}
	var list []string
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	*p = list
	return nil
}

// wappAttrs are the "\;key:value" attributes Wappalyzer appends to a
// pattern, e.g. "WordPress ([\d.]+)\;version:\1\;confidence:90".
type wappAttrs struct {
	pattern    string
	version    int // regex group carrying the version, 0 = none
	confidence int // 0-100, 0 = unset
}

var versionRef = regexp.MustCompile(`^\\(\d)`)

func parseWappPattern(raw string) wappAttrs {
	parts := strings.Split(raw, `\;`)
	a := wappAttrs{pattern: parts[0]}
	for _, attr := range parts[1:] {
		kv := strings.SplitN(attr, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch key {
		case "version":
			if m := versionRef.FindStringSubmatch(val); m != nil {
				a.version, _ = strconv.Atoi(m[1])
			}
		case "confidence":
			a.confidence, _ = strconv.Atoi(val)
		}
	}
	return a
}

// ImportWappalyzer reads every *.json file in dir (one letter per file in
// a webappanalyzer checkout) and converts the technologies.
func (im *Importer) ImportWappalyzer(dir string) (Stats, error) {
	var st Stats
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return st, err
	}
	if len(files) == 0 {
		return st, fmt.Errorf("no *.json files in %s (expected webappanalyzer src/technologies)", dir)
	}
	sort.Strings(files)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return st, err
		}
		var techs map[string]wappTech
		if err := json.Unmarshal(data, &techs); err != nil {
			return st, fmt.Errorf("%s: %w", f, err)
		}
		names := make([]string, 0, len(techs))
		for name := range techs {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			sig, skipped := im.convertWapp(name, techs[name])
			st.MatchersSkipped += skipped
			im.add(sig, &st)
		}
	}
	return st, nil
}

func (im *Importer) convertWapp(name string, t wappTech) (fingerprint.Signature, int) {
	skipped := 0
	sig := fingerprint.Signature{Name: name, Category: "app"}
	if len(t.Cats) > 0 {
		if cat, ok := wappCategories[t.Cats[0]]; ok {
			sig.Category = cat
		}
	}

	// Headers: presence or a regex on the value.
	headerNames := make([]string, 0, len(t.Headers))
	for h := range t.Headers {
		headerNames = append(headerNames, h)
	}
	sort.Strings(headerNames)
	for _, h := range headerNames {
		a := parseWappPattern(t.Headers[h])
		m := fingerprint.Matcher{
			Header:  strings.ToLower(h),
			Value:   a.pattern,
			Version: a.version,
			Weight:  weight(a.confidence),
		}
		sig.Match = append(sig.Match, m)
	}

	// Cookies: our engine matches on cookie names, so the name regex is
	// carried 1:1; a value pattern has no counterpart and drops the weight
	// one notch rather than being invented.
	cookieNames := make([]string, 0, len(t.Cookies))
	for c := range t.Cookies {
		cookieNames = append(cookieNames, c)
	}
	sort.Strings(cookieNames)
	for _, c := range cookieNames {
		a := parseWappPattern(t.Cookies[c])
		w := weight(a.confidence)
		if a.pattern != "" {
			w *= 0.8
		}
		sig.Match = append(sig.Match, fingerprint.Matcher{Cookie: c, Weight: w})
	}

	// HTML source.
	for _, raw := range t.HTML {
		a := parseWappPattern(raw)
		if a.pattern == "" {
			continue
		}
		sig.Match = append(sig.Match, fingerprint.Matcher{Body: a.pattern, Version: a.version, Weight: weight(a.confidence)})
	}

	// <meta name=... content="...">.
	metaNames := make([]string, 0, len(t.Meta))
	for mn := range t.Meta {
		metaNames = append(metaNames, mn)
	}
	sort.Strings(metaNames)
	for _, mn := range metaNames {
		a := parseWappPattern(t.Meta[mn])
		quoted := regexp.QuoteMeta(mn)
		var pattern string
		version := a.version
		if a.pattern == "" {
			pattern = `<meta[^>]*name=["']?` + quoted
		} else if a.version > 0 {
			pattern = `<meta[^>]*name=["']?` + quoted + `["']?[^>]*content=["'](?:` + a.pattern + `)`
		} else {
			pattern = `<meta[^>]*name=["']?` + quoted + `["']?[^>]*content=["'](` + a.pattern + `)`
			version = 1
		}
		sig.Match = append(sig.Match, fingerprint.Matcher{Body: pattern, Version: version, Weight: weight(a.confidence)})
	}

	// External script URLs.
	for _, raw := range t.ScriptSrc {
		a := parseWappPattern(raw)
		if a.pattern == "" {
			continue
		}
		sig.Match = append(sig.Match, fingerprint.Matcher{
			Body:    `<script[^>]+src=["'][^"']*` + a.pattern,
			Version: a.version,
			Weight:  weight(a.confidence),
		})
	}

	// Inline script content.
	for _, raw := range t.Scripts {
		a := parseWappPattern(raw)
		if a.pattern == "" {
			continue
		}
		sig.Match = append(sig.Match, fingerprint.Matcher{Body: a.pattern, Version: a.version, Weight: weight(a.confidence)})
	}

	// Evidence we cannot express passively: the page URL (we only fetch
	// fixed paths), JS globals, DOM selectors, DNS records and XHR calls.
	for _, n := range []int{len(t.URL), len(t.XHR)} {
		skipped += n
	}
	for _, raw := range []json.RawMessage{t.JS, t.DOM, t.DNS} {
		if len(raw) > 0 && string(raw) != "null" && string(raw) != "{}" {
			skipped++
		}
	}
	return sig, skipped
}
