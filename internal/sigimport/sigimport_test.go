package sigimport

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Inner-Savages/silence-on-the-wire/internal/fingerprint"
)

const wappFixture = `{
  "W3 Total Cache": {
    "cats": [23],
    "headers": {
      "X-Powered-By": "W3 Total Cache(?:/([\\d.]+))?\\;version:\\1"
    },
    "html": "<!-- Performance optimized by W3 Total Cache",
    "icon": "w3tc.png",
    "website": "https://www.boldgrid.com/w3-total-cache/"
  },
  "jQuery": {
    "cats": [59],
    "scriptSrc": "jquery.*\\.js\\;confidence:80",
    "js": { "jQuery": "" }
  },
  "Presence Cookie": {
    "cats": [999],
    "cookies": { "session_id": "" },
    "url": "^/shop"
  },
  "JS Only Widget": {
    "cats": [5],
    "js": { "someGlobal": "" },
    "dom": ".widget"
  }
}`

const nucleiFixture = `id: gitea-detect
info:
  name: Gitea Detect
  author: example
  severity: info
  tags: tech,gitea
http:
  - method: GET
    path:
      - "{{BaseURL}}/user/login"
    matchers:
      - type: word
        part: body
        words:
          - "Powered by Gitea"
      - type: status
        status:
          - 200
    extractors:
      - type: regex
        part: body
        group: 3
        regex:
          - "Powered by Gitea(\\s*)Version:(\\s*)([\\d.]+)"
`

const nucleiFaviconFixture = `id: confluence-detect
info:
  name: Atlassian Confluence Detection
  tags: tech,confluence
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code==200 && (\"-235150127\" == mmh3(base64_py(body)))"
      - type: word
        part: body
        words:
          - "Log in to Confluence"
`

func writeFixture(t *testing.T, dir, name, content string) string {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return full
}

func findSig(sigs []fingerprint.Signature, name string) *fingerprint.Signature {
	for i := range sigs {
		if sigs[i].Name == name {
			return &sigs[i]
		}
	}
	return nil
}

func TestImportWappalyzer(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "w.json", wappFixture)

	imp := NewImporter(Options{})
	st, err := imp.ImportWappalyzer(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Considered != 4 {
		t.Fatalf("considered = %d, want 4", st.Considered)
	}
	// JS Only Widget has no passive evidence and must be dropped.
	if st.Imported != 3 || st.SkipNoEvidence != 1 {
		t.Fatalf("imported = %d, no-evidence = %d, want 3 and 1", st.Imported, st.SkipNoEvidence)
	}
	if st.MatchersSkipped == 0 {
		t.Fatal("js/dom/url evidence should be counted as skipped")
	}

	sigs := imp.Signatures()

	w3tc := findSig(sigs, "W3 Total Cache")
	if w3tc == nil {
		t.Fatal("W3 Total Cache missing")
	}
	if w3tc.Category != "caching" {
		t.Fatalf("category = %q, want caching", w3tc.Category)
	}
	var header *fingerprint.Matcher
	var body bool
	for i := range w3tc.Match {
		m := &w3tc.Match[i]
		if m.Header == "x-powered-by" {
			header = m
		}
		if m.Body != "" {
			body = true
		}
	}
	if header == nil {
		t.Fatal("x-powered-by matcher missing")
	}
	if header.Version != 1 {
		t.Fatalf("header version group = %d, want 1", header.Version)
	}
	if !body {
		t.Fatal("html matcher missing")
	}

	jq := findSig(sigs, "jQuery")
	if jq == nil {
		t.Fatal("jQuery missing")
	}
	if len(jq.Match) != 1 {
		t.Fatalf("jQuery should keep only scriptSrc, got %d matchers", len(jq.Match))
	}
	if got, want := jq.Match[0].Weight, 0.8; got != want {
		t.Fatalf("jquery weight = %v, want %v", got, want)
	}

	pc := findSig(sigs, "Presence Cookie")
	if pc == nil {
		t.Fatal("Presence Cookie missing")
	}
	if pc.Category != "app" {
		t.Fatalf("unknown category id should fall back to app, got %q", pc.Category)
	}
	if len(pc.Match) != 1 || pc.Match[0].Cookie != "session_id" {
		t.Fatalf("cookie presence matcher wrong: %+v", pc.Match)
	}
}

func TestImportNuclei(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "http/technologies/gitea-detect.yaml", nucleiFixture)
	writeFixture(t, dir, "http/technologies/favicon/confluence-detect.yaml", nucleiFaviconFixture)

	imp := NewImporter(Options{})
	st, err := imp.ImportNuclei(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Considered != 2 || st.Imported != 2 {
		t.Fatalf("considered/imported = %d/%d, want 2/2", st.Considered, st.Imported)
	}

	sigs := imp.Signatures()

	gitea := findSig(sigs, "Gitea")
	if gitea == nil {
		t.Fatal("Gitea missing (name suffix not stripped?)")
	}
	var path, version *fingerprint.Matcher
	for i := range gitea.Match {
		m := &gitea.Match[i]
		if m.Path == "/user/login" {
			path = m
		}
		if m.Version == 3 {
			version = m
		}
	}
	if path == nil {
		t.Fatal("path matcher missing")
	}
	if path.Status != 200 {
		t.Fatalf("path status = %d, want 200", path.Status)
	}
	if version == nil {
		t.Fatal("extractor version group 3 not attached")
	}
	if len(gitea.Tags) != 2 || gitea.Tags[0] != "tech" {
		t.Fatalf("tags = %v", gitea.Tags)
	}

	conf := findSig(sigs, "Atlassian Confluence")
	if conf == nil {
		t.Fatal("Confluence missing")
	}
	var fav *fingerprint.Matcher
	for i := range conf.Match {
		if conf.Match[i].Favicon != nil {
			fav = &conf.Match[i]
		}
	}
	if fav == nil {
		t.Fatal("favicon matcher missing")
	}
	if *fav.Favicon != -235150127 {
		t.Fatalf("favicon hash = %d, want -235150127", *fav.Favicon)
	}
}

func TestNucleiNamedDSLBecomesOwnSignature(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "wp-plugin-detect.yaml", `id: wordpress-plugin-detect
info:
  name: WordPress Plugin Detect
  tags: tech,wordpress,plugin
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: dsl
        name: elementor
        dsl:
          - 'regex("/plugins/elementor/", body)'
          - 'status_code == 200'
        condition: and
      - type: dsl
        name: woocommerce
        dsl:
          - 'regex("/plugins/woocommerce/", body)'
          - 'status_code == 200'
        condition: and
`)

	imp := NewImporter(Options{})
	st, err := imp.ImportNuclei(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The parent template has no evidence of its own; the two named dsl
	// matchers become standalone signatures.
	if st.Imported != 2 || st.SkipNoEvidence != 1 {
		t.Fatalf("imported = %d, no-evidence = %d, want 2 and 1", st.Imported, st.SkipNoEvidence)
	}
	sigs := imp.Signatures()
	el := findSig(sigs, "Wordpress Plugin Elementor")
	if el == nil {
		t.Fatalf("plugin signature missing, have %v", sigs)
	}
	if len(el.Match) != 1 || el.Match[0].Body != "/plugins/elementor/" {
		t.Fatalf("elementor matcher wrong: %+v", el.Match)
	}
	if len(el.Tags) != 3 {
		t.Fatalf("tags not inherited: %v", el.Tags)
	}
}

func TestNucleiAndConditionWithDroppedMatcherDiscardsRest(t *testing.T) {
	dir := t.TempDir()
	// The word matcher alone (<html|<body) would match every page; the
	// template requires AND with a DSL helper we cannot translate, so the
	// whole request must be discarded rather than approximated.
	writeFixture(t, dir, "graphql-apollo-detect.yaml", `id: graphql-apollo-detect
info:
  name: GraphQL Apollo Detect
  tags: tech,graphql
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "<html"
          - "<body"
      - type: dsl
        dsl:
          - "contains(body, 'apollo')"
`)

	imp := NewImporter(Options{})
	st, err := imp.ImportNuclei(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Imported != 0 || st.SkipNoEvidence != 1 {
		t.Fatalf("imported = %d, no-evidence = %d, want 0 and 1", st.Imported, st.SkipNoEvidence)
	}
	if st.MatchersSkipped == 0 {
		t.Fatal("discarded matchers should be counted as skipped")
	}
}

func TestReservedNamesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "gitea-detect.yaml", nucleiFixture)

	imp := NewImporter(Options{Reserved: []string{"Gitea"}})
	st, err := imp.ImportNuclei(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Imported != 0 || st.SkipDuplicate != 1 {
		t.Fatalf("imported = %d, duplicates = %d, want 0 and 1", st.Imported, st.SkipDuplicate)
	}
}

func TestBadRegexMatcherDropped(t *testing.T) {
	dir := t.TempDir()
	// A lookahead is valid in Wappalyzer's JS regexes but not in RE2.
	writeFixture(t, dir, "b.json", `{"Lookahead App": {"cats": [1], "html": "foo(?=bar)", "cookies": {"ok_cookie": ""}}}`)

	imp := NewImporter(Options{})
	st, err := imp.ImportWappalyzer(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Imported != 1 {
		t.Fatalf("imported = %d, want 1 (cookie matcher survives)", st.Imported)
	}
	sigs := imp.Signatures()
	if len(sigs) != 1 || len(sigs[0].Match) != 1 || sigs[0].Match[0].Cookie == "" {
		t.Fatalf("only the cookie matcher should remain: %+v", sigs)
	}
	if st.MatchersSkipped != 1 {
		t.Fatalf("matchers skipped = %d, want 1", st.MatchersSkipped)
	}
}

func TestMarshalRoundTripThroughEngine(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "w.json", wappFixture)
	writeFixture(t, dir, "gitea-detect.yaml", nucleiFixture)

	imp := NewImporter(Options{})
	if _, err := imp.ImportWappalyzer(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := imp.ImportNuclei(dir); err != nil {
		t.Fatal(err)
	}

	data, err := Marshal(imp.Signatures(), "test")
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "imported.yaml")
	if err := os.WriteFile(out, data, 0o644); err != nil {
		t.Fatal(err)
	}
	// The real contract: the fingerprint engine must load what we emit.
	e, err := fingerprint.NewEngine(out)
	if err != nil {
		t.Fatalf("engine rejected imported file: %v", err)
	}
	if findSig(e.Signatures(), "W3 Total Cache") == nil {
		t.Fatal("imported signature not visible in engine")
	}
	found := false
	for _, p := range e.Paths() { // built-in signatures contribute their own paths
		if p == "/user/login" {
			found = true
		}
	}
	if !found {
		t.Fatalf("engine paths = %v, want /user/login among them", e.Paths())
	}
}
