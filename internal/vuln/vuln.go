package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

// Default upstream endpoints. All three are free; NVD is faster with an API
// key (NVD_API_KEY), the others need none.
const (
	defaultNVDBase  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	defaultEPSSBase = "https://api.first.org/data/v1/epss"
	defaultKEVURL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// Client queries NVD, EPSS and KEV with on-disk caching and polite pacing.
type Client struct {
	HTTP     *http.Client
	NVDBase  string
	EPSSBase string
	KEVURL   string
	APIKey   string // NVD_API_KEY; empty means the tight anonymous quota
	Cache    *cache

	// NVDDelay is the minimum spacing between uncached NVD calls
	// (anonymous quota is ~5 requests per 30 s; a key raises it ~10x).
	NVDDelay time.Duration

	mu       sync.Mutex // paces NVD calls
	lastCall time.Time
}

// NewClient builds a Client with production endpoints and a cache in dir.
func NewClient(cacheDir, nvdAPIKey string) (*Client, error) {
	c, err := newCache(cacheDir)
	if err != nil {
		return nil, err
	}
	delay := 6 * time.Second
	if nvdAPIKey != "" {
		delay = 600 * time.Millisecond
	}
	return &Client{
		HTTP:    &http.Client{Timeout: 15 * time.Second},
		NVDBase: defaultNVDBase, EPSSBase: defaultEPSSBase, KEVURL: defaultKEVURL,
		APIKey: nvdAPIKey, Cache: c, NVDDelay: delay,
	}, nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// cvssMetric mirrors one cvssMetricVXX entry from the NVD response.
type cvssMetric struct {
	Data struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"cvssData"`
}

// nvdCVE is the subset of the NVD API 2.0 response we use.
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSV31 []cvssMetric `json:"cvssMetricV31"`
				CVSSV30 []cvssMetric `json:"cvssMetricV30"`
				CVSSV2  []cvssMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// queryNVD returns the raw CVE entries for one CPE, from cache or upstream.
func (c *Client) queryNVD(ctx context.Context, cpeName string) (*nvdResponse, error) {
	if raw, ok := c.Cache.get("nvd", cpeName); ok {
		var resp nvdResponse
		if json.Unmarshal(raw, &resp) == nil {
			return &resp, nil
		}
	}
	c.mu.Lock()
	if wait := c.NVDDelay - time.Since(c.lastCall); wait > 0 {
		select {
		case <-ctx.Done():
			c.mu.Unlock()
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	c.lastCall = time.Now()
	c.mu.Unlock()

	u := c.NVDBase + "?cpeName=" + url.QueryEscape(cpeName) + "&resultsPerPage=200"
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD: HTTP %d: %.200s", resp.StatusCode, body)
	}
	c.Cache.set("nvd", cpeName, body)
	var out nvdResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("NVD: %w", err)
	}
	return &out, nil
}

// epssResponse is the FIRST EPSS API answer.
type epssResponse struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

// queryEPSS fetches EPSS scores for a batch of CVE IDs (one request, they
// accept long comma-separated lists; chunks of 100 stay well inside).
func (c *Client) queryEPSS(ctx context.Context, cves []string) (map[string][2]float64, error) {
	out := map[string][2]float64{}
	for start := 0; start < len(cves); start += 100 {
		end := start + 100
		if end > len(cves) {
			end = len(cves)
		}
		batch := cves[start:end]
		key := strings.Join(batch, ",")
		var raw json.RawMessage
		if cached, ok := c.Cache.get("epss", key); ok {
			raw = cached
		} else {
			u := c.EPSSBase + "?cve=" + url.QueryEscape(key)
			req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
			if err != nil {
				return nil, err
			}
			resp, err := c.httpClient().Do(req)
			if err != nil {
				return out, err
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
			resp.Body.Close()
			if err != nil {
				return out, err
			}
			if resp.StatusCode != 200 {
				return out, fmt.Errorf("EPSS: HTTP %d", resp.StatusCode)
			}
			c.Cache.set("epss", key, body)
			raw = body
		}
		var parsed epssResponse
		if json.Unmarshal(raw, &parsed) != nil {
			continue
		}
		for _, d := range parsed.Data {
			epss, _ := strconv.ParseFloat(d.EPSS, 64)
			pct, _ := strconv.ParseFloat(d.Percentile, 64)
			out[d.CVE] = [2]float64{epss, pct}
		}
	}
	return out, nil
}

// kevCatalog is the CISA Known Exploited Vulnerabilities feed.
type kevCatalog struct {
	Vulnerabilities []struct {
		ID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// kevSet returns the set of CVE IDs CISA lists as actively exploited.
func (c *Client) kevSet(ctx context.Context) (map[string]bool, error) {
	var raw json.RawMessage
	if cached, ok := c.Cache.get("kev", "catalog"); ok {
		raw = cached
	} else {
		req, err := http.NewRequestWithContext(ctx, "GET", c.KEVURL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.httpClient().Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("KEV: HTTP %d", resp.StatusCode)
		}
		c.Cache.set("kev", "catalog", body)
		raw = body
	}
	var cat kevCatalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, v := range cat.Vulnerabilities {
		set[v.ID] = true
	}
	return set, nil
}

// Lookup returns the CVEs affecting one exact-version CPE, ranked by EPSS
// (exploitation probability), with CVSS as the tie-breaker. Sources that
// fail are skipped rather than failing the whole lookup.
func (c *Client) Lookup(ctx context.Context, cpeName string) ([]result.Vuln, error) {
	nvd, err := c.queryNVD(ctx, cpeName)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(nvd.Vulnerabilities))
	cvss := map[string]float64{}
	summary := map[string]string{}
	for _, v := range nvd.Vulnerabilities {
		ids = append(ids, v.CVE.ID)
		cvss[v.CVE.ID] = pickCVSS(v.CVE.Metrics.CVSSV31, v.CVE.Metrics.CVSSV30, v.CVE.Metrics.CVSSV2)
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				summary[v.CVE.ID] = d.Value
				break
			}
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	epss, epssErr := c.queryEPSS(ctx, ids)
	kev, _ := c.kevSet(ctx)

	out := make([]result.Vuln, 0, len(ids))
	for _, id := range ids {
		v := result.Vuln{CVE: id, CVSS: cvss[id], Summary: summary[id], KEV: kev[id]}
		if s, ok := epss[id]; ok {
			v.EPSS, v.Percentile = s[0], s[1]
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EPSS != out[j].EPSS {
			return out[i].EPSS > out[j].EPSS
		}
		return out[i].CVSS > out[j].CVSS
	})
	if epssErr != nil && len(out) == 0 {
		return nil, epssErr
	}
	return out, nil
}

// EnrichTech resolves a detected technology to its CPE and looks the CVEs
// up. version is required; without it the answer would be every CVE ever
// assigned to the product, which is noise.
func (c *Client) EnrichTech(ctx context.Context, name, version string) ([]result.Vuln, error) {
	cpe, ok := CPEFor(name, version)
	if !ok {
		return nil, nil
	}
	return c.Lookup(ctx, cpe)
}

// EnrichBanner resolves a service banner (e.g. captured by a control scan)
// the same way.
func (c *Client) EnrichBanner(ctx context.Context, banner string) ([]result.Vuln, error) {
	cpe, ok := CPEForBanner(banner)
	if !ok {
		return nil, nil
	}
	return c.Lookup(ctx, cpe)
}

// pickCVSS prefers the newest metric available.
func pickCVSS(sets ...[]cvssMetric) float64 {
	for _, set := range sets {
		for _, m := range set {
			if m.Data.BaseScore > 0 {
				return m.Data.BaseScore
			}
		}
	}
	return 0
}
