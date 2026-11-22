// Package exposure correlates the inside view of the network (what the
// passive sensor sees) with the outside view (what internet-wide scanners
// like Shodan or Censys see of the public IP). The diff between the two is
// where shadow IT and accidental exposures live: a service the sensor
// never saw, answering on the public address, or an internal service that
// turned out to be reachable from the world.
//
// Shodan is the reference provider (our favicon hashes are its mmh3
// format, so favicon search works out of the box); Censys covers host
// views. Everything is fail-soft — a missing key or a network error
// degrades to "no external view", never to a failed scan.
package exposure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ExternalService is one service the outside world can reach.
type ExternalService struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"` // tcp / udp
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`

	// FaviconMMH3 is the Shodan-compatible mmh3 favicon hash — the same
	// format internal/probe computes, which makes cross-matching free.
	FaviconMMH3 *int32 `json:"favicon_mmh3,omitempty"`
}

// Key identifies the service for diffing.
func (s ExternalService) Key() string {
	proto := s.Proto
	if proto == "" {
		proto = "tcp"
	}
	return strconv.Itoa(s.Port) + "/" + proto
}

// ExternalView is what the internet sees of one public IP.
type ExternalView struct {
	IP         string            `json:"ip"`
	Source     string            `json:"source"` // shodan | censys
	FetchedAt  time.Time         `json:"fetched_at"`
	LastUpdate string            `json:"last_update,omitempty"`
	Org        string            `json:"org,omitempty"`
	Hostnames  []string          `json:"hostnames,omitempty"`
	Tags       []string          `json:"tags,omitempty"`
	Vulns      []string          `json:"vulns,omitempty"`
	Services   []ExternalService `json:"services"`
}

// Provider is one outside-view source.
type Provider interface {
	Name() string
	// Host returns the external view of one public IP.
	Host(ctx context.Context, ip string) (*ExternalView, error)
	// FaviconSearch returns "ip:port" addresses exposing a favicon with
	// the given mmh3 hash. Providers without favicon search report an
	// error; callers treat it as "no data", not a failure.
	FaviconSearch(ctx context.Context, hash int32) ([]string, error)
}

// --- Shodan -----------------------------------------------------------------

// Shodan queries api.shodan.io. Favicon hashes are natively mmh3, the same
// hashing the internal scanner uses (internal/probe/mmh3.go).
type Shodan struct {
	APIKey string
	Base   string       // default https://api.shodan.io
	HTTP   *http.Client // optional override (tests)
}

func (s *Shodan) Name() string { return "shodan" }

func (s *Shodan) base() string {
	if s.Base != "" {
		return s.Base
	}
	return "https://api.shodan.io"
}

func (s *Shodan) httpClient() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func (s *Shodan) get(ctx context.Context, path string, out interface{}) error {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	req, err := http.NewRequestWithContext(ctx, "GET", s.base()+path+sep+"key="+url.QueryEscape(s.APIKey), nil)
	if err != nil {
		return err
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Shodan: HTTP %d: %.200s", resp.StatusCode, body)
	}
	return json.Unmarshal(body, out)
}

// MyIP returns the public egress IP seen by Shodan.
func (s *Shodan) MyIP(ctx context.Context) (string, error) {
	var ip string
	if err := s.get(ctx, "/tools/myip", &ip); err != nil {
		return "", err
	}
	return strings.TrimSpace(ip), nil
}

// shodanHost mirrors the /shodan/host response subset we use.
type shodanHost struct {
	IPStr      string   `json:"ip_str"`
	Org        string   `json:"org"`
	LastUpdate string   `json:"last_update"`
	Hostnames  []string `json:"hostnames"`
	Tags       []string `json:"tags"`
	Vulns      []string `json:"vulns"`
	Data       []struct {
		Port      int    `json:"port"`
		Transport string `json:"transport"`
		Product   string `json:"product"`
		Version   string `json:"version"`
		Data      string `json:"data"`
		HTTP      *struct {
			Favicon *struct {
				Hash int32 `json:"hash"`
			} `json:"favicon"`
		} `json:"http"`
	} `json:"data"`
}

// Host returns the external view of ip as Shodan sees it.
func (s *Shodan) Host(ctx context.Context, ip string) (*ExternalView, error) {
	var h shodanHost
	if err := s.get(ctx, "/shodan/host/"+url.PathEscape(ip), &h); err != nil {
		return nil, err
	}
	view := &ExternalView{
		IP: ip, Source: s.Name(), FetchedAt: time.Now(),
		LastUpdate: h.LastUpdate, Org: h.Org, Hostnames: h.Hostnames, Tags: h.Tags, Vulns: h.Vulns,
	}
	for _, d := range h.Data {
		svc := ExternalService{
			Port: d.Port, Proto: d.Transport, Product: d.Product,
			Version: d.Version, Banner: strings.TrimSpace(d.Data),
		}
		if d.HTTP != nil && d.HTTP.Favicon != nil && d.HTTP.Favicon.Hash != 0 {
			hash := d.HTTP.Favicon.Hash
			svc.FaviconMMH3 = &hash
		}
		view.Services = append(view.Services, svc)
	}
	return view, nil
}

// shodanSearch mirrors the /shodan/search response subset we use.
type shodanSearch struct {
	Matches []struct {
		IPStr string `json:"ip_str"`
		Port  int    `json:"port"`
	} `json:"matches"`
	Total int `json:"total"`
}

// FaviconSearch finds every public host exposing a favicon with the given
// mmh3 hash — the direct "where else is this app visible" question.
func (s *Shodan) FaviconSearch(ctx context.Context, hash int32) ([]string, error) {
	var res shodanSearch
	q := url.QueryEscape("favicon:" + strconv.FormatInt(int64(hash), 10))
	if err := s.get(ctx, "/shodan/search?query="+q, &res); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(res.Matches))
	for _, m := range res.Matches {
		out = append(out, m.IPStr+":"+strconv.Itoa(m.Port))
	}
	return out, nil
}

// --- Censys -----------------------------------------------------------------

// Censys queries the v2 hosts API with API-ID/secret basic auth. Favicon
// search is not part of the free host view, so FaviconSearch reports an
// error and the engine simply skips cross-matching for this provider.
type Censys struct {
	ID, Secret string
	Base       string
	HTTP       *http.Client
}

func (c *Censys) Name() string { return "censys" }

func (c *Censys) base() string {
	if c.Base != "" {
		return c.Base
	}
	return "https://search.censys.io/api"
}

// censysHost mirrors the /v2/hosts/{ip} response subset we use.
type censysHost struct {
	Result struct {
		Services []struct {
			Port        int    `json:"port"`
			ServiceName string `json:"service_name"`
			Banner      string `json:"banner"`
			Software    []struct {
				Product string `json:"product"`
				Version string `json:"version"`
			} `json:"software"`
		} `json:"services"`
		Location struct {
			Country string `json:"country"`
		} `json:"location"`
		AutonomousSystem struct {
			Name string `json:"name"`
		} `json:"autonomous_system"`
		LastUpdatedAt string `json:"last_updated_at"`
	} `json:"result"`
}

// Host returns the external view of ip as Censys sees it.
func (c *Censys) Host(ctx context.Context, ip string) (*ExternalView, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.base()+"/v2/hosts/"+url.PathEscape(ip), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.ID, c.Secret)
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Censys: HTTP %d: %.200s", resp.StatusCode, body)
	}
	var h censysHost
	if err := json.Unmarshal(body, &h); err != nil {
		return nil, fmt.Errorf("Censys: %w", err)
	}
	view := &ExternalView{
		IP: ip, Source: c.Name(), FetchedAt: time.Now(),
		LastUpdate: h.Result.LastUpdatedAt, Org: h.Result.AutonomousSystem.Name,
	}
	for _, s := range h.Result.Services {
		svc := ExternalService{Port: s.Port, Proto: "tcp", Banner: strings.TrimSpace(s.Banner)}
		if len(s.Software) > 0 {
			svc.Product = s.Software[0].Product
			svc.Version = s.Software[0].Version
		}
		if svc.Product == "" {
			svc.Product = strings.ToLower(s.ServiceName)
		}
		view.Services = append(view.Services, svc)
	}
	return view, nil
}

// FaviconSearch is not covered by the Censys free host API.
func (c *Censys) FaviconSearch(ctx context.Context, hash int32) ([]string, error) {
	return nil, fmt.Errorf("censys: favicon search unsupported")
}

// NewProvider builds a provider from settings; empty provider defaults to
// shodan. key for censys is "api-id:api-secret".
func NewProvider(provider, key string) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "shodan":
		if key == "" {
			return nil, fmt.Errorf("brak klucza API Shodan")
		}
		return &Shodan{APIKey: key}, nil
	case "censys":
		id, secret, ok := strings.Cut(key, ":")
		if !ok || id == "" || secret == "" {
			return nil, fmt.Errorf("klucz Censys musi mieć format api-id:api-secret")
		}
		return &Censys{ID: id, Secret: secret}, nil
	default:
		return nil, fmt.Errorf("nieznany dostawca widoku zewnętrznego: %s", provider)
	}
}
