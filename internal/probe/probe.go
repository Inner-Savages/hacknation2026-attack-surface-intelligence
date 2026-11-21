// Package probe fetches basic information from web services found by the
// scanner: status, title, headers, cookies, redirects, TLS certificate and
// favicon hash. It only sends GET requests, never logs in, follows
// redirects only within the same host, and caps body size and time.
package probe

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

// UserAgent identifies the prober in target logs.
const UserAgent = "silence-on-the-wire/scanner (+https://github.com/Inner-Savages/silence-on-the-wire)"

const (
	maxBody      = 512 << 10 // bytes of the page kept for title and fingerprinting
	maxFavicon   = 256 << 10
	maxRedirects = 5
	maxHeaderLen = 512
)

// Target is a web service to probe. Host goes into the URL, Host header
// and TLS SNI (a hostname if the scan target was one); the connection is
// always made to Addr, the address nmap actually scanned.
type Target struct {
	Host   string
	Addr   string
	Port   int
	Scheme string // http or https
}

// Prober probes web services.
type Prober struct {
	Timeout time.Duration // per request; default 10s
}

func (p *Prober) timeout() time.Duration {
	if p.Timeout <= 0 {
		return 10 * time.Second
	}
	return p.Timeout
}

// client builds an HTTP client that dials t.Addr whatever the URL says and
// does not follow redirects by itself.
func (p *Prober) client(t Target) *http.Client {
	dialer := &net.Dialer{Timeout: p.timeout()}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(t.Addr, port))
		},
		// Verification is off on purpose: the point is to record what the
		// certificate says, including self-signed and expired ones.
		TLSClientConfig:        &tls.Config{InsecureSkipVerify: true, ServerName: t.Host},
		TLSHandshakeTimeout:    p.timeout(),
		ResponseHeaderTimeout:  p.timeout(),
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       p.timeout(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Probe fetches "/" (following same-host redirects) and the favicon.
func (p *Prober) Probe(ctx context.Context, t Target) *result.HTTP {
	start := time.Now()
	base := (&url.URL{Scheme: t.Scheme, Host: net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), Path: "/"}).String()
	res := &result.HTTP{URL: base}
	defer func() { res.Duration = result.Duration(time.Since(start)) }()

	c := p.client(t)
	cur := base
	var resp *http.Response
	for hop := 0; ; hop++ {
		r, err := p.get(ctx, c, cur)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		loc := r.Header.Get("Location")
		if r.StatusCode < 300 || r.StatusCode >= 400 || loc == "" || hop == maxRedirects {
			resp = r
			break
		}
		r.Body.Close()
		next, err := url.Parse(cur)
		if err == nil {
			next, err = next.Parse(loc)
		}
		res.Redirects = append(res.Redirects, result.Redirect{URL: cur, Status: r.StatusCode, Location: loc})
		if err != nil || next.Hostname() != t.Host || (next.Scheme != "http" && next.Scheme != "https") {
			// Off-host (or odd) redirect: record it, don't follow it.
			res.FinalURL = cur
			res.Status = r.StatusCode
			return res
		}
		cur = next.String()
	}
	defer resp.Body.Close()

	res.FinalURL = cur
	res.Status = resp.StatusCode
	res.Headers = headers(resp.Header)
	res.Cookies = cookies(resp)
	if resp.TLS != nil {
		res.TLS = tlsInfo(resp.TLS)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	res.Body = body
	res.BodySize = len(body)
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		res.BodySHA256 = hex.EncodeToString(sum[:])
	}
	res.Title = title(body)
	res.Favicon = p.favicon(ctx, c, cur, body)
	return res
}

func (p *Prober) get(ctx context.Context, c *http.Client, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "text/html,*/*;q=0.8")
	resp, err := c.Do(req)
	if err != nil {
		return nil, shortErr(err)
	}
	return resp, nil
}

var iconLinkRe = regexp.MustCompile(`(?is)<link[^>]+rel=["']?(?:shortcut )?icon["']?[^>]*>`)
var hrefRe = regexp.MustCompile(`(?is)href=["']?([^"' >]+)`)

// favicon fetches the icon declared in the page, or /favicon.ico.
func (p *Prober) favicon(ctx context.Context, c *http.Client, page string, body []byte) *result.Favicon {
	pageURL, err := url.Parse(page)
	if err != nil {
		return nil
	}
	ref := "/favicon.ico"
	if m := iconLinkRe.Find(body); m != nil {
		if h := hrefRe.FindSubmatch(m); h != nil {
			ref = html.UnescapeString(string(h[1]))
		}
	}
	u, err := pageURL.Parse(ref)
	if err != nil || u.Hostname() != pageURL.Hostname() || (u.Scheme != "http" && u.Scheme != "https") {
		return nil
	}
	resp, err := p.get(ctx, c, u.String())
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	icon, _ := io.ReadAll(io.LimitReader(resp.Body, maxFavicon))
	if len(icon) == 0 {
		return nil
	}
	sum := md5.Sum(icon)
	return &result.Favicon{URL: u.String(), Hash: FaviconHash(icon), MD5: hex.EncodeToString(sum[:]), Size: len(icon)}
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func title(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.Join(strings.Fields(html.UnescapeString(string(m[1]))), " ")
	if len(t) > 200 {
		t = t[:200]
	}
	return t
}

func headers(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, vs := range h {
		k = strings.ToLower(k)
		if k == "set-cookie" {
			continue // values are secrets; names and flags go to Cookies
		}
		for _, v := range vs {
			if len(v) > maxHeaderLen {
				v = v[:maxHeaderLen]
			}
			out[k] = append(out[k], v)
		}
	}
	return out
}

func cookies(resp *http.Response) []result.Cookie {
	var out []result.Cookie
	for _, c := range resp.Cookies() {
		ss := ""
		switch c.SameSite {
		case http.SameSiteLaxMode:
			ss = "Lax"
		case http.SameSiteStrictMode:
			ss = "Strict"
		case http.SameSiteNoneMode:
			ss = "None"
		}
		out = append(out, result.Cookie{Name: c.Name, Path: c.Path, Domain: c.Domain, Secure: c.Secure, HttpOnly: c.HttpOnly, SameSite: ss})
	}
	return out
}

func tlsInfo(cs *tls.ConnectionState) *result.TLS {
	info := &result.TLS{Version: tls.VersionName(cs.Version), Cipher: tls.CipherSuiteName(cs.CipherSuite)}
	if len(cs.PeerCertificates) == 0 {
		return info
	}
	cert := cs.PeerCertificates[0]
	sum := sha256.Sum256(cert.Raw)
	info.Subject = cert.Subject.String()
	info.Issuer = cert.Issuer.String()
	info.DNSNames = cert.DNSNames
	for _, ip := range cert.IPAddresses {
		info.IPs = append(info.IPs, ip.String())
	}
	info.NotBefore, info.NotAfter = cert.NotBefore, cert.NotAfter
	info.Expired = time.Now().After(cert.NotAfter)
	info.SelfSigned = isSelfSigned(cert)
	info.SHA256 = hex.EncodeToString(sum[:])
	return info
}

func isSelfSigned(c *x509.Certificate) bool {
	return c.Subject.String() == c.Issuer.String() && c.CheckSignatureFrom(c) == nil
}

// shortErr drops net/url's "Get \"http://...\": " prefix; the URL is
// already in the result.
func shortErr(err error) error {
	if ue, ok := err.(*url.Error); ok {
		return ue.Err
	}
	return err
}

// Schemes says how to talk to a service nmap found, in order of preference.
// Empty means "not a web service".
func Schemes(s result.Service) []string {
	if s.State != "open" || s.Proto != "tcp" {
		return nil
	}
	name := strings.ToLower(s.Name)
	tlsish := s.Tunnel == "ssl" || name == "https" || strings.HasPrefix(name, "ssl") || name == "https-alt"
	switch {
	case strings.Contains(name, "http") && tlsish, name == "https", name == "ssl/http":
		return []string{"https"}
	case strings.Contains(name, "http"):
		return []string{"http"}
	case name == "tcpwrapped" || name == "unknown" || name == "":
		if webPorts[s.Port] {
			return []string{"http", "https"}
		}
	}
	return nil
}

// webPorts are common HTTP(S) ports where an unidentified service is worth
// one HTTP attempt.
var webPorts = map[int]bool{80: true, 81: true, 443: true, 591: true, 3000: true, 5000: true, 8000: true,
	8008: true, 8080: true, 8081: true, 8088: true, 8443: true, 8888: true, 9000: true, 9090: true, 9443: true}

// ProbeScan probes every web service in the scan, parallel at a time, and
// stores the results in Service.HTTP.
func (p *Prober) ProbeScan(ctx context.Context, s *result.Scan, parallel int) int {
	if parallel <= 0 {
		parallel = 8
	}
	type job struct {
		host *result.Host
		svc  *result.Service
	}
	var jobs []job
	for i := range s.Hosts {
		h := &s.Hosts[i]
		for j := range h.Services {
			if Schemes(h.Services[j]) != nil {
				jobs = append(jobs, job{h, &h.Services[j]})
			}
		}
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, parallel)
	for _, jb := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			host := jb.host.Address
			if len(jb.host.Hostnames) > 0 {
				host = jb.host.Hostnames[0]
			}
			var last *result.HTTP
			for _, scheme := range Schemes(*jb.svc) {
				last = p.Probe(ctx, Target{Host: host, Addr: jb.host.Address, Port: jb.svc.Port, Scheme: scheme})
				if last.Error == "" {
					break
				}
			}
			jb.svc.HTTP = last
		}()
	}
	wg.Wait()
	return len(jobs)
}

// FetchPath GETs one fixed path of a web service already probed (used by
// fingerprinting, e.g. /wp-login.php). It does not follow redirects and
// reuses the scheme and host the main probe settled on.
func (p *Prober) FetchPath(ctx context.Context, h *result.Host, s *result.Service, path string) (*result.Page, error) {
	if s.HTTP == nil || s.HTTP.Error != "" {
		return nil, errors.New("service was not probed successfully")
	}
	base, err := url.Parse(s.HTTP.URL)
	if err != nil {
		return nil, err
	}
	u, err := base.Parse(path)
	if err != nil || u.Host != base.Host {
		return nil, fmt.Errorf("path %q leaves the service", path)
	}
	t := Target{Host: base.Hostname(), Addr: h.Address, Port: s.Port, Scheme: base.Scheme}
	resp, err := p.get(ctx, p.client(t), u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return &result.Page{Path: path, Status: resp.StatusCode, Headers: headers(resp.Header), Title: title(body), Body: body}, nil
}
