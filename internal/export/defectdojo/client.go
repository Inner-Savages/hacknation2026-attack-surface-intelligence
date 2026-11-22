// Package defectdojo sends observations to a DefectDojo instance through
// its REST API v2 as informational findings, without creating duplicates
// and without touching decisions analysts made there.
package defectdojo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client talks to one DefectDojo instance.
type Client struct {
	base  string // without trailing slash, ends with /api/v2
	token string
	http  *http.Client
}

// New checks the URL and returns a client. The URL is the instance's root
// (https://dojo.example.org) or its /api/v2. Plain HTTP would expose the
// token on the network, so it is refused except for loopback addresses,
// unless allowHTTP is set.
func New(rawURL, token string, allowHTTP bool) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("DefectDojo URL must look like https://dojo.example.org")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("DefectDojo URL must not contain credentials or parameters; the token comes from the environment or a file")
	}
	if u.Scheme == "http" && !allowHTTP && !loopback(u.Hostname()) {
		return nil, errors.New("refusing to send the API token over plain HTTP to " + u.Hostname())
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("no DefectDojo API token")
	}
	base := strings.TrimSuffix(strings.TrimRight(u.String(), "/"), "/api/v2")
	return &Client{
		base:  base + "/api/v2",
		token: token,
		http: &http.Client{
			Timeout: 2 * time.Minute, // imports are synchronous and may be slow
			// Following a redirect would turn a POST into a GET and might
			// carry the token elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func loopback(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// Error is a response DefectDojo refused a request with.
type Error struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *Error) Error() string {
	return fmt.Sprintf("DefectDojo %s %s: %d %s: %s", e.Method, e.Path, e.Status, http.StatusText(e.Status), e.Body)
}

// do sends a request and decodes the JSON response into out (if not nil).
func (c *Client) do(ctx context.Context, method, path string, query url.Values, contentType string, body io.Reader, out any) error {
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+c.token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return fmt.Errorf("DefectDojo %s %s: timed out", method, path)
		}
		return fmt.Errorf("DefectDojo: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("DefectDojo %s %s: %w", method, path, err)
	}
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fmt.Errorf("DefectDojo %s %s: redirected to %q; use that URL", method, path, resp.Header.Get("Location"))
	case resp.StatusCode >= 400:
		return &Error{Method: method, Path: path, Status: resp.StatusCode, Body: truncate(clean(string(data)), 500)}
	case out == nil:
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("DefectDojo %s %s: not a JSON API response (is the URL right?): %w", method, path, err)
	}
	return nil
}

func (c *Client) send(ctx context.Context, method, path string, in, out any) error {
	data, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return c.do(ctx, method, path, nil, "application/json", bytes.NewReader(data), out)
}

const pageSize = 100

// list fetches all pages of a collection. The server's "next" links are not
// followed: behind a proxy they can point elsewhere.
func list[T any](ctx context.Context, c *Client, path string, query url.Values) ([]T, error) {
	var out []T
	q := url.Values{}
	for k, v := range query {
		q[k] = v
	}
	q.Set("limit", strconv.Itoa(pageSize))
	for {
		q.Set("offset", strconv.Itoa(len(out)))
		var page struct {
			Count   int `json:"count"`
			Results []T `json:"results"`
		}
		if err := c.do(ctx, http.MethodGet, path, q, "", nil, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Results...)
		if len(page.Results) == 0 || len(out) >= page.Count {
			return out, nil
		}
	}
}

// upload sends a report file to a running test's reimport.
func (c *Client) upload(ctx context.Context, fields map[string]string, filename string, report []byte, out any) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			return err
		}
	}
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return err
	}
	if _, err := fw.Write(report); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, "/reimport-scan/", nil, mw.FormDataContentType(), &buf, out)
}
