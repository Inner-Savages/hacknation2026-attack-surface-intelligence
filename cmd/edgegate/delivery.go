package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

func post(client *http.Client, url string, body []byte) error {
	return postWithToken(client, url, body, os.Getenv("ASI_CENTRAL_TOKEN"))
}

func postWithToken(client *http.Client, url string, body []byte, token string) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// validateRemote requires TLS for any destination other than loopback.
func validateRemote(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("invalid central URL")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" || u.Hostname() == "central") {
		return nil
	}
	return fmt.Errorf("central-url must be HTTPS or HTTP loopback")
}
