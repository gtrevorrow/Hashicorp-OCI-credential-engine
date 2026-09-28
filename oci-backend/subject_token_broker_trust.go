package ocibackend

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	maxBrokeredDocumentBytes = 1 << 20
	maxBrokeredKeys          = 64
	brokeredCacheTTL         = 5 * time.Minute
	brokeredRefreshInterval  = 30 * time.Second
)

// One entry per mount bounds memory. Policy changes cannot reuse another policy's keys.
// A shared flight serializes refreshes; waiting callers retain cancellation support.
type brokeredTrustCache struct {
	mu      sync.Mutex
	policy  [32]byte
	keys    []jose.JSONWebKey
	fetched time.Time
	flight  chan struct{}
	err     error
}

func brokeredURL(raw string, debugHTTP bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Opaque != "" {
		return nil, fmt.Errorf("trust URL must be absolute with no credentials, query, or fragment")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		local := strings.EqualFold(u.Hostname(), "localhost") || (ip != nil && ip.IsLoopback())
		if u.Scheme != "http" || !debugHTTP || !local {
			return nil, fmt.Errorf("trust URL requires HTTPS; debug_allow_brokered_http permits HTTP only on loopback")
		}
	}
	return u, nil
}

func brokeredOrigin(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(host, port)
}

func validateBrokeredRemotePolicy(c *federatedConfig) error {
	for _, raw := range c.BrokeredSubjectTokenAllowedJWKSOrigins {
		u, err := brokeredURL(raw, c.DebugAllowBrokeredHTTP)
		if err != nil {
			return fmt.Errorf("invalid allowed JWKS origin: %w", err)
		}
		if u.Path != "" {
			return fmt.Errorf("allowed JWKS origins must not contain a path")
		}
	}
	switch c.BrokeredSubjectTokenTrustType {
	case brokeredTrustTypeOIDCDiscovery:
		_, err := brokeredURL(c.BrokeredSubjectTokenIssuer, c.DebugAllowBrokeredHTTP)
		return err
	case brokeredTrustTypeJWKSURL:
		_, err := brokeredURL(c.BrokeredSubjectTokenJWKSURL, c.DebugAllowBrokeredHTTP)
		return err
	}
	return nil
}

func allowedBrokeredJWKSURL(raw string, c *federatedConfig) error {
	u, err := brokeredURL(raw, c.DebugAllowBrokeredHTTP)
	if err != nil {
		return err
	}
	issuer, err := brokeredURL(c.BrokeredSubjectTokenIssuer, c.DebugAllowBrokeredHTTP)
	if err != nil {
		return err
	}
	if brokeredOrigin(u) == brokeredOrigin(issuer) {
		return nil
	}
	for _, rawOrigin := range c.BrokeredSubjectTokenAllowedJWKSOrigins {
		origin, err := brokeredURL(rawOrigin, c.DebugAllowBrokeredHTTP)
		if err == nil && origin.Path == "" && brokeredOrigin(u) == brokeredOrigin(origin) {
			return nil
		}
	}
	return fmt.Errorf("discovered JWKS origin is not allowed; configure brokered_subject_token_allowed_jwks_origins")
}

// Debug HTTP must remain on loopback even if localhost resolves unexpectedly.
func validateBrokeredAddress(host string, ip net.IP, debug bool) error {
	localHost := strings.EqualFold(host, "localhost")
	if parsed := net.ParseIP(host); parsed != nil {
		localHost = parsed.IsLoopback()
	}
	if debug && localHost {
		if !ip.IsLoopback() {
			return fmt.Errorf("debug loopback host resolved to a non-loopback address")
		}
		return nil
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return fmt.Errorf("trust host resolved to a non-public address")
	}
	return nil
}

// Check every resolved address and dial the checked address, avoiding DNS rebinding.
// Trust fetches do not use environment proxies that could bypass these checks.
func brokeredDialContext(debugHTTP bool) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("trust host resolved to no addresses")
		}
		for _, addr := range ips {
			if err := validateBrokeredAddress(host, addr.IP, debugHTTP); err != nil {
				return nil, err
			}
		}

		var dialErr error
		for _, addr := range ips {
			conn, err := (&net.Dialer{Timeout: defaultHTTPClientTimeout}).DialContext(ctx, network, net.JoinHostPort(addr.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			dialErr = err
		}
		return nil, dialErr
	}
}

func (b *backend) fetchBrokeredJSON(ctx context.Context, rawURL string, out interface{}, c *federatedConfig) error {
	if _, err := brokeredURL(rawURL, c.DebugAllowBrokeredHTTP); err != nil {
		return err
	}
	transport := b.brokeredTransport
	if transport == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil
		t.DialContext = brokeredDialContext(c.DebugAllowBrokeredHTTP)
		defer t.CloseIdleConnections()
		transport = t
	}
	client := &http.Client{Timeout: defaultHTTPClientTimeout, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("trust endpoint returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBrokeredDocumentBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxBrokeredDocumentBytes {
		return fmt.Errorf("trust document exceeds %d bytes", maxBrokeredDocumentBytes)
	}
	return json.Unmarshal(body, out)
}

func (b *backend) cachedBrokeredVerificationKeys(ctx context.Context, c *federatedConfig, refresh bool) ([]jose.JSONWebKey, error) {
	if c.BrokeredSubjectTokenTrustType != brokeredTrustTypeOIDCDiscovery && c.BrokeredSubjectTokenTrustType != brokeredTrustTypeJWKSURL {
		return b.resolveBrokeredVerificationKeys(ctx, c)
	}
	// Only trust-policy data belongs in the cache identity, never OAuth credentials.
	raw, _ := json.Marshal(struct {
		Type, Issuer, URL string
		Debug             bool
		Origins           []string
	}{
		c.BrokeredSubjectTokenTrustType, c.BrokeredSubjectTokenIssuer, c.BrokeredSubjectTokenJWKSURL, c.DebugAllowBrokeredHTTP, c.BrokeredSubjectTokenAllowedJWKSOrigins})
	id := sha256.Sum256(raw)
	cache := &b.brokeredTrustCache
	for {
		cache.mu.Lock()
		age := time.Since(cache.fetched)
		if cache.policy == id && cache.err != nil && age < brokeredRefreshInterval {
			err := cache.err
			cache.mu.Unlock()
			return nil, err
		}
		if cache.policy == id && len(cache.keys) > 0 && age < brokeredCacheTTL && (!refresh || age < brokeredRefreshInterval) {
			keys := cache.keys
			cache.mu.Unlock()
			return keys, nil
		}
		if cache.flight != nil {
			done := cache.flight
			cache.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-done:
				continue
			}
		}
		cache.flight = make(chan struct{})
		cache.mu.Unlock()
		keys, err := b.resolveBrokeredVerificationKeys(ctx, c)
		cache.mu.Lock()
		// Failed refreshes invalidate the entry: never serve stale keys after a failure.
		cache.err = err
		// A caller canceling its request must not impose a mount-wide failure cooldown.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			cache.err = nil
		}
		cache.policy = id
		cache.keys = nil
		cache.fetched = time.Now()
		if err == nil {
			cache.keys = keys
		}
		close(cache.flight)
		cache.flight = nil
		cache.mu.Unlock()
		return keys, err
	}
}
