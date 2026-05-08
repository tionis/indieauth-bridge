package indieauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/eric/indieauth-bridge/internal/security"
)

var (
	linkTagRe = regexp.MustCompile(`(?is)<link\s+[^>]*>`)
	attrRe    = regexp.MustCompile(`(?is)(rel|href)\s*=\s*["']([^"']+)["']`)
)

type ClientMetadata struct {
	RedirectURIs []string `json:"redirect_uris"`
	RedirectURI  string   `json:"redirect_uri"`
}

func ValidateClientRedirect(ctx context.Context, httpClient *http.Client, clientID, redirectURI string, allowHTTP, discoveryEnabled bool) error {
	if err := security.ValidateRedirectURI(clientID, redirectURI, allowHTTP); err == nil {
		return nil
	}
	if !discoveryEnabled {
		return errors.New("redirect_uri must have the same origin as client_id")
	}
	uris, err := DiscoverClientRedirectURIs(ctx, httpClient, clientID, allowHTTP)
	if err != nil {
		return err
	}
	requested, err := normalizedRedirect(redirectURI, allowHTTP)
	if err != nil {
		return err
	}
	for _, discovered := range uris {
		normalized, err := normalizedRedirect(discovered, allowHTTP)
		if err == nil && normalized == requested {
			return nil
		}
	}
	return errors.New("redirect_uri is not declared by client metadata")
}

func DiscoverClientRedirectURIs(ctx context.Context, httpClient *http.Client, clientID string, allowHTTP bool) ([]string, error) {
	clientURL, err := security.ValidateHTTPSURL(clientID, allowHTTP)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/html;q=0.9")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("client metadata could not be fetched")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return nil, err
	}
	if uris := redirectURIsFromJSON(body); len(uris) > 0 {
		return resolveRedirectURIs(clientURL, uris), nil
	}
	if uris := redirectURIsFromHTML(body); len(uris) > 0 {
		return resolveRedirectURIs(clientURL, uris), nil
	}
	return nil, errors.New("client metadata did not declare redirect_uri")
}

func redirectURIsFromJSON(body []byte) []string {
	var metadata ClientMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil
	}
	uris := append([]string{}, metadata.RedirectURIs...)
	if metadata.RedirectURI != "" {
		uris = append(uris, metadata.RedirectURI)
	}
	return uris
}

func redirectURIsFromHTML(body []byte) []string {
	var out []string
	for _, tag := range linkTagRe.FindAll(body, -1) {
		attrs := map[string]string{}
		for _, match := range attrRe.FindAllSubmatch(tag, -1) {
			attrs[strings.ToLower(string(match[1]))] = string(match[2])
		}
		if !relContains(attrs["rel"], "redirect_uri") || attrs["href"] == "" {
			continue
		}
		out = append(out, attrs["href"])
	}
	return out
}

func relContains(rel, want string) bool {
	for _, part := range strings.Fields(rel) {
		if strings.EqualFold(part, want) {
			return true
		}
	}
	return false
}

func resolveRedirectURIs(base *url.URL, uris []string) []string {
	out := make([]string, 0, len(uris))
	for _, raw := range uris {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.String() == "" {
			continue
		}
		if !u.IsAbs() {
			u = base.ResolveReference(u)
		}
		out = append(out, u.String())
	}
	return out
}

func normalizedRedirect(raw string, allowHTTP bool) (string, error) {
	u, err := security.ValidateHTTPSURL(raw, allowHTTP)
	if err != nil {
		return "", err
	}
	if u.Fragment != "" {
		return "", errors.New("redirect_uri must not contain a fragment")
	}
	return u.String(), nil
}
