package indieauth

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/eric/indieauth-bridge/internal/security"
)

const profileMetadataLimit = 256 * 1024

var (
	metaTagRe     = regexp.MustCompile(`(?is)<meta\s+[^>]*>`)
	htmlAttrRe    = regexp.MustCompile(`(?is)([a-z_:][a-z0-9_.:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	profileLinkRe = regexp.MustCompile(`(?is)<link\s+[^>]*>`)
)

type ProfileIdentityBinding struct {
	Me      string
	Issuer  string
	Subject string
}

// DiscoverProfileIdentity fetches a profile URL and resolves the OIDC identity
// that the page explicitly delegates to this bridge.
func DiscoverProfileIdentity(
	ctx context.Context,
	httpClient *http.Client,
	me string,
	allowHTTP bool,
	metadataName string,
	bridgePublicURL string,
	expectedIssuer string,
) (ProfileIdentityBinding, error) {
	profileURL, err := security.ValidateHTTPSURL(me, allowHTTP)
	if err != nil {
		return ProfileIdentityBinding{}, err
	}
	profileURL.Fragment = ""
	if profileURL.Path == "" {
		profileURL.Path = "/"
	}
	if err := validateMetadataFetchTarget(ctx, profileURL, allowHTTP); err != nil {
		return ProfileIdentityBinding{}, err
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	httpClient = profileClientWithRedirectGuard(httpClient, profileURL, allowHTTP)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL.String(), nil)
	if err != nil {
		return ProfileIdentityBinding{}, err
	}
	req.Header.Set("Accept", "text/html")
	resp, err := httpClient.Do(req)
	if err != nil {
		return ProfileIdentityBinding{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ProfileIdentityBinding{}, errors.New("profile page could not be fetched")
	}
	if contentType := strings.ToLower(resp.Header.Get("Content-Type")); contentType != "" && !strings.Contains(contentType, "text/html") {
		return ProfileIdentityBinding{}, errors.New("profile page is not HTML")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, profileMetadataLimit+1))
	if err != nil {
		return ProfileIdentityBinding{}, err
	}
	if len(body) > profileMetadataLimit {
		return ProfileIdentityBinding{}, errors.New("profile page is too large")
	}
	if !pageDelegatesToBridge(body, profileURL, bridgePublicURL) {
		return ProfileIdentityBinding{}, errors.New("profile page does not delegate IndieAuth to this bridge")
	}
	issuer, subject, err := identityMetadataFromHTML(body, metadataName, allowHTTP)
	if err != nil {
		return ProfileIdentityBinding{}, err
	}
	if issuer != expectedIssuer {
		return ProfileIdentityBinding{}, errors.New("profile identity issuer does not match the configured backend")
	}
	canonicalMe, err := security.CanonicalURL(profileURL.String())
	if err != nil {
		return ProfileIdentityBinding{}, err
	}
	return ProfileIdentityBinding{Me: canonicalMe, Issuer: issuer, Subject: subject}, nil
}

func profileClientWithRedirectGuard(base *http.Client, original *url.URL, allowPrivate bool) *http.Client {
	client := *base
	if !allowPrivate {
		var transport *http.Transport
		if configured, ok := base.Transport.(*http.Transport); ok {
			transport = configured.Clone()
		} else {
			transport = http.DefaultTransport.(*http.Transport).Clone()
		}
		transport.Proxy = nil
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, address := range addresses {
				if isUnsafeMetadataIP(address.IP) {
					continue
				}
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, errors.New("profile host has no safe addresses")
		}
		client.Transport = transport
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("too many profile redirects")
		}
		if !security.SameOrigin(original, req.URL) {
			return errors.New("profile redirects must remain on the same origin")
		}
		return validateMetadataFetchTarget(req.Context(), req.URL, allowPrivate)
	}
	return &client
}

func identityMetadataFromHTML(body []byte, metadataName string, allowHTTP bool) (string, string, error) {
	var found []string
	for _, tag := range metaTagRe.FindAll(body, -1) {
		attrs := htmlAttributes(tag)
		if !strings.EqualFold(attrs["name"], metadataName) {
			continue
		}
		if value := strings.TrimSpace(attrs["content"]); value != "" {
			found = append(found, value)
		}
	}
	if len(found) == 0 {
		return "", "", fmt.Errorf("profile page does not contain %q metadata", metadataName)
	}
	if len(found) > 1 {
		return "", "", fmt.Errorf("profile page contains multiple %q metadata tags", metadataName)
	}
	parts := strings.Fields(found[0])
	if len(parts) != 2 {
		return "", "", fmt.Errorf("%q metadata must contain an issuer and subject", metadataName)
	}
	issuerURL, err := security.ValidateHTTPSURL(parts[0], allowHTTP)
	if err != nil {
		return "", "", fmt.Errorf("profile identity issuer: %w", err)
	}
	issuer := issuerURL.String()
	if subject := strings.TrimSpace(parts[1]); subject == "" || len(subject) > 512 {
		return "", "", errors.New("profile identity subject is invalid")
	}
	return issuer, parts[1], nil
}

func pageDelegatesToBridge(body []byte, base *url.URL, bridgePublicURL string) bool {
	bridge := strings.TrimRight(bridgePublicURL, "/")
	wanted := map[string]string{
		"indieauth-metadata":     bridge + "/.well-known/oauth-authorization-server",
		"authorization_endpoint": bridge + "/authorize",
	}
	for _, tag := range profileLinkRe.FindAll(body, -1) {
		attrs := htmlAttributes(tag)
		href := strings.TrimSpace(attrs["href"])
		if href == "" {
			continue
		}
		u, err := url.Parse(href)
		if err != nil {
			continue
		}
		if !u.IsAbs() {
			u = base.ResolveReference(u)
		}
		for rel, endpoint := range wanted {
			if relContains(attrs["rel"], rel) && u.String() == endpoint {
				return true
			}
		}
	}
	return false
}

func htmlAttributes(tag []byte) map[string]string {
	attrs := map[string]string{}
	for _, match := range htmlAttrRe.FindAllSubmatch(tag, -1) {
		value := match[2]
		if len(value) == 0 {
			value = match[3]
		}
		attrs[strings.ToLower(string(match[1]))] = html.UnescapeString(string(value))
	}
	return attrs
}
