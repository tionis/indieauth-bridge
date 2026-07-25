package indieauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eric/indieauth-bridge/internal/security"
)

const authorizationMetadataLimit = 128 * 1024

type AuthorizationServer struct {
	Me                    string
	MetadataEndpoint      string
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	LegacyVerification    bool
}

type authorizationServerMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func DiscoverAuthorizationServer(
	ctx context.Context,
	httpClient *http.Client,
	me string,
	allowHTTP bool,
) (AuthorizationServer, error) {
	profileURL, err := security.ValidateHTTPSURL(me, allowHTTP)
	if err != nil {
		return AuthorizationServer{}, err
	}
	profileURL.Fragment = ""
	if profileURL.Path == "" {
		profileURL.Path = "/"
	}
	client, err := SafeHTTPClient(ctx, httpClient, profileURL, allowHTTP, true)
	if err != nil {
		return AuthorizationServer{}, err
	}
	body, err := fetchLimited(ctx, client, profileURL.String(), "text/html", profileMetadataLimit)
	if err != nil {
		return AuthorizationServer{}, err
	}
	links := linksFromHTML(body, profileURL)
	server := AuthorizationServer{
		Me:                    profileURL.String(),
		MetadataEndpoint:      firstLink(links["indieauth-metadata"]),
		AuthorizationEndpoint: firstLink(links["authorization_endpoint"]),
		TokenEndpoint:         firstLink(links["token_endpoint"]),
	}
	if server.MetadataEndpoint != "" {
		metadataURL, err := security.ValidateHTTPSURL(server.MetadataEndpoint, allowHTTP)
		if err != nil {
			return AuthorizationServer{}, errors.New("invalid IndieAuth metadata endpoint")
		}
		metadataClient, err := SafeHTTPClient(ctx, httpClient, metadataURL, allowHTTP, true)
		if err != nil {
			return AuthorizationServer{}, err
		}
		metadataBody, err := fetchLimited(
			ctx,
			metadataClient,
			metadataURL.String(),
			"application/json",
			authorizationMetadataLimit,
		)
		if err != nil {
			return AuthorizationServer{}, err
		}
		var metadata authorizationServerMetadata
		if err := json.Unmarshal(metadataBody, &metadata); err != nil {
			return AuthorizationServer{}, errors.New("IndieAuth metadata is not valid JSON")
		}
		server.Issuer = metadata.Issuer
		server.AuthorizationEndpoint = metadata.AuthorizationEndpoint
		server.TokenEndpoint = metadata.TokenEndpoint
	}
	if server.AuthorizationEndpoint == "" {
		return AuthorizationServer{}, errors.New("profile did not advertise an authorization endpoint")
	}
	if server.Issuer != "" {
		issuer, err := security.ValidateHTTPSURL(server.Issuer, allowHTTP)
		if err != nil || issuer.Fragment != "" {
			return AuthorizationServer{}, errors.New("invalid authorization server issuer")
		}
		server.Issuer = issuer.String()
	}
	if err := validateDiscoveredEndpoint(ctx, server.AuthorizationEndpoint, allowHTTP); err != nil {
		return AuthorizationServer{}, errors.New("invalid authorization endpoint")
	}
	if server.TokenEndpoint != "" {
		if err := validateDiscoveredEndpoint(ctx, server.TokenEndpoint, allowHTTP); err != nil {
			return AuthorizationServer{}, errors.New("invalid token endpoint")
		}
	} else {
		server.LegacyVerification = true
	}
	canonicalMe, err := security.CanonicalURL(profileURL.String())
	if err != nil {
		return AuthorizationServer{}, err
	}
	server.Me = canonicalMe
	return server, nil
}

func validateDiscoveredEndpoint(ctx context.Context, raw string, allowHTTP bool) error {
	u, err := security.ValidateHTTPSURL(raw, allowHTTP)
	if err != nil {
		return err
	}
	if u.Fragment != "" {
		return errors.New("endpoint must not contain a fragment")
	}
	return validateMetadataFetchTarget(ctx, u, allowHTTP)
}

func fetchLimited(
	ctx context.Context,
	client *http.Client,
	rawURL string,
	accept string,
	limit int64,
) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("metadata could not be fetched")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("metadata response is too large")
	}
	return body, nil
}

func linksFromHTML(body []byte, base *url.URL) map[string][]string {
	out := map[string][]string{}
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
		for _, rel := range strings.Fields(attrs["rel"]) {
			key := strings.ToLower(rel)
			out[key] = append(out[key], u.String())
		}
	}
	return out
}

func firstLink(links []string) string {
	if len(links) == 0 {
		return ""
	}
	return links[0]
}
