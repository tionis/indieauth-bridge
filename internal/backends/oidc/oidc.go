package oidc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sync"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/eric/indieauth-bridge/internal/backends"
	"github.com/eric/indieauth-bridge/internal/security"
	"golang.org/x/oauth2"
)

type Config struct {
	Name               string
	Issuer             string
	ClientID           string
	ClientSecret       string
	RedirectURI        string
	Scopes             []string
	InsecureSkipVerify bool
}

type Backend struct {
	mu       sync.Mutex
	name     string
	config   Config
	provider *gooidc.Provider
	verifier *gooidc.IDTokenVerifier
	oauth2   oauth2.Config
}

func New(ctx context.Context, cfg Config) (*Backend, error) {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{gooidc.ScopeOpenID, "profile", "email"}
	}
	if cfg.Name == "" {
		cfg.Name = "oidc"
	}
	return &Backend{
		name:   cfg.Name,
		config: cfg,
	}, nil
}

func (b *Backend) Name() string {
	return b.name
}

func (b *Backend) BeginAuth(ctx context.Context, req backends.AuthRequest) (string, backends.BackendState, error) {
	if err := b.ensureProvider(ctx); err != nil {
		return "", backends.BackendState{}, err
	}
	state, err := security.RandomToken()
	if err != nil {
		return "", backends.BackendState{}, err
	}
	nonce, err := security.RandomToken()
	if err != nil {
		return "", backends.BackendState{}, err
	}
	authURL := b.oauth2.AuthCodeURL(state, gooidc.Nonce(nonce))
	return authURL, backends.BackendState{State: state, Nonce: nonce}, nil
}

func (b *Backend) CompleteAuth(ctx context.Context, callback backends.CallbackRequest, state backends.BackendState) (backends.Identity, error) {
	if err := b.ensureProvider(ctx); err != nil {
		return backends.Identity{}, err
	}
	if errMsg := callback.Query.Get("error"); errMsg != "" {
		return backends.Identity{}, fmt.Errorf("oidc error: %s", errMsg)
	}
	if !security.ConstantTimeEqual(callback.Query.Get("state"), state.State) {
		return backends.Identity{}, errors.New("invalid oidc state")
	}
	code := callback.Query.Get("code")
	if code == "" {
		return backends.Identity{}, errors.New("missing oidc code")
	}
	ctx = contextWithHTTPClient(ctx, b.config.InsecureSkipVerify)
	token, err := b.oauth2.Exchange(ctx, code)
	if err != nil {
		return backends.Identity{}, fmt.Errorf("oidc token exchange failed: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return backends.Identity{}, errors.New("oidc token response missing id_token")
	}
	idToken, err := b.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return backends.Identity{}, fmt.Errorf("oidc id_token verification failed: %w", err)
	}
	if !security.ConstantTimeEqual(idToken.Nonce, state.Nonce) {
		return backends.Identity{}, errors.New("invalid oidc nonce")
	}
	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return backends.Identity{}, err
	}
	if userInfo, err := b.provider.UserInfo(ctx, oauth2.StaticTokenSource(token)); err == nil {
		_ = userInfo.Claims(&claims)
	}
	return identityFromClaims(idToken.Subject, claims), nil
}

func (b *Backend) ensureProvider(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.provider != nil {
		return nil
	}
	ctx = contextWithHTTPClient(ctx, b.config.InsecureSkipVerify)
	provider, err := gooidc.NewProvider(ctx, b.config.Issuer)
	if err != nil {
		return err
	}
	b.provider = provider
	b.verifier = provider.Verifier(&gooidc.Config{ClientID: b.config.ClientID})
	b.oauth2 = oauth2.Config{
		ClientID:     b.config.ClientID,
		ClientSecret: b.config.ClientSecret,
		RedirectURL:  b.config.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       b.config.Scopes,
	}
	return nil
}

func contextWithHTTPClient(ctx context.Context, insecure bool) context.Context {
	if !insecure {
		return ctx
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	return gooidc.ClientContext(ctx, &http.Client{Transport: transport})
}

func identityFromClaims(subject string, claims map[string]any) backends.Identity {
	return backends.Identity{
		Subject:           subject,
		Username:          stringClaim(claims, "username"),
		Email:             stringClaim(claims, "email"),
		EmailVerified:     boolClaim(claims, "email_verified"),
		Name:              stringClaim(claims, "name"),
		PreferredUsername: stringClaim(claims, "preferred_username"),
		Groups:            stringSliceClaim(claims, "groups"),
		RawClaims:         claims,
	}
}

func stringClaim(claims map[string]any, name string) string {
	if v, ok := claims[name].(string); ok {
		return v
	}
	return ""
}

func boolClaim(claims map[string]any, name string) bool {
	if v, ok := claims[name].(bool); ok {
		return v
	}
	return false
}

func stringSliceClaim(claims map[string]any, name string) []string {
	raw, ok := claims[name]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
