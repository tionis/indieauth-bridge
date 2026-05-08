package backends

import (
	"context"
	"net/url"
)

type AuthRequest struct {
	RequestID string
	Me        string
	Scopes    []string
}

type BackendState struct {
	State  string         `json:"state"`
	Nonce  string         `json:"nonce"`
	Values map[string]any `json:"values,omitempty"`
}

type CallbackRequest struct {
	Query url.Values
}

type Identity struct {
	Subject           string         `json:"subject"`
	Username          string         `json:"username,omitempty"`
	Email             string         `json:"email,omitempty"`
	EmailVerified     bool           `json:"email_verified,omitempty"`
	Name              string         `json:"name,omitempty"`
	PreferredUsername string         `json:"preferred_username,omitempty"`
	Groups            []string       `json:"groups,omitempty"`
	RawClaims         map[string]any `json:"raw_claims,omitempty"`
}

type Backend interface {
	Name() string
	BeginAuth(ctx context.Context, req AuthRequest) (redirectURL string, state BackendState, err error)
	CompleteAuth(ctx context.Context, callback CallbackRequest, state BackendState) (Identity, error)
}
