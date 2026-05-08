package storage

import (
	"context"
	"errors"
	"time"

	"github.com/eric/indieauth-bridge/internal/backends"
)

var (
	ErrNotFound = errors.New("not found")
	ErrUsed     = errors.New("already used")
	ErrExpired  = errors.New("expired")
)

type AuthRequest struct {
	ID                  string
	Backend             string
	BackendState        backends.BackendState
	Me                  string
	ClientID            string
	RedirectURI         string
	Scope               string
	ClientState         string
	CodeChallenge       string
	CodeChallengeMethod string
	ProfileJSON         []byte
	ExpiresAt           time.Time
	CreatedAt           time.Time
}

type AuthorizationCode struct {
	CodeHash            string
	Me                  string
	ClientID            string
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	ProfileJSON         []byte
	ExpiresAt           time.Time
	CreatedAt           time.Time
}

type AccessToken struct {
	TokenHash   string
	Me          string
	ClientID    string
	Scope       string
	ProfileJSON []byte
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

type Store interface {
	Close() error
	CreateAuthRequest(context.Context, AuthRequest) error
	GetAuthRequestByBackendState(context.Context, string, string) (AuthRequest, error)
	DeleteAuthRequest(context.Context, string) error
	CreateAuthorizationCode(context.Context, string, AuthorizationCode) error
	ConsumeAuthorizationCode(context.Context, string, time.Time) (AuthorizationCode, error)
	CreateAccessToken(context.Context, string, AccessToken) error
	Cleanup(context.Context, time.Time) error
}
