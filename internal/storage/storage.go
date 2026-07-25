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
	ErrRevoked  = errors.New("revoked")
	ErrConflict = errors.New("conflict")
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
	RevokedAt   *time.Time
}

type ConsentRequest struct {
	ID                  string
	CSRFToken           string
	Me                  string
	ClientID            string
	RedirectURI         string
	Scope               string
	ClientState         string
	CodeChallenge       string
	CodeChallengeMethod string
	ProfileJSON         []byte
	Subject             string
	ExpiresAt           time.Time
	CreatedAt           time.Time
}

type AuditEvent struct {
	EventType string
	Subject   string
	Me        string
	ClientID  string
	CreatedAt time.Time
}

type ManagedProfile struct {
	Handle      string
	Issuer      string
	Subject     string
	DisplayName string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Store interface {
	Close() error
	CreateAuthRequest(context.Context, AuthRequest) error
	GetAuthRequestByBackendState(context.Context, string, string) (AuthRequest, error)
	DeleteAuthRequest(context.Context, string) error
	CreateAuthorizationCode(context.Context, string, AuthorizationCode) error
	ConsumeAuthorizationCode(context.Context, string, time.Time) (AuthorizationCode, error)
	CreateAccessToken(context.Context, string, AccessToken) error
	GetAccessToken(context.Context, string, time.Time) (AccessToken, error)
	RevokeAccessToken(context.Context, string, time.Time) error
	CreateConsentRequest(context.Context, ConsentRequest) error
	GetConsentRequest(context.Context, string, time.Time) (ConsentRequest, error)
	DeleteConsentRequest(context.Context, string) error
	CreateAuditEvent(context.Context, AuditEvent) error
	CreateManagedProfile(context.Context, ManagedProfile) error
	GetManagedProfileByHandle(context.Context, string) (ManagedProfile, error)
	GetManagedProfileByIdentity(context.Context, string, string) (ManagedProfile, error)
	UpdateManagedProfile(context.Context, ManagedProfile) error
	Cleanup(context.Context, time.Time) error
}
