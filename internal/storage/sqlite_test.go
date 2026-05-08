package storage

import (
	"context"
	"testing"
	"time"

	"github.com/eric/indieauth-bridge/internal/backends"
)

func TestAuthorizationCodeOneUseAndExpiry(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLite(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now()
	code := "code"
	err = store.CreateAuthorizationCode(ctx, code, AuthorizationCode{
		Me:                  "https://eric.example/",
		ClientID:            "https://client.example/",
		RedirectURI:         "https://client.example/callback",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(time.Minute),
		CreatedAt:           now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeAuthorizationCode(ctx, code, now); err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	if _, err := store.ConsumeAuthorizationCode(ctx, code, now); err != ErrUsed {
		t.Fatalf("expected used error, got %v", err)
	}
	expired := "expired"
	if err := store.CreateAuthorizationCode(ctx, expired, AuthorizationCode{ExpiresAt: now.Add(-time.Second), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeAuthorizationCode(ctx, expired, now); err != ErrExpired {
		t.Fatalf("expected expired error, got %v", err)
	}
}

func TestAuthRequestByBackendState(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLite(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now()
	err = store.CreateAuthRequest(ctx, AuthRequest{
		ID:           "req",
		Backend:      "authentik",
		BackendState: backends.BackendState{State: "oidc-state", Nonce: "nonce"},
		Me:           "https://eric.example/",
		ClientID:     "https://client.example/",
		RedirectURI:  "https://client.example/callback",
		ExpiresAt:    now.Add(time.Minute),
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.GetAuthRequestByBackendState(ctx, "authentik", "oidc-state")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "req" || got.BackendState.Nonce != "nonce" {
		t.Fatalf("unexpected request: %+v", got)
	}
}

func TestAccessTokenLookupAndRevoke(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLite(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now()
	token := "access-token"
	if err := store.CreateAccessToken(ctx, token, AccessToken{
		Me:        "https://eric.example/",
		ClientID:  "https://client.example/",
		Scope:     "profile",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetAccessToken(ctx, token, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Me != "https://eric.example/" || got.TokenHash == token {
		t.Fatalf("unexpected token record: %+v", got)
	}
	if err := store.RevokeAccessToken(ctx, token, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAccessToken(ctx, token, now); err != ErrRevoked {
		t.Fatalf("expected revoked token, got %v", err)
	}
}

func TestConsentRequestExpiry(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLite(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now()
	if err := store.CreateConsentRequest(ctx, ConsentRequest{
		ID:          "consent",
		CSRFToken:   "csrf",
		Me:          "https://eric.example/",
		ClientID:    "https://client.example/",
		RedirectURI: "https://client.example/callback",
		Subject:     "sub",
		ExpiresAt:   now.Add(time.Minute),
		CreatedAt:   now,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetConsentRequest(ctx, "consent", now)
	if err != nil {
		t.Fatal(err)
	}
	if got.CSRFToken != "csrf" {
		t.Fatalf("unexpected consent request: %+v", got)
	}
	if _, err := store.GetConsentRequest(ctx, "consent", now.Add(2*time.Minute)); err != ErrExpired {
		t.Fatalf("expected expired consent request, got %v", err)
	}
}

func TestSchemaMigrationsRecorded(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLite(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var count int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count < 2 {
		t.Fatalf("expected migrations to be recorded, got %d", count)
	}
}
