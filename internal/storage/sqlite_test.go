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
