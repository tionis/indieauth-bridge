package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eric/indieauth-bridge/internal/backends"
)

func TestOIDCBackendWithMockProvider(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	var issuedNonce string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeTestJSON(w, map[string]any{
				"issuer":                                issuer,
				"authorization_endpoint":                issuer + "/authorize",
				"token_endpoint":                        issuer + "/token",
				"jwks_uri":                              issuer + "/keys",
				"userinfo_endpoint":                     issuer + "/userinfo",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			writeTestJSON(w, map[string]any{"keys": []any{jwkFromKey(key)}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			idToken := signTestJWT(t, key, map[string]any{
				"iss":                issuer,
				"aud":                "client-id",
				"sub":                "subject-1",
				"exp":                time.Now().Add(time.Hour).Unix(),
				"iat":                time.Now().Add(-time.Minute).Unix(),
				"nonce":              issuedNonce,
				"preferred_username": "eric",
				"email":              "eric@example.org",
				"email_verified":     true,
				"groups":             []string{"indieauth"},
			})
			writeTestJSON(w, map[string]any{
				"access_token": "access",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     idToken,
			})
		case "/userinfo":
			writeTestJSON(w, map[string]any{
				"name": "Eric",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL

	backend, err := New(context.Background(), Config{
		Name:         "authentik",
		Issuer:       issuer,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://bridge.example/auth/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	redirectURL, state, err := backend.BeginAuth(context.Background(), backends.AuthRequest{RequestID: "req"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("nonce") == "" || parsed.Query().Get("state") != state.State {
		t.Fatalf("missing state/nonce in redirect: %s", redirectURL)
	}
	issuedNonce = parsed.Query().Get("nonce")

	identity, err := backend.CompleteAuth(context.Background(), backends.CallbackRequest{Query: url.Values{
		"state": {state.State},
		"code":  {"oidc-code"},
	}}, state)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "subject-1" || identity.Email != "eric@example.org" || identity.Name != "Eric" {
		t.Fatalf("unexpected identity: %+v", identity)
	}
}

func writeTestJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func jwkFromKey(key *rsa.PrivateKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"kid": "test-key",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func signTestJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": "test-key"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	sum := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join([]string{unsigned, base64.RawURLEncoding.EncodeToString(sig)}, ".")
}
