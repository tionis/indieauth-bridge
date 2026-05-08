package security

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestRandomTokenUnique(t *testing.T) {
	a, err := RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("tokens should be unique")
	}
	if len(a) < 32 || len(b) < 32 {
		t.Fatal("token format too short")
	}
}

func TestPKCES256(t *testing.T) {
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if !VerifyPKCES256(verifier, challenge) {
		t.Fatal("expected valid verifier")
	}
	if VerifyPKCES256(verifier+"x", challenge) {
		t.Fatal("expected invalid verifier")
	}
}

func TestValidateRedirectURI(t *testing.T) {
	if err := ValidateRedirectURI("https://client.example/app", "https://client.example/callback", false); err != nil {
		t.Fatalf("same origin rejected: %v", err)
	}
	if err := ValidateRedirectURI("https://client.example/app", "https://evil.example/callback", false); err == nil {
		t.Fatal("cross-origin redirect accepted")
	}
	if err := ValidateRedirectURI("http://localhost:8080/app", "http://localhost:8080/callback", false); err == nil {
		t.Fatal("http accepted outside dev mode")
	}
	if err := ValidateRedirectURI("http://localhost:8080/app", "http://localhost:8080/callback", true); err != nil {
		t.Fatalf("http rejected in dev mode: %v", err)
	}
}
