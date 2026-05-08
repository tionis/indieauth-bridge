package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

const tokenBytes = 32

func RandomToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func ConstantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func VerifyPKCES256(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	return ConstantTimeEqual(expected, challenge)
}

func ValidateCodeChallenge(challenge, method string) error {
	if challenge == "" {
		return errors.New("code_challenge is required")
	}
	if method != "S256" {
		return errors.New("code_challenge_method must be S256")
	}
	if len(challenge) < 43 || len(challenge) > 128 {
		return errors.New("code_challenge length is invalid")
	}
	for _, r := range challenge {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_' || r == '~' {
			continue
		}
		return errors.New("code_challenge contains invalid characters")
	}
	return nil
}

func CanonicalURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("url must be absolute")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

func ValidateHTTPSURL(raw string, allowHTTP bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("url must be absolute")
	}
	if u.User != nil {
		return nil, errors.New("url must not include userinfo")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return nil, errors.New("http is only allowed in dev mode")
		}
	default:
		return nil, errors.New("url must use https")
	}
	if host := u.Hostname(); host == "" || strings.ContainsAny(host, " \t\r\n") {
		return nil, errors.New("url host is invalid")
	}
	return u, nil
}

func SameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(normalizedHostPort(a), normalizedHostPort(b))
}

func ValidateRedirectURI(clientID, redirectURI string, allowHTTP bool) error {
	client, err := ValidateHTTPSURL(clientID, allowHTTP)
	if err != nil {
		return fmt.Errorf("client_id: %w", err)
	}
	redirect, err := ValidateHTTPSURL(redirectURI, allowHTTP)
	if err != nil {
		return fmt.Errorf("redirect_uri: %w", err)
	}
	if redirect.Fragment != "" {
		return errors.New("redirect_uri must not contain a fragment")
	}
	if !SameOrigin(client, redirect) {
		return errors.New("redirect_uri must have the same origin as client_id")
	}
	return nil
}

func normalizedHostPort(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else if u.Scheme == "http" {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port)
}
