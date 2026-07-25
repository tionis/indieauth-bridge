package indieauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIdentityMetadataFromHTML(t *testing.T) {
	body := []byte(`<meta content="https://auth.example/application/o/indieauth/ stable-subject" name="indieauth-identity">`)
	issuer, subject, err := identityMetadataFromHTML(body, "indieauth-identity", false)
	if err != nil {
		t.Fatal(err)
	}
	if issuer != "https://auth.example/application/o/indieauth/" || subject != "stable-subject" {
		t.Fatalf("unexpected identity metadata: issuer=%q subject=%q", issuer, subject)
	}
}

func TestDiscoverProfileIdentity(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(strings.Join([]string{
			`<link rel="indieauth-metadata" href="http://bridge.example/.well-known/oauth-authorization-server">`,
			`<meta name="indieauth-identity" content="http://auth.example/ auth-sub">`,
		}, "")))
	}))
	defer server.Close()

	binding, err := DiscoverProfileIdentity(
		context.Background(),
		server.Client(),
		server.URL,
		true,
		"indieauth-identity",
		"http://bridge.example",
		"http://auth.example/",
	)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Me != server.URL+"/" || binding.Subject != "auth-sub" {
		t.Fatalf("unexpected binding: %#v", binding)
	}
}

func TestIdentityMetadataRejectsMultipleBindings(t *testing.T) {
	body := []byte(`
<meta name="indieauth-identity" content="https://auth.example/ first">
<meta name="indieauth-identity" content="https://auth.example/ second">
`)
	if _, _, err := identityMetadataFromHTML(body, "indieauth-identity", false); err == nil {
		t.Fatal("expected multiple identity bindings to be rejected")
	}
}
