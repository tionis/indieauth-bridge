package indieauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverAuthorizationServerFromMetadata(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/profile":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<link rel="indieauth-metadata" href="` + server.URL + `/metadata">`))
		case "/metadata":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "issuer": "` + server.URL + `",
  "authorization_endpoint": "` + server.URL + `/authorize",
  "token_endpoint": "` + server.URL + `/token"
}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	discovered, err := DiscoverAuthorizationServer(
		context.Background(),
		server.Client(),
		server.URL+"/profile",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if discovered.AuthorizationEndpoint != server.URL+"/authorize" ||
		discovered.TokenEndpoint != server.URL+"/token" ||
		discovered.MetadataEndpoint != server.URL+"/metadata" ||
		discovered.Issuer != server.URL {
		t.Fatalf("unexpected discovery result: %#v", discovered)
	}
}

func TestDiscoverAuthorizationServerFromLegacyLinks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`
<link rel="authorization_endpoint" href="/authorize">
<link rel="token_endpoint" href="/token">
`))
	}))
	defer server.Close()

	discovered, err := DiscoverAuthorizationServer(
		context.Background(),
		server.Client(),
		server.URL,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if discovered.AuthorizationEndpoint != server.URL+"/authorize" ||
		discovered.TokenEndpoint != server.URL+"/token" {
		t.Fatalf("unexpected legacy discovery result: %#v", discovered)
	}
}

func TestDiscoverAuthorizationServerAllowsLegacyAuthorizationOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<link rel="authorization_endpoint" href="/authorize">`))
	}))
	defer server.Close()

	discovered, err := DiscoverAuthorizationServer(
		context.Background(),
		server.Client(),
		server.URL,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !discovered.LegacyVerification || discovered.TokenEndpoint != "" {
		t.Fatalf("expected legacy verification mode: %#v", discovered)
	}
}
