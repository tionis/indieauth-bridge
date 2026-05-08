package indieauth

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestValidateClientRedirectWithJSONMetadata(t *testing.T) {
	redirectTarget := httptest.NewServer(http.NotFoundHandler())
	defer redirectTarget.Close()
	client := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"redirect_uris":["` + redirectTarget.URL + `/cb"]}`))
	}))
	defer client.Close()

	err := ValidateClientRedirect(context.Background(), client.Client(), client.URL+"/app", redirectTarget.URL+"/cb", true, true)
	if err != nil {
		t.Fatalf("expected metadata redirect to be accepted: %v", err)
	}
}

func TestValidateClientRedirectWithHTMLMetadata(t *testing.T) {
	redirectTarget := httptest.NewServer(http.NotFoundHandler())
	defer redirectTarget.Close()
	client := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><head><link rel="redirect_uri" href="` + redirectTarget.URL + `/cb"></head></html>`))
	}))
	defer client.Close()

	err := ValidateClientRedirect(context.Background(), client.Client(), client.URL+"/app", redirectTarget.URL+"/cb", true, true)
	if err != nil {
		t.Fatalf("expected HTML metadata redirect to be accepted: %v", err)
	}
}

func TestValidateClientRedirectRejectsUndeclaredMetadata(t *testing.T) {
	client := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"redirect_uris":["` + "http://" + r.Host + `/other"]}`))
	}))
	defer client.Close()

	err := ValidateClientRedirect(context.Background(), client.Client(), client.URL+"/app", "http://other.example/cb", true, true)
	if err == nil {
		t.Fatal("expected undeclared redirect to be rejected")
	}
}

func TestValidateMetadataFetchTargetBlocksPrivateAddresses(t *testing.T) {
	u := mustParseURL(t, "https://127.0.0.1/client")
	if err := validateMetadataFetchTarget(context.Background(), u, false); err == nil {
		t.Fatal("expected private metadata target to be blocked")
	}
	if err := validateMetadataFetchTarget(context.Background(), u, true); err != nil {
		t.Fatalf("dev/private metadata target should be allowed when requested: %v", err)
	}
}

func TestUnsafeMetadataIP(t *testing.T) {
	if !isUnsafeMetadataIP(net.ParseIP("10.0.0.1")) {
		t.Fatal("private IP should be unsafe")
	}
	if !isUnsafeMetadataIP(net.ParseIP("169.254.169.254")) {
		t.Fatal("link-local IP should be unsafe")
	}
	if isUnsafeMetadataIP(net.ParseIP("203.0.113.1")) {
		t.Fatal("documentation public IP should not be treated as unsafe")
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
