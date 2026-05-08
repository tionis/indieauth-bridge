package indieauth

import (
	"context"
	"net/http"
	"net/http/httptest"
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
