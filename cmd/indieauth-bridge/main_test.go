package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunHealthcheckAcceptsSuccessfulResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if got := runHealthcheck([]string{"--url", server.URL}); got != 0 {
		t.Fatalf("runHealthcheck() = %d, want 0", got)
	}
}

func TestRunHealthcheckRejectsFailedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	if got := runHealthcheck([]string{"--url", server.URL}); got != 1 {
		t.Fatalf("runHealthcheck() = %d, want 1", got)
	}
}

func TestRunHealthcheckRejectsNonHTTPURL(t *testing.T) {
	if got := runHealthcheck([]string{"--url", "file:///tmp/health"}); got != 2 {
		t.Fatalf("runHealthcheck() = %d, want 2", got)
	}
}
