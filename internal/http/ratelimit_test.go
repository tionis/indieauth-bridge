package bridgehttp

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	limiter := newRateLimiter(60, 2, nil)
	now := time.Now()
	if !limiter.allow("client", now) {
		t.Fatal("first request should be allowed")
	}
	if !limiter.allow("client", now) {
		t.Fatal("second request should be allowed")
	}
	if limiter.allow("client", now) {
		t.Fatal("third request should be limited")
	}
	if !limiter.allow("client", now.Add(time.Second)) {
		t.Fatal("request should be allowed after token refill")
	}
}

func TestRateLimiterTrustedProxy(t *testing.T) {
	limiter := newRateLimiter(60, 2, []string{"192.0.2.10"})
	req := httptest.NewRequest("GET", "/authorize", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.1, 192.0.2.10")
	if got := limiter.clientKey(req); got != "198.51.100.1" {
		t.Fatalf("client key = %q", got)
	}
}
