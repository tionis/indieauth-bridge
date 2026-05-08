package bridgehttp

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type rateLimiter struct {
	mu       sync.Mutex
	clients  map[string]*bucket
	rate     float64
	burst    float64
	trusted  []*net.IPNet
	lastTrim time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(requestsPerMinute, burst int, trustedProxies []string) *rateLimiter {
	if requestsPerMinute <= 0 {
		requestsPerMinute = 60
	}
	if burst <= 0 {
		burst = 20
	}
	limiter := &rateLimiter{
		clients: map[string]*bucket{},
		rate:    float64(requestsPerMinute) / 60,
		burst:   float64(burst),
	}
	for _, raw := range trustedProxies {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if ip := net.ParseIP(raw); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			limiter.trusted = append(limiter.trusted, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		if _, network, err := net.ParseCIDR(raw); err == nil {
			limiter.trusted = append(limiter.trusted, network)
		}
	}
	return limiter
}

func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastTrim) > 5*time.Minute {
		for k, b := range l.clients {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.clients, k)
			}
		}
		l.lastTrim = now
	}
	b := l.clients[key]
	if b == nil {
		l.clients[key] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens = minFloat(l.burst, b.tokens+elapsed*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *rateLimiter) clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remoteIP := net.ParseIP(host)
	if remoteIP != nil && l.proxyTrusted(remoteIP) {
		forwarded := r.Header.Get("X-Forwarded-For")
		if forwarded != "" {
			first := strings.TrimSpace(strings.Split(forwarded, ",")[0])
			if ip := net.ParseIP(first); ip != nil {
				return ip.String()
			}
		}
	}
	if remoteIP != nil {
		return remoteIP.String()
	}
	return host
}

func (l *rateLimiter) proxyTrusted(ip net.IP) bool {
	for _, network := range l.trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
