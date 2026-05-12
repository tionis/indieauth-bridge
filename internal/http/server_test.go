package bridgehttp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eric/indieauth-bridge/internal/backends"
	"github.com/eric/indieauth-bridge/internal/config"
	"github.com/eric/indieauth-bridge/internal/storage"
)

type fakeBackend struct {
	state string
}

func (f fakeBackend) Name() string { return "authentik" }

func (f fakeBackend) BeginAuth(ctx context.Context, req backends.AuthRequest) (string, backends.BackendState, error) {
	return "https://auth.example/authorize?state=" + f.state, backends.BackendState{State: f.state, Nonce: "nonce"}, nil
}

func (f fakeBackend) CompleteAuth(ctx context.Context, callback backends.CallbackRequest, state backends.BackendState) (backends.Identity, error) {
	return backends.Identity{Subject: "auth-sub", PreferredUsername: "eric", Email: "eric@example.org"}, nil
}

func TestMetadata(t *testing.T) {
	app := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["issuer"] != "http://bridge.example" {
		t.Fatalf("unexpected issuer: %v", body["issuer"])
	}
	if body["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("metadata should advertise iss authorization responses: %v", body["authorization_response_iss_parameter_supported"])
	}
}

func TestIndexLandingPage(t *testing.T) {
	app := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "text/html") {
		t.Fatalf("unexpected content type: %s", contentType)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"IndieAuth authorization server",
		"http://bridge.example/authorize",
		"http://bridge.example/token",
		"http://bridge.example/.well-known/oauth-authorization-server",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("landing page missing %q", want)
		}
	}
	for _, leaked := range []string{"client-secret", "change-me", "auth-sub"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("landing page leaked sensitive or mapping value %q", leaked)
		}
	}
}

func TestAuthorizeCallbackAndTokenFlow(t *testing.T) {
	app := newTestServer(t)
	handler := app.Routes()
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	challenge := pkceChallenge(verifier)

	authURL := "/authorize?response_type=code&me=https%3A%2F%2Feric.example%2F&client_id=http%3A%2F%2Fclient.example%2Fapp&redirect_uri=http%3A%2F%2Fclient.example%2Fcallback&state=client-state&scope=profile+email&code_challenge=" + url.QueryEscape(challenge) + "&code_challenge_method=S256"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, authURL, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status = %d body=%s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "https://auth.example/authorize?state=oidc-state" {
		t.Fatalf("unexpected oidc redirect: %s", loc)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?state=oidc-state&code=oidc-code", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d body=%s", rec.Code, rec.Body.String())
	}
	callback, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if callback.Scheme != "http" || callback.Host != "client.example" || callback.Query().Get("state") != "client-state" || callback.Query().Get("iss") != "http://bridge.example" {
		t.Fatalf("unexpected client redirect: %s", callback.String())
	}
	code := callback.Query().Get("code")
	if code == "" {
		t.Fatal("missing IndieAuth code")
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"http://client.example/app"},
		"redirect_uri":  {"http://client.example/callback"},
		"code_verifier": {verifier},
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token status = %d body=%s", rec.Code, rec.Body.String())
	}
	var tokenBody map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tokenBody); err != nil {
		t.Fatal(err)
	}
	if tokenBody["me"] != "https://eric.example/" || tokenBody["token_type"] != "Bearer" || tokenBody["access_token"] == "" {
		t.Fatalf("unexpected token response: %#v", tokenBody)
	}
	accessToken := tokenBody["access_token"].(string)

	form = url.Values{"token": {accessToken}}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("introspect status = %d body=%s", rec.Code, rec.Body.String())
	}
	var introspectBody map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &introspectBody); err != nil {
		t.Fatal(err)
	}
	if introspectBody["active"] != true || introspectBody["me"] != "https://eric.example/" {
		t.Fatalf("unexpected introspection response: %#v", introspectBody)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("post-revoke introspect status = %d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &introspectBody); err != nil {
		t.Fatal(err)
	}
	if introspectBody["active"] != false {
		t.Fatalf("expected inactive token after revoke: %#v", introspectBody)
	}

	rec = httptest.NewRecorder()
	reuseForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"http://client.example/app"},
		"redirect_uri":  {"http://client.example/callback"},
		"code_verifier": {verifier},
	}
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(reuseForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("reused code status = %d", rec.Code)
	}
}

func TestConsentApprovalFlow(t *testing.T) {
	app := newTestServer(t)
	app.cfg.Security.ConsentRequired = true
	handler := app.Routes()
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	challenge := pkceChallenge(verifier)

	authURL := "/authorize?response_type=code&me=https%3A%2F%2Feric.example%2F&client_id=http%3A%2F%2Fclient.example%2Fapp&redirect_uri=http%3A%2F%2Fclient.example%2Fcallback&state=client-state&scope=profile&code_challenge=" + url.QueryEscape(challenge) + "&code_challenge_method=S256"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, authURL, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?state=oidc-state&code=oidc-code", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d body=%s", rec.Code, rec.Body.String())
	}
	consentURL, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	consentID := consentURL.Query().Get("id")
	if consentID == "" || consentURL.Path != "/consent" {
		t.Fatalf("unexpected consent redirect: %s", consentURL.String())
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/consent?id="+url.QueryEscape(consentID), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("consent page status = %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected consent cache-control: %s", rec.Header().Get("Cache-Control"))
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'nonce-") {
		t.Fatalf("consent page CSP should allow only the nonce script, got %q", csp)
	}
	if !strings.Contains(csp, "form-action 'self' http://bridge.example/consent") {
		t.Fatalf("consent page CSP should allow the public consent action, got %q", csp)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `action="http://bridge.example/consent?id=`+consentID+`"`) {
		t.Fatal("consent form should submit to the public consent URL")
	}
	if !strings.Contains(body, "button.disabled = true") {
		t.Fatal("consent form should disable submit buttons after submit")
	}
	csrfToken := hiddenInputValue(t, body, "csrf")
	form := url.Values{
		"csrf":     {csrfToken},
		"decision": {"approve"},
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/consent?id="+url.QueryEscape(consentID), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("consent post status = %d body=%s", rec.Code, rec.Body.String())
	}
	callback, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if callback.Host != "client.example" || callback.Query().Get("code") == "" || callback.Query().Get("state") != "client-state" || callback.Query().Get("iss") != "http://bridge.example" {
		t.Fatalf("unexpected final redirect: %s", callback.String())
	}
}

func TestLegacyIndieAuthAuthorizeAndProfileExchange(t *testing.T) {
	app := newTestServer(t)
	handler := app.Routes()

	authURL := "/authorize?me=https%3A%2F%2Feric.example%2F&scope&client_id=http%3A%2F%2Fclient.example%2Fapp&redirect_uri=http%3A%2F%2Fclient.example%2Fcallback&state=client-state"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, authURL, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?state=oidc-state&code=oidc-code", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d body=%s", rec.Code, rec.Body.String())
	}
	callback, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := callback.Query().Get("code")
	if code == "" || callback.Query().Get("state") != "client-state" || callback.Query().Get("iss") != "http://bridge.example" {
		t.Fatalf("unexpected final redirect: %s", callback.String())
	}

	form := url.Values{
		"code":         {code},
		"client_id":    {"http://client.example/app"},
		"redirect_uri": {"http://client.example/callback"},
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("profile exchange status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["me"] != "https://eric.example/" || body["access_token"] != nil {
		t.Fatalf("unexpected profile exchange response: %#v", body)
	}
}

func TestLegacyIndieAuthCodeCannotUseTokenEndpointWhenPKCERequired(t *testing.T) {
	app := newTestServer(t)
	handler := app.Routes()

	authURL := "/authorize?me=https%3A%2F%2Feric.example%2F&scope&client_id=http%3A%2F%2Fclient.example%2Fapp&redirect_uri=http%3A%2F%2Fclient.example%2Fcallback&state=client-state"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, authURL, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?state=oidc-state&code=oidc-code", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d body=%s", rec.Code, rec.Body.String())
	}
	callback, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {callback.Query().Get("code")},
		"client_id":    {"http://client.example/app"},
		"redirect_uri": {"http://client.example/callback"},
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("token status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestConsentInvalidCSRFDoesNotConsumeRequest(t *testing.T) {
	app := newTestServer(t)
	app.cfg.Security.ConsentRequired = true
	handler := app.Routes()
	consentID := createConsentRequest(t, app)

	form := url.Values{
		"id":       {consentID},
		"csrf":     {"wrong"},
		"decision": {"approve"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid csrf status = %d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := app.store.GetConsentRequest(context.Background(), consentID, time.Now()); err != nil {
		t.Fatalf("consent request should remain after invalid csrf: %v", err)
	}
}

func TestAuthorizeRejectsInvalidRedirect(t *testing.T) {
	app := newTestServer(t)
	challenge := pkceChallenge("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
	authURL := "/authorize?response_type=code&me=https%3A%2F%2Feric.example%2F&client_id=http%3A%2F%2Fclient.example%2Fapp&redirect_uri=http%3A%2F%2Fevil.example%2Fcallback&state=client-state&code_challenge=" + url.QueryEscape(challenge) + "&code_challenge_method=S256"
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, authURL, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestTokenRejectsBadPKCE(t *testing.T) {
	app := newTestServer(t)
	now := time.Now()
	code := "manual-code"
	challenge := pkceChallenge("correct-verifier-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	err := app.store.CreateAuthorizationCode(context.Background(), code, storage.AuthorizationCode{
		Me:                  "https://eric.example/",
		ClientID:            "http://client.example/app",
		RedirectURI:         "http://client.example/callback",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(time.Minute),
		CreatedAt:           now,
	})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"http://client.example/app"},
		"redirect_uri":  {"http://client.example/callback"},
		"code_verifier": {"wrong"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := config.Default()
	cfg.Server.PublicURL = "http://bridge.example"
	cfg.Server.Issuer = "http://bridge.example"
	cfg.Security.CookieSecret = "change-me"
	cfg.Security.DevMode = true
	cfg.Security.ConsentRequired = false
	cfg.Security.ClientMetadataDiscoveryEnabled = false
	cfg.RateLimit.Enabled = false
	cfg.Profiles = []config.ProfileConfig{{
		Me:              "https://eric.example/",
		DisplayName:     "Eric",
		Email:           "eric@example.org",
		Backend:         "authentik",
		AllowedSubjects: []string{"auth-sub"},
	}}
	cfg.Backends = map[string]config.BackendConfig{"authentik": {
		Type: "authentik", Issuer: "http://auth.example/", ClientID: "id", ClientSecret: "secret", RedirectURI: "http://bridge.example/auth/callback",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	store, err := storage.OpenSQLite(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	app := NewServer(cfg, store, map[string]backends.Backend{"authentik": fakeBackend{state: "oidc-state"}}, slog.New(slog.NewTextHandler(testWriter{t}, nil)))
	app.now = time.Now
	return app
}

func createConsentRequest(t *testing.T, app *Server) string {
	t.Helper()
	now := time.Now()
	consentID := "consent-id"
	if err := app.store.CreateConsentRequest(context.Background(), storage.ConsentRequest{
		ID:          consentID,
		CSRFToken:   "csrf-token",
		Me:          "https://eric.example/",
		ClientID:    "http://client.example/app",
		RedirectURI: "http://client.example/callback",
		Scope:       "profile",
		ClientState: "client-state",
		Subject:     "auth-sub",
		ExpiresAt:   now.Add(time.Minute),
		CreatedAt:   now,
	}); err != nil {
		t.Fatal(err)
	}
	return consentID
}

func hiddenInputValue(t *testing.T, body, name string) string {
	t.Helper()
	needle := `name="` + name + `" value="`
	start := strings.Index(body, needle)
	if start == -1 {
		t.Fatalf("hidden input %q not found in body", name)
	}
	start += len(needle)
	end := strings.Index(body[start:], `"`)
	if end == -1 {
		t.Fatalf("hidden input %q value is unterminated", name)
	}
	return body[start : start+end]
}

type testWriter struct {
	t *testing.T
}

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
