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
		"Connect a profile",
		"Test a login",
		"Server details",
		"http://bridge.example/authorize",
		"http://bridge.example/token",
		"http://bridge.example/.well-known/oauth-authorization-server",
		"http://bridge.example/test",
		"http://bridge.example/health",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("landing page missing %q", want)
		}
	}
	for _, obsolete := range []string{"Static profiles", "Backends"} {
		if strings.Contains(body, obsolete) {
			t.Fatalf("landing page still contains obsolete detail %q", obsolete)
		}
	}
	for _, leaked := range []string{"client-secret", "change-me", "auth-sub"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("landing page leaked sensitive or mapping value %q", leaked)
		}
	}
}

func TestHumanReadableHealthPage(t *testing.T) {
	app := newTestServer(t)
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("health page status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IndieAuth bridge is responding") {
		t.Fatalf("health page does not show a visible result: %s", rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("health page should not be cached, got %q", rec.Header().Get("Cache-Control"))
	}

	rec = httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("machine health endpoint status=%d", rec.Code)
	}
}

func TestThemeToggleAssetsAndPolicy(t *testing.T) {
	app := newTestServer(t)
	handler := app.Routes()
	for _, path := range []string{"/", "/health", "/test"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `<script src="/theme.js"></script>`) {
			t.Fatalf("%s does not load the theme control", path)
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self'") {
			t.Fatalf("%s CSP does not allow the same-origin theme script: %q", path, rec.Header().Get("Content-Security-Policy"))
		}
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/theme.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("theme script status=%d", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "text/javascript") {
		t.Fatalf("unexpected theme script content type: %q", contentType)
	}
	for _, want := range []string{
		`["system", "light", "dark"]`,
		"prefers-color-scheme: dark",
		"localStorage",
		`aria-label", "Color theme`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("theme script missing %q", want)
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

func TestDynamicProfileAuthorizeAndCallback(t *testing.T) {
	app := newTestServer(t)
	app.cfg.Profiles = nil
	app.cfg.DynamicProfiles.Enabled = true
	app.cfg.DynamicProfiles.Backend = "authentik"

	profileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`
<link rel="indieauth-metadata" href="http://bridge.example/.well-known/oauth-authorization-server">
<meta name="indieauth-identity" content="http://auth.example/ auth-sub">
`))
	}))
	defer profileServer.Close()
	app.httpClient = profileServer.Client()

	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	authURL := "/authorize?response_type=code&me=" + url.QueryEscape(profileServer.URL) +
		"&client_id=http%3A%2F%2Fclient.example%2Fapp&redirect_uri=http%3A%2F%2Fclient.example%2Fcallback" +
		"&state=client-state&scope=profile&code_challenge=" + url.QueryEscape(pkceChallenge(verifier)) +
		"&code_challenge_method=S256"
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, authURL, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?state=oidc-state&code=oidc-code", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d body=%s", rec.Code, rec.Body.String())
	}
	callback, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if callback.Query().Get("code") == "" {
		t.Fatalf("dynamic profile callback did not issue a code: %s", callback.String())
	}
}

func TestSetupReturnsAuthenticatedMetadataTag(t *testing.T) {
	app := newTestServer(t)
	app.cfg.DynamicProfiles.Enabled = true
	app.cfg.DynamicProfiles.Backend = "authentik"
	app.cfg.ManagedProfiles.Enabled = true
	app.cfg.ManagedProfiles.Backend = "authentik"
	handler := app.Routes()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/setup", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("setup status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?state=oidc-state&code=oidc-code", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("setup callback status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "http://auth.example/ auth-sub") {
		t.Fatalf("setup page does not contain identity metadata: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "http://bridge.example/@eric") {
		t.Fatalf("setup page does not contain hosted profile: %s", rec.Body.String())
	}
	for _, fragment := range []string{
		`rel=&#34;indieauth-metadata&#34;`,
		`rel=&#34;authorization_endpoint&#34;`,
		`rel=&#34;token_endpoint&#34;`,
		`name="identity_token"`,
		`Check profile`,
		`embedded IndieAuth tester`,
	} {
		if !strings.Contains(rec.Body.String(), fragment) {
			t.Fatalf("setup page missing %q: %s", fragment, rec.Body.String())
		}
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("setup response should not be cached")
	}

	rec = httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/@eric", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("managed profile status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{
		`class="h-card"`,
		`rel="indieauth-metadata"`,
		`http://bridge.example/@eric`,
		`Test this login`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("managed profile missing %q: %s", want, rec.Body.String())
		}
	}
	if strings.Contains(rec.Body.String(), "auth-sub") {
		t.Fatal("managed profile must not expose the Authentik subject")
	}
}

func TestManagedProfileAuthorizeUsesStoredImmutableBinding(t *testing.T) {
	app := newTestServer(t)
	app.cfg.ManagedProfiles.Enabled = true
	app.cfg.ManagedProfiles.Backend = "authentik"
	now := time.Now()
	if err := app.store.CreateManagedProfile(context.Background(), storage.ManagedProfile{
		Handle: "eric", Issuer: "http://auth.example/", Subject: "auth-sub",
		DisplayName: "Eric", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	authURL := "/authorize?response_type=code&me=http%3A%2F%2Fbridge.example%2F%40eric&client_id=http%3A%2F%2Fclient.example%2Fapp&redirect_uri=http%3A%2F%2Fclient.example%2Fcallback&state=client-state&scope=profile&code_challenge=" +
		url.QueryEscape(pkceChallenge(verifier)) + "&code_challenge_method=S256"
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, authURL, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?state=oidc-state&code=oidc-code", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status=%d body=%s", rec.Code, rec.Body.String())
	}
	callback, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if callback.Query().Get("code") == "" || callback.Query().Get("state") != "client-state" {
		t.Fatalf("unexpected callback: %s", callback.String())
	}
}

func TestManagedProfileHandleNormalizationAndCollision(t *testing.T) {
	if got := normalizeManagedHandle("  Eric Wéndland  "); got != "eric-w-ndland" {
		t.Fatalf("unexpected normalized handle: %q", got)
	}
	app := newTestServer(t)
	app.cfg.ManagedProfiles.Enabled = true
	app.cfg.ManagedProfiles.Backend = "authentik"
	first, err := app.ensureManagedProfile(context.Background(), backends.Identity{
		Subject: "first", PreferredUsername: "Eric", Name: "First Eric",
	}, "http://auth.example/")
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.ensureManagedProfile(context.Background(), backends.Identity{
		Subject: "second", PreferredUsername: "Eric", Name: "Second Eric",
	}, "http://auth.example/")
	if err != nil {
		t.Fatal(err)
	}
	if first.Handle != "eric" || second.Handle == "eric" || !strings.HasPrefix(second.Handle, "eric-") {
		t.Fatalf("unexpected collision handles: first=%q second=%q", first.Handle, second.Handle)
	}
	renamed, err := app.ensureManagedProfile(context.Background(), backends.Identity{
		Subject: "first", PreferredUsername: "renamed", Name: "First Eric",
	}, "http://auth.example/")
	if err != nil {
		t.Fatal(err)
	}
	if renamed.Handle != "eric" {
		t.Fatalf("username change must not change identity URL: %q", renamed.Handle)
	}
}

func TestSetupCheckValidatesAuthenticatedProfileBinding(t *testing.T) {
	app := newTestServer(t)
	app.cfg.DynamicProfiles.Enabled = true
	app.cfg.DynamicProfiles.Backend = "authentik"
	identityToken, err := app.sealSetupIdentity("http://auth.example/", "auth-sub")
	if err != nil {
		t.Fatal(err)
	}
	profileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`
<link rel="indieauth-metadata" href="http://bridge.example/.well-known/oauth-authorization-server">
<meta name="indieauth-identity" content="http://auth.example/ auth-sub">
`))
	}))
	defer profileServer.Close()
	app.httpClient = profileServer.Client()
	form := url.Values{
		"me":             {profileServer.URL},
		"identity_token": {identityToken},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/setup/check", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Profile is ready") {
		t.Fatalf("profile check failed: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestEmbeddedIndieAuthClientFlow(t *testing.T) {
	app := newTestServer(t)
	var challenge string
	var bridgeServer *httptest.Server
	bridgeHandler := app.Routes()
	bridgeServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/profile":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`
<link rel="indieauth-metadata" href="` + bridgeServer.URL + `/as/metadata">
`))
		case "/as/metadata":
			writeJSON(w, http.StatusOK, map[string]string{
				"issuer":                 bridgeServer.URL,
				"authorization_endpoint": bridgeServer.URL + "/as/authorize",
				"token_endpoint":         bridgeServer.URL + "/as/token",
			})
		case "/as/token":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
				http.Error(w, "bad verifier", http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token": "test-access-token",
				"me":           bridgeServer.URL + "/profile",
				"profile":      map[string]string{"name": "Test User"},
				"scope":        "profile email",
				"token_type":   "Bearer",
			})
		default:
			bridgeHandler.ServeHTTP(w, r)
		}
	}))
	defer bridgeServer.Close()
	app.cfg.Server.PublicURL = bridgeServer.URL
	app.cfg.Server.Issuer = bridgeServer.URL
	app.httpClient = bridgeServer.Client()

	rec := httptest.NewRecorder()
	form := url.Values{"me": {bridgeServer.URL + "/profile"}}
	req := httptest.NewRequest(http.MethodPost, "/test/start", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("test start status=%d body=%s", rec.Code, rec.Body.String())
	}
	authorizationURL, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	challenge = authorizationURL.Query().Get("code_challenge")
	if authorizationURL.Path != "/as/authorize" || challenge == "" {
		t.Fatalf("unexpected authorization redirect: %s", authorizationURL.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("test client did not set state cookie")
	}

	callbackURL := "/test/callback?code=test-code&state=" +
		url.QueryEscape(authorizationURL.Query().Get("state")) +
		"&iss=" + url.QueryEscape(bridgeServer.URL)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(cookies[0])
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("test callback status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{"IndieAuth test completed", "test-access-token", "Test User"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("test result missing %q: %s", want, rec.Body.String())
		}
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("test result must not be cached")
	}
}

func TestEmbeddedIndieAuthClientAllowsDiscoveredAuthorizationRedirect(t *testing.T) {
	app := newTestServer(t)
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/test", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("test page status=%d body=%s", rec.Code, rec.Body.String())
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "form-action") {
		t.Fatalf("test page CSP must allow redirects to discovered authorization servers, got %q", csp)
	}
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("test page CSP lost baseline protections: %q", csp)
	}
}

func TestEmbeddedIndieAuthClientLegacyVerification(t *testing.T) {
	app := newTestServer(t)
	var bridgeServer *httptest.Server
	bridgeHandler := app.Routes()
	bridgeServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/profile":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<link rel="authorization_endpoint" href="` + bridgeServer.URL + `/legacy-authorize">`))
		case "/legacy-authorize":
			if r.Method != http.MethodPost {
				http.Error(w, "expected legacy verification POST", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			_, _ = w.Write([]byte(url.Values{
				"me":      {bridgeServer.URL + "/profile"},
				"profile": {`{"name":"Legacy User"}`},
			}.Encode()))
		default:
			bridgeHandler.ServeHTTP(w, r)
		}
	}))
	defer bridgeServer.Close()
	app.cfg.Server.PublicURL = bridgeServer.URL
	app.cfg.Server.Issuer = bridgeServer.URL
	app.httpClient = bridgeServer.Client()

	form := url.Values{"me": {bridgeServer.URL + "/profile"}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test/start", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("legacy test start status=%d body=%s", rec.Code, rec.Body.String())
	}
	authorizationURL, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if authorizationURL.Query().Get("code_challenge") != "" || authorizationURL.Query().Get("response_type") != "" {
		t.Fatalf("legacy request should not include modern parameters: %s", authorizationURL.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("test client did not set state cookie")
	}

	rec = httptest.NewRecorder()
	callbackURL := "/test/callback?code=legacy-code&state=" + url.QueryEscape(authorizationURL.Query().Get("state"))
	req = httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(cookies[0])
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy callback status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{"IndieAuth test completed", "Legacy verification response", "Legacy User"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("legacy test result missing %q: %s", want, rec.Body.String())
		}
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
	if strings.Contains(csp, "form-action") {
		t.Fatalf("consent page CSP should not restrict form redirects, got %q", csp)
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
