package bridgehttp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eric/indieauth-bridge/internal/indieauth"
	"github.com/eric/indieauth-bridge/internal/security"
)

const (
	testClientCookieName = "iab_test_client"
	testClientBodyLimit  = 256 * 1024
)

type setupIdentityState struct {
	Issuer    string `json:"issuer"`
	Subject   string `json:"subject"`
	ExpiresAt int64  `json:"expires_at"`
}

type testClientState struct {
	State                 string `json:"state"`
	Me                    string `json:"me"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	AuthorizationIssuer   string `json:"authorization_issuer,omitempty"`
	TokenEndpoint         string `json:"token_endpoint"`
	CodeVerifier          string `json:"code_verifier"`
	LegacyVerification    bool   `json:"legacy_verification,omitempty"`
	ExpiresAt             int64  `json:"expires_at"`
}

var setupCheckTemplate = template.Must(template.New("setup-check").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IndieAuth Profile Check</title>
  <style>
    :root { color-scheme: light; --bg: #f7f8f5; --surface: #fff; --ink: #1b1f23; --muted: #5f6b76; --line: #d9dfdf; --ok: #047857; --error: #b42318; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--ink); font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.5; }
    main { width: min(720px, calc(100% - 28px)); padding: 32px 0; }
    .card { padding: 22px; border: 1px solid var(--line); border-radius: 10px; background: var(--surface); }
    h1 { margin-top: 0; }
    .ok { color: var(--ok); } .error { color: var(--error); }
    code { overflow-wrap: anywhere; }
    a { color: inherit; font-weight: 700; }
  </style>
</head>
<body>
  <main>
    <div class="card">
      {{if .Valid}}
      <h1 class="ok">Profile is ready</h1>
      <p><code>{{.Me}}</code> delegates to this bridge and is linked to the Authentik account used during setup.</p>
      {{else}}
      <h1 class="error">Profile is not ready</h1>
      <p><code>{{.Me}}</code> could not be validated.</p>
      <p>{{.Error}}</p>
      {{end}}
      <p><a href="{{.SetupURL}}">Return to setup</a> · <a href="{{.TestURL}}">Test an IndieAuth login</a></p>
    </div>
  </main>
</body>
</html>`))

var testClientTemplate = template.Must(template.New("test-client").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="redirect_uri" href="{{.RedirectURI}}">
  <title>IndieAuth Login Tester</title>
  <style>
    :root { color-scheme: light; --bg: #f7f8f5; --surface: #fff; --ink: #1b1f23; --muted: #5f6b76; --line: #d9dfdf; --accent: #0f766e; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--ink); font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.5; }
    main { width: min(720px, calc(100% - 28px)); padding: 32px 0; }
    .card { padding: 24px; border: 1px solid var(--line); border-radius: 10px; background: var(--surface); }
    h1 { margin: 0 0 10px; } p { color: var(--muted); }
    label { display: block; margin-bottom: 7px; font-weight: 700; }
    .row { display: flex; gap: 10px; }
    input { flex: 1; min-width: 0; padding: 11px 12px; border: 1px solid var(--line); border-radius: 7px; font: inherit; }
    button { padding: 11px 16px; border: 1px solid var(--accent); border-radius: 7px; background: var(--accent); color: #fff; font: inherit; font-weight: 700; cursor: pointer; }
    a { color: var(--accent); font-weight: 700; }
    @media (max-width: 600px) { .row { flex-direction: column; } }
  </style>
</head>
<body>
  <main>
    <div class="card">
      <h1>Test an IndieAuth login</h1>
      <p>This is a real, generic IndieAuth client. It discovers endpoints from the profile URL, uses authorization code flow with PKCE, and displays the returned data once. Tokens are not retained.</p>
      <form method="post" action="{{.StartURL}}">
        <label for="me">Profile URL</label>
        <div class="row">
          <input id="me" name="me" type="url" inputmode="url" placeholder="https://example.com/" required>
          <button type="submit">Start login</button>
        </div>
      </form>
      <p><a href="{{.SetupURL}}">Set up a profile</a> · <a href="{{.HomeURL}}">Bridge status</a></p>
    </div>
  </main>
</body>
</html>`))

var testResultTemplate = template.Must(template.New("test-result").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IndieAuth Test Result</title>
  <style>
    :root { color-scheme: light; --bg: #f7f8f5; --surface: #fff; --ink: #1b1f23; --muted: #5f6b76; --line: #d9dfdf; --accent: #0f766e; --error: #b42318; }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--ink); font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.5; }
    main { width: min(900px, calc(100% - 28px)); margin: 0 auto; padding: 32px 0; }
    section { margin: 16px 0; padding: 20px; border: 1px solid var(--line); border-radius: 10px; background: var(--surface); }
    h1, h2 { margin-top: 0; } p { color: var(--muted); }
    pre { overflow: auto; padding: 14px; border-radius: 7px; background: #111827; color: #f9fafb; white-space: pre-wrap; word-break: break-word; }
    .error { color: var(--error); } a { color: var(--accent); font-weight: 700; }
  </style>
</head>
<body>
  <main>
    {{if .Error}}
    <h1 class="error">IndieAuth test failed</h1>
    <section><p>{{.Error}}</p></section>
    {{else}}
    <h1>IndieAuth test completed</h1>
    <p>The authorization and verification responses below came from the discovered IndieAuth server. This page is sent with <code>Cache-Control: no-store</code>.</p>
    <section><h2>Profile</h2><pre>{{.Me}}</pre></section>
    <section><h2>Discovered endpoints</h2><pre>{{.Endpoints}}</pre></section>
    <section><h2>Authorization response</h2><pre>{{.AuthorizationResponse}}</pre></section>
    <section><h2>{{.ExchangeLabel}}</h2><pre>{{.TokenResponse}}</pre></section>
    {{end}}
    <p><a href="{{.TestURL}}">Run another test</a> · <a href="{{.SetupURL}}">Set up a profile</a></p>
  </main>
</body>
</html>`))

func (s *Server) handleSetupCheck(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DynamicProfiles.Enabled {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := r.ParseForm(); err != nil {
		s.renderSetupCheck(w, "", errors.New("invalid form body"))
		return
	}
	me := strings.TrimSpace(r.Form.Get("me"))
	identityState, err := s.openSetupIdentity(r.Form.Get("identity_token"))
	if err == nil {
		backend := s.cfg.Backends[s.cfg.DynamicProfiles.Backend]
		var binding indieauth.ProfileIdentityBinding
		binding, err = indieauth.DiscoverProfileIdentity(
			r.Context(),
			s.httpClient,
			me,
			s.cfg.Security.DevMode || !s.cfg.Security.RequireHTTPS,
			s.cfg.DynamicProfiles.MetadataName,
			s.cfg.Server.PublicURL,
			backend.Issuer,
		)
		if err == nil && (!security.ConstantTimeEqual(binding.Subject, identityState.Subject) || binding.Issuer != identityState.Issuer) {
			err = errors.New("the published identity does not match the account used during setup")
		}
	}
	s.renderSetupCheck(w, me, err)
}

func (s *Server) renderSetupCheck(w http.ResponseWriter, me string, checkErr error) {
	data := map[string]any{
		"Valid":    checkErr == nil,
		"Me":       me,
		"SetupURL": s.cfg.Server.PublicURL + "/setup",
		"TestURL":  s.cfg.Server.PublicURL + "/test",
	}
	if checkErr != nil {
		data["Error"] = checkErr.Error()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := setupCheckTemplate.Execute(w, data); err != nil {
		s.logger.Error("setup check render failed", "err", err)
	}
}

func (s *Server) sealSetupIdentity(issuer, subject string) (string, error) {
	payload, err := json.Marshal(setupIdentityState{
		Issuer:    issuer,
		Subject:   subject,
		ExpiresAt: s.now().Add(s.cfg.Security.AuthRequestTTL.Duration).Unix(),
	})
	if err != nil {
		return "", err
	}
	return security.Seal(s.cfg.Security.CookieSecret, payload)
}

func (s *Server) openSetupIdentity(value string) (setupIdentityState, error) {
	plaintext, err := security.Open(s.cfg.Security.CookieSecret, value)
	if err != nil {
		return setupIdentityState{}, errors.New("setup session is invalid; sign in again")
	}
	var state setupIdentityState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return setupIdentityState{}, errors.New("setup session is invalid; sign in again")
	}
	if state.Issuer == "" || state.Subject == "" || s.now().Unix() > state.ExpiresAt {
		return setupIdentityState{}, errors.New("setup session expired; sign in again")
	}
	return state, nil
}

func (s *Server) handleTestClient(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"RedirectURI": s.cfg.Server.PublicURL + "/test/callback",
		"StartURL":    s.cfg.Server.PublicURL + "/test/start",
		"SetupURL":    s.cfg.Server.PublicURL + "/setup",
		"HomeURL":     s.cfg.Server.PublicURL + "/",
	}
	// The fixed same-origin form action redirects to the authorization endpoint
	// discovered from the submitted profile. Browsers apply form-action across
	// that redirect chain, so a self-only policy would block generic providers.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := testClientTemplate.Execute(w, data); err != nil {
		s.logger.Error("test client render failed", "err", err)
	}
}

func (s *Server) handleTestStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := r.ParseForm(); err != nil {
		s.renderTestError(w, "invalid form body")
		return
	}
	allowHTTP := s.cfg.Security.DevMode || !s.cfg.Security.RequireHTTPS
	discovered, err := indieauth.DiscoverAuthorizationServer(
		r.Context(),
		s.httpClient,
		strings.TrimSpace(r.Form.Get("me")),
		allowHTTP,
	)
	if err != nil {
		s.renderTestError(w, "endpoint discovery failed: "+err.Error())
		return
	}
	state, err := security.RandomToken()
	if err != nil {
		s.renderTestError(w, "test state creation failed")
		return
	}
	verifier, err := security.RandomToken()
	if err != nil {
		s.renderTestError(w, "PKCE verifier creation failed")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	testState := testClientState{
		State:                 state,
		Me:                    discovered.Me,
		AuthorizationEndpoint: discovered.AuthorizationEndpoint,
		AuthorizationIssuer:   discovered.Issuer,
		TokenEndpoint:         discovered.TokenEndpoint,
		CodeVerifier:          verifier,
		LegacyVerification:    discovered.LegacyVerification,
		ExpiresAt:             s.now().Add(s.cfg.Security.AuthRequestTTL.Duration).Unix(),
	}
	payload, err := json.Marshal(testState)
	if err != nil {
		s.renderTestError(w, "test state creation failed")
		return
	}
	sealed, err := security.Seal(s.cfg.Security.CookieSecret, payload)
	if err != nil {
		s.renderTestError(w, "test state creation failed")
		return
	}
	s.setTestCookie(w, sealed, int(s.cfg.Security.AuthRequestTTL.Duration.Seconds()))
	authorizationURL, err := url.Parse(discovered.AuthorizationEndpoint)
	if err != nil {
		s.renderTestError(w, "discovered authorization endpoint is invalid")
		return
	}
	clientID := s.cfg.Server.PublicURL + "/test"
	redirectURI := s.cfg.Server.PublicURL + "/test/callback"
	query := authorizationURL.Query()
	query.Set("me", discovered.Me)
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("state", state)
	if discovered.LegacyVerification {
		query.Del("response_type")
		query.Del("scope")
		query.Del("code_challenge")
		query.Del("code_challenge_method")
	} else {
		query.Set("response_type", "code")
		query.Set("scope", "profile email")
		query.Set("code_challenge", challenge)
		query.Set("code_challenge_method", "S256")
	}
	authorizationURL.RawQuery = query.Encode()
	http.Redirect(w, r, authorizationURL.String(), http.StatusFound)
}

func (s *Server) handleTestCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	cookie, err := r.Cookie(testClientCookieName)
	s.clearTestCookie(w)
	if err != nil {
		s.renderTestError(w, "test session is missing or expired")
		return
	}
	plaintext, err := security.Open(s.cfg.Security.CookieSecret, cookie.Value)
	if err != nil {
		s.renderTestError(w, "test session is invalid")
		return
	}
	var state testClientState
	if err := json.Unmarshal(plaintext, &state); err != nil || state.State == "" || s.now().Unix() > state.ExpiresAt {
		s.renderTestError(w, "test session is invalid or expired")
		return
	}
	if !security.ConstantTimeEqual(r.URL.Query().Get("state"), state.State) {
		s.renderTestError(w, "authorization response state did not match")
		return
	}
	if oauthError := r.URL.Query().Get("error"); oauthError != "" {
		s.renderTestError(w, "authorization server returned "+oauthError+": "+r.URL.Query().Get("error_description"))
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" || len(code) > 4096 {
		s.renderTestError(w, "authorization response did not include a code")
		return
	}
	if responseIssuer := r.URL.Query().Get("iss"); state.AuthorizationIssuer != "" &&
		responseIssuer != state.AuthorizationIssuer {
		s.renderTestError(w, "authorization response issuer did not match discovery metadata")
		return
	}
	exchangeEndpoint := state.TokenEndpoint
	if state.LegacyVerification {
		exchangeEndpoint = state.AuthorizationEndpoint
	}
	tokenURL, err := security.ValidateHTTPSURL(
		exchangeEndpoint,
		s.cfg.Security.DevMode || !s.cfg.Security.RequireHTTPS,
	)
	if err != nil {
		s.renderTestError(w, "stored token endpoint is invalid")
		return
	}
	client, err := indieauth.SafeHTTPClient(
		r.Context(),
		s.httpClient,
		tokenURL,
		s.cfg.Security.DevMode || !s.cfg.Security.RequireHTTPS,
		false,
	)
	if err != nil {
		s.renderTestError(w, "token endpoint is unavailable")
		return
	}
	form := url.Values{
		"code":         {code},
		"client_id":    {s.cfg.Server.PublicURL + "/test"},
		"redirect_uri": {s.cfg.Server.PublicURL + "/test/callback"},
	}
	if !state.LegacyVerification {
		form.Set("grant_type", "authorization_code")
		form.Set("code_verifier", state.CodeVerifier)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		s.renderTestError(w, "token request creation failed")
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json, application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		s.renderTestError(w, "token request failed: "+err.Error())
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, testClientBodyLimit+1))
	if err != nil || len(body) > testClientBodyLimit {
		s.renderTestError(w, "token response could not be read")
		return
	}
	s.renderTestResult(w, state, r.URL.Query(), resp, body)
}

func (s *Server) renderTestResult(
	w http.ResponseWriter,
	state testClientState,
	authorizationResponse url.Values,
	tokenResponse *http.Response,
	body []byte,
) {
	endpoints, _ := json.MarshalIndent(map[string]string{
		"authorization_endpoint": state.AuthorizationEndpoint,
		"issuer":                 state.AuthorizationIssuer,
		"token_endpoint":         state.TokenEndpoint,
	}, "", "  ")
	authorizationJSON, _ := json.MarshalIndent(authorizationResponse, "", "  ")
	tokenBody := prettyTokenResponse(tokenResponse.Header.Get("Content-Type"), body)
	exchangeLabel := "Token response"
	if state.LegacyVerification {
		exchangeLabel = "Legacy verification response"
	}
	data := map[string]any{
		"Me":                    state.Me,
		"Endpoints":             string(endpoints),
		"AuthorizationResponse": string(authorizationJSON),
		"TokenResponse":         fmt.Sprintf("HTTP %s\n%s", tokenResponse.Status, tokenBody),
		"ExchangeLabel":         exchangeLabel,
		"TestURL":               s.cfg.Server.PublicURL + "/test",
		"SetupURL":              s.cfg.Server.PublicURL + "/setup",
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := testResultTemplate.Execute(w, data); err != nil {
		s.logger.Error("test result render failed", "err", err)
	}
}

func (s *Server) renderTestError(w http.ResponseWriter, message string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	if err := testResultTemplate.Execute(w, map[string]any{
		"Error":    message,
		"TestURL":  s.cfg.Server.PublicURL + "/test",
		"SetupURL": s.cfg.Server.PublicURL + "/setup",
	}); err != nil {
		s.logger.Error("test error render failed", "err", err)
	}
}

func (s *Server) setTestCookie(w http.ResponseWriter, value string, maxAge int) {
	publicURL, _ := url.Parse(s.cfg.Server.PublicURL)
	http.SetCookie(w, &http.Cookie{
		Name:     testClientCookieName,
		Value:    value,
		Path:     "/test",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   publicURL != nil && publicURL.Scheme == "https",
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearTestCookie(w http.ResponseWriter) {
	s.setTestCookie(w, "", -1)
}

func prettyTokenResponse(contentType string, body []byte) string {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if mediaType == "application/json" || json.Valid(body) {
		var value any
		if json.Unmarshal(body, &value) == nil {
			pretty, _ := json.MarshalIndent(value, "", "  ")
			return string(pretty)
		}
	}
	if values, err := url.ParseQuery(string(body)); err == nil && len(values) > 0 {
		pretty, _ := json.MarshalIndent(values, "", "  ")
		return string(pretty)
	}
	return string(body)
}
