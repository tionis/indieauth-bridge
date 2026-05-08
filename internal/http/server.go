package bridgehttp

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/eric/indieauth-bridge/internal/backends"
	"github.com/eric/indieauth-bridge/internal/config"
	"github.com/eric/indieauth-bridge/internal/indieauth"
	"github.com/eric/indieauth-bridge/internal/security"
	"github.com/eric/indieauth-bridge/internal/storage"
)

type Server struct {
	cfg      config.Config
	store    storage.Store
	backends map[string]backends.Backend
	logger   *slog.Logger
	now      func() time.Time
}

var landingTemplate = template.Must(template.New("landing").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IndieAuth Bridge</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8f5;
      --surface: #ffffff;
      --ink: #1b1f23;
      --muted: #5f6b76;
      --line: #d9dfdf;
      --accent: #0f766e;
      --accent-ink: #063f3b;
      --warn: #9a6700;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--ink);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }
    main {
      width: min(1040px, calc(100% - 32px));
      margin: 0 auto;
      padding: 56px 0 40px;
    }
    header {
      display: grid;
      gap: 18px;
      padding: 0 0 34px;
      border-bottom: 1px solid var(--line);
    }
    .eyebrow {
      color: var(--accent-ink);
      font-size: 13px;
      font-weight: 700;
      letter-spacing: .08em;
      text-transform: uppercase;
    }
    h1 {
      max-width: 820px;
      margin: 0;
      font-size: clamp(34px, 7vw, 68px);
      line-height: .98;
      letter-spacing: 0;
    }
    .lede {
      max-width: 720px;
      margin: 0;
      color: var(--muted);
      font-size: 18px;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 8px;
    }
    a.button {
      display: inline-flex;
      align-items: center;
      min-height: 42px;
      padding: 9px 14px;
      border: 1px solid var(--accent);
      border-radius: 7px;
      color: #fff;
      background: var(--accent);
      text-decoration: none;
      font-weight: 700;
    }
    a.button.secondary {
      color: var(--accent-ink);
      background: transparent;
    }
    section {
      padding: 30px 0;
      border-bottom: 1px solid var(--line);
    }
    h2 {
      margin: 0 0 16px;
      font-size: 20px;
      letter-spacing: 0;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 14px;
    }
    .metric, .endpoint {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      padding: 16px;
    }
    .metric span, .endpoint span {
      display: block;
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .metric strong {
      display: block;
      margin-top: 7px;
      font-size: 24px;
    }
    .endpoint {
      display: grid;
      gap: 8px;
    }
    .endpoint a {
      overflow-wrap: anywhere;
      color: var(--accent-ink);
      font-weight: 700;
      text-decoration-thickness: 1px;
      text-underline-offset: 3px;
    }
    .note {
      margin: 18px 0 0;
      color: var(--warn);
      font-size: 14px;
    }
    footer {
      padding-top: 24px;
      color: var(--muted);
      font-size: 14px;
    }
    @media (max-width: 760px) {
      main { width: min(100% - 24px, 1040px); padding-top: 34px; }
      .grid { grid-template-columns: 1fr; }
      h1 { font-size: 40px; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <div class="eyebrow">IndieAuth authorization server</div>
      <h1>Sign in with a profile URL through your OIDC provider.</h1>
      <p class="lede">This bridge accepts IndieAuth authorization requests for configured profile URLs and delegates authentication to an OIDC backend such as authentik.</p>
      <div class="actions">
        <a class="button" href="{{.MetadataURL}}">View metadata</a>
        <a class="button secondary" href="{{.HealthURL}}">Check health</a>
      </div>
    </header>

    <section aria-labelledby="status-heading">
      <h2 id="status-heading">Status</h2>
      <div class="grid">
        <div class="metric"><span>Issuer</span><strong>{{.Issuer}}</strong></div>
        <div class="metric"><span>Profiles</span><strong>{{.ProfileCount}}</strong></div>
        <div class="metric"><span>Backends</span><strong>{{.BackendNames}}</strong></div>
      </div>
      {{if .DevMode}}<p class="note">Development mode is enabled. Do not use this configuration for public traffic.</p>{{end}}
    </section>

    <section aria-labelledby="endpoints-heading">
      <h2 id="endpoints-heading">Endpoints</h2>
      <div class="grid">
        <div class="endpoint"><span>Authorization</span><a href="{{.AuthorizeURL}}">{{.AuthorizeURL}}</a></div>
        <div class="endpoint"><span>Token</span><a href="{{.TokenURL}}">{{.TokenURL}}</a></div>
        <div class="endpoint"><span>Metadata</span><a href="{{.MetadataURL}}">{{.MetadataURL}}</a></div>
      </div>
    </section>

    <footer>
      Publish the metadata, authorization, and token links from your profile site so IndieAuth clients can discover this bridge.
    </footer>
  </main>
</body>
</html>`))

func NewServer(cfg config.Config, store storage.Store, backendMap map[string]backends.Backend, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, store: store, backends: backendMap, logger: logger, now: time.Now}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleMetadata)
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.HandleFunc("GET /callback/{backend}", s.handleCallback)
	mux.HandleFunc("POST /token", s.handleToken)
	return s.securityHeaders(mux)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	names := make([]string, 0, len(s.backends))
	for name := range s.backends {
		names = append(names, name)
	}
	sort.Strings(names)
	data := map[string]any{
		"Issuer":       s.cfg.Server.Issuer,
		"AuthorizeURL": s.cfg.Server.PublicURL + "/authorize",
		"TokenURL":     s.cfg.Server.PublicURL + "/token",
		"MetadataURL":  s.cfg.Server.PublicURL + "/.well-known/oauth-authorization-server",
		"HealthURL":    s.cfg.Server.PublicURL + "/healthz",
		"ProfileCount": len(s.cfg.Profiles),
		"BackendNames": strings.Join(names, ", "),
		"DevMode":      s.cfg.Security.DevMode,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := landingTemplate.Execute(w, data); err != nil {
		s.logger.Error("landing page render failed", "err", err)
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.cfg.Server.Issuer,
		"authorization_endpoint":                s.cfg.Server.PublicURL + "/authorize",
		"token_endpoint":                        s.cfg.Server.PublicURL + "/token",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      indieauth.SupportedScopes,
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		http.Error(w, "unsupported response_type", http.StatusBadRequest)
		return
	}
	if q.Get("state") == "" {
		http.Error(w, "state is required", http.StatusBadRequest)
		return
	}
	scope := q.Get("scope")
	if !indieauth.ScopeAllowed(scope) {
		http.Error(w, "unsupported scope", http.StatusBadRequest)
		return
	}
	profile, ok := s.cfg.ProfileByMe(q.Get("me"))
	if !ok {
		http.Error(w, "unknown me URL", http.StatusBadRequest)
		return
	}
	allowHTTP := s.cfg.Security.DevMode || !s.cfg.Security.RequireHTTPS
	if _, err := security.ValidateHTTPSURL(q.Get("client_id"), allowHTTP); err != nil {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}
	if err := security.ValidateRedirectURI(q.Get("client_id"), q.Get("redirect_uri"), allowHTTP); err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	challenge := q.Get("code_challenge")
	challengeMethod := q.Get("code_challenge_method")
	if s.cfg.Security.RequirePKCE {
		if err := security.ValidateCodeChallenge(challenge, challengeMethod); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else if challenge != "" && challengeMethod != "S256" {
		http.Error(w, "code_challenge_method must be S256", http.StatusBadRequest)
		return
	}
	backend := s.backends[profile.Backend]
	if backend == nil {
		http.Error(w, "profile backend is not available", http.StatusInternalServerError)
		return
	}
	profileJSON, err := indieauth.ProfileJSON(profile)
	if err != nil {
		http.Error(w, "profile encoding failed", http.StatusInternalServerError)
		return
	}
	requestID, err := security.RandomToken()
	if err != nil {
		http.Error(w, "request creation failed", http.StatusInternalServerError)
		return
	}
	redirectURL, backendState, err := backend.BeginAuth(r.Context(), backends.AuthRequest{
		RequestID: requestID,
		Me:        profile.Me,
		Scopes:    strings.Fields(scope),
	})
	if err != nil {
		s.logger.Error("backend begin auth failed", "backend", profile.Backend, "err", err)
		http.Error(w, "backend authorization failed", http.StatusBadGateway)
		return
	}
	now := s.now()
	err = s.store.CreateAuthRequest(r.Context(), storage.AuthRequest{
		ID:                  requestID,
		Backend:             profile.Backend,
		BackendState:        backendState,
		Me:                  profile.Me,
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               scope,
		ClientState:         q.Get("state"),
		CodeChallenge:       challenge,
		CodeChallengeMethod: challengeMethod,
		ProfileJSON:         profileJSON,
		ExpiresAt:           now.Add(s.cfg.Security.AuthRequestTTL.Duration),
		CreatedAt:           now,
	})
	if err != nil {
		s.logger.Error("store auth request failed", "err", err)
		http.Error(w, "request creation failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	backendName := r.PathValue("backend")
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "state is required", http.StatusBadRequest)
		return
	}
	ar, backend, err := s.findAuthRequest(r.Context(), backendName, state)
	if err != nil {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}
	defer func() {
		if err := s.store.DeleteAuthRequest(context.Background(), ar.ID); err != nil {
			s.logger.Warn("delete auth request failed", "err", err)
		}
	}()
	identity, err := backend.CompleteAuth(r.Context(), backends.CallbackRequest{Query: r.URL.Query()}, ar.BackendState)
	if err != nil {
		s.logger.Warn("backend auth completion rejected", "backend", ar.Backend, "err", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	profile, ok := s.cfg.ProfileByMe(ar.Me)
	if !ok || !indieauth.IdentityAllowed(profile, identity) {
		s.logger.Warn("identity not allowed for profile", "backend", ar.Backend, "subject", identity.Subject, "me", ar.Me)
		http.Error(w, "identity is not allowed for requested profile", http.StatusForbidden)
		return
	}
	code, err := security.RandomToken()
	if err != nil {
		http.Error(w, "code creation failed", http.StatusInternalServerError)
		return
	}
	now := s.now()
	if err := s.store.CreateAuthorizationCode(r.Context(), code, storage.AuthorizationCode{
		Me:                  ar.Me,
		ClientID:            ar.ClientID,
		RedirectURI:         ar.RedirectURI,
		Scope:               ar.Scope,
		CodeChallenge:       ar.CodeChallenge,
		CodeChallengeMethod: ar.CodeChallengeMethod,
		ProfileJSON:         ar.ProfileJSON,
		ExpiresAt:           now.Add(s.cfg.Security.CodeTTL.Duration),
		CreatedAt:           now,
	}); err != nil {
		s.logger.Error("store authorization code failed", "err", err)
		http.Error(w, "code creation failed", http.StatusInternalServerError)
		return
	}
	redirect, err := url.Parse(ar.RedirectURI)
	if err != nil {
		http.Error(w, "invalid stored redirect", http.StatusInternalServerError)
		return
	}
	values := redirect.Query()
	values.Set("code", code)
	if ar.ClientState != "" {
		values.Set("state", ar.ClientState)
	}
	redirect.RawQuery = values.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (s *Server) findAuthRequest(ctx context.Context, requestedBackend, state string) (storage.AuthRequest, backends.Backend, error) {
	if requestedBackend != "" {
		backend := s.backends[requestedBackend]
		if backend == nil {
			return storage.AuthRequest{}, nil, storage.ErrNotFound
		}
		ar, err := s.store.GetAuthRequestByBackendState(ctx, requestedBackend, state)
		return ar, backend, err
	}
	for name, backend := range s.backends {
		ar, err := s.store.GetAuthRequestByBackendState(ctx, name, state)
		if err == nil {
			return ar, backend, nil
		}
		if !errors.Is(err, storage.ErrNotFound) && !errors.Is(err, storage.ErrExpired) {
			return storage.AuthRequest{}, nil, err
		}
	}
	return storage.AuthRequest{}, nil, storage.ErrNotFound
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code")
		return
	}
	code := r.Form.Get("code")
	if code == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	rec, err := s.store.ConsumeAuthorizationCode(r.Context(), code, s.now())
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
		return
	}
	if rec.ClientID != r.Form.Get("client_id") || rec.RedirectURI != r.Form.Get("redirect_uri") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id or redirect_uri mismatch")
		return
	}
	if rec.CodeChallenge != "" {
		if !security.VerifyPKCES256(r.Form.Get("code_verifier"), rec.CodeChallenge) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	}
	token, err := security.RandomToken()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token creation failed")
		return
	}
	now := s.now()
	if err := s.store.CreateAccessToken(r.Context(), token, storage.AccessToken{
		Me:          rec.Me,
		ClientID:    rec.ClientID,
		Scope:       rec.Scope,
		ProfileJSON: rec.ProfileJSON,
		ExpiresAt:   now.Add(s.cfg.Security.AccessTokenTTL.Duration),
		CreatedAt:   now,
	}); err != nil {
		s.logger.Error("store access token failed", "err", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token storage failed")
		return
	}
	response := map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"scope":        rec.Scope,
		"me":           rec.Me,
	}
	if len(rec.ProfileJSON) > 0 {
		var profile map[string]any
		if err := json.Unmarshal(rec.ProfileJSON, &profile); err == nil {
			response["profile"] = profile
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}
