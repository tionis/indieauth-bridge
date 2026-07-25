package bridgehttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eric/indieauth-bridge/internal/backends"
	"github.com/eric/indieauth-bridge/internal/config"
	"github.com/eric/indieauth-bridge/internal/indieauth"
	"github.com/eric/indieauth-bridge/internal/security"
	"github.com/eric/indieauth-bridge/internal/storage"
)

type Server struct {
	cfg        config.Config
	store      storage.Store
	backends   map[string]backends.Backend
	logger     *slog.Logger
	now        func() time.Time
	httpClient *http.Client
	limiter    *rateLimiter
}

const (
	backendStateDynamicProfile = "indieauth_dynamic_profile"
	backendStateProfileIssuer  = "indieauth_profile_issuer"
	backendStateProfileSubject = "indieauth_profile_subject"
	backendStateSetup          = "indieauth_setup"
)

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
    .service-state {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: var(--muted);
      font-size: 14px;
    }
    .service-state::before {
      width: 9px;
      height: 9px;
      border-radius: 999px;
      background: #16a34a;
      content: "";
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
    .details {
      margin: 0;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      overflow: hidden;
    }
    .details div {
      display: grid;
      grid-template-columns: 150px minmax(0, 1fr);
      gap: 16px;
      padding: 12px 16px;
      border-bottom: 1px solid var(--line);
    }
    .details div:last-child { border-bottom: 0; }
    .details dt {
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .details dd { min-width: 0; margin: 0; }
    .details a, .details code {
      overflow-wrap: anywhere;
      color: var(--accent-ink);
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
      .details div { grid-template-columns: 1fr; gap: 4px; }
      h1 { font-size: 40px; }
    }
  </style>
  <script src="/theme.js"></script>
</head>
<body>
  <main>
    <header>
      <div class="eyebrow">IndieAuth authorization server</div>
      <h1>Use a hosted profile—or your own website—as your sign-in identity.</h1>
      <p class="lede">No personal website? Create a ready-to-use profile here. If you already have a website, you can connect that instead.</p>
      <div class="actions">
        {{if .SetupURL}}<a class="button" href="{{.SetupURL}}">Create a hosted profile</a>{{end}}
        {{if .SetupURL}}<a class="button secondary" href="{{.SetupURL}}">Connect your website</a>{{end}}
        <a class="button secondary" href="{{.TestURL}}">Test a login</a>
      </div>
      <a class="service-state" href="{{.HealthPageURL}}">Service is responding</a>
    </header>

    <section aria-labelledby="details-heading">
      <h2 id="details-heading">Server details</h2>
      <dl class="details">
        <div><dt>Issuer</dt><dd><code>{{.Issuer}}</code></dd></div>
        <div><dt>Authorization</dt><dd><a href="{{.AuthorizeURL}}">/authorize</a></dd></div>
        <div><dt>Token</dt><dd><a href="{{.TokenURL}}">/token</a></dd></div>
        <div><dt>Metadata</dt><dd><a href="{{.MetadataURL}}">/.well-known/oauth-authorization-server</a></dd></div>
      </dl>
      {{if .DevMode}}<p class="note">Development mode is enabled. Do not use this configuration for public traffic.</p>{{end}}
    </section>

    <footer>
      New here? Create a hosted profile and use it immediately. Connecting a personal website remains available as an optional, more customizable identity.
    </footer>
  </main>
</body>
</html>`))

var healthTemplate = template.Must(template.New("health").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IndieAuth Bridge Health</title>
  <style>
    :root { color-scheme: light; --bg: #f7f8f5; --surface: #fff; --ink: #1b1f23; --muted: #5f6b76; --line: #d9dfdf; --ok: #047857; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--ink); font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.5; }
    main { width: min(620px, calc(100% - 28px)); padding: 32px 0; }
    .card { padding: 26px; border: 1px solid var(--line); border-radius: 10px; background: var(--surface); }
    .status { display: flex; align-items: center; gap: 10px; color: var(--ok); font-size: 14px; font-weight: 800; letter-spacing: .04em; text-transform: uppercase; }
    .status::before { width: 11px; height: 11px; border-radius: 999px; background: #16a34a; content: ""; }
    h1 { margin: 12px 0 8px; font-size: 34px; }
    p { margin: 0 0 18px; color: var(--muted); }
    code { overflow-wrap: anywhere; }
    a { color: var(--ok); font-weight: 700; }
  </style>
  <script src="/theme.js"></script>
</head>
<body>
  <main>
    <div class="card">
      <div class="status">Healthy</div>
      <h1>IndieAuth bridge is responding</h1>
      <p>The application handled this request successfully. Automated monitoring remains available at <code>/healthz</code>.</p>
      <a href="{{.HomeURL}}">Return to the bridge</a>
    </div>
  </main>
</body>
</html>`))

var setupTemplate = template.Must(template.New("setup").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Your IndieAuth profile</title>
  <style>
    :root { color-scheme: light; --bg: #f7f8f5; --surface: #fff; --ink: #1b1f23; --muted: #5f6b76; --line: #d9dfdf; --accent: #0f766e; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--ink); font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.5; }
    main { width: min(820px, calc(100% - 28px)); padding: 32px 0; }
    h1 { margin: 0 0 12px; font-size: 34px; line-height: 1.1; }
    h2 { margin: 28px 0 8px; font-size: 21px; }
    p, li { color: var(--muted); }
    pre { overflow-x: auto; padding: 18px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface); white-space: pre-wrap; word-break: break-all; }
    .profile-card { padding: 22px; border: 1px solid var(--accent); border-radius: 10px; background: var(--surface); }
    .profile-card h1 { margin-bottom: 10px; }
    .profile-url { display: inline-block; margin: 6px 0 14px; overflow-wrap: anywhere; font-size: 18px; }
    form { display: flex; gap: 10px; margin-top: 12px; }
    input[type="url"] { flex: 1; min-width: 0; padding: 11px 12px; border: 1px solid var(--line); border-radius: 7px; font: inherit; }
    button { padding: 11px 16px; border: 1px solid var(--accent); border-radius: 7px; background: var(--accent); color: #fff; font: inherit; font-weight: 700; cursor: pointer; }
    a { color: var(--accent); font-weight: 700; }
    @media (max-width: 620px) { form { flex-direction: column; } }
  </style>
  <script src="/theme.js"></script>
</head>
<body>
  <main>
    {{if .ManagedProfileURL}}
    <section class="profile-card">
      <h1>Your hosted profile is ready</h1>
      <p>Use this URL whenever an IndieAuth application asks for your website or profile:</p>
      <a class="profile-url" href="{{.ManagedProfileURL}}">{{.ManagedProfileURL}}</a>
      <p>It remains bound to your account even if your Authentik username later changes.</p>
      <p><a href="{{.TestURL}}?me={{.ManagedProfileURL}}">Test this profile now</a></p>
    </section>
    {{else}}
    <h1>Connect your website</h1>
    {{end}}

    {{if .ExternalProfiles}}
    <h2>Optional: use your own website</h2>
    <p>Add both fragments below anywhere inside the profile page's <code>&lt;head&gt;</code>. They tell IndieAuth clients where to log in and tell this bridge which Authentik account owns the page.</p>
    <h2>1. Advertise the IndieAuth endpoints</h2>
    <pre><code>{{.DiscoveryFragment}}</code></pre>

    <h2>2. Link the page to your Authentik identity</h2>
    <pre><code>{{.IdentityFragment}}</code></pre>
    <p>This identifier is public, not a password. You may use the same identity fragment on any number of profile pages. Removing it revokes that page's binding.</p>

    <h2>3. Check the published page</h2>
    <p>Deploy the page, then enter its full URL. The bridge will verify the endpoint links and confirm that the identity tag matches the account you just used.</p>
    <form method="post" action="{{.CheckAction}}">
      <input type="hidden" name="identity_token" value="{{.IdentityToken}}">
      <input name="me" type="url" inputmode="url" placeholder="https://example.com/" required>
      <button type="submit">Check profile</button>
    </form>

    <h2>4. Exercise the complete login</h2>
    <p>Use the <a href="{{.TestURL}}">embedded IndieAuth tester</a> to run a real PKCE login and inspect the authorization and token responses.</p>
    {{end}}
    <p><a href="{{.HomeURL}}">Return to the bridge</a></p>
  </main>
</body>
</html>`))

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Approve Sign-in</title>
  <style>
    :root { color-scheme: light; --bg: #f7f8f5; --surface: #fff; --ink: #1b1f23; --muted: #5f6b76; --line: #d9dfdf; --accent: #0f766e; --danger: #9f1239; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--ink); font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.5; }
    main { width: min(620px, calc(100% - 28px)); padding: 28px 0; }
    h1 { margin: 0 0 12px; font-size: 32px; letter-spacing: 0; line-height: 1.1; }
    p { color: var(--muted); margin: 0 0 20px; }
    dl { display: grid; gap: 12px; margin: 0 0 22px; padding: 18px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface); }
    dt { color: var(--muted); font-size: 13px; font-weight: 700; text-transform: uppercase; }
    dd { margin: 3px 0 0; overflow-wrap: anywhere; font-weight: 700; }
    form { display: flex; flex-wrap: wrap; gap: 10px; }
    button { min-height: 42px; padding: 9px 14px; border-radius: 7px; border: 1px solid var(--accent); background: var(--accent); color: white; font: inherit; font-weight: 700; cursor: pointer; }
    button.secondary { border-color: var(--danger); background: transparent; color: var(--danger); }
    button:disabled { opacity: .68; cursor: wait; }
  </style>
  <script nonce="{{.ScriptNonce}}">
    addEventListener("DOMContentLoaded", () => {
      const form = document.querySelector("form");
      if (!form) return;
      form.addEventListener("submit", () => {
        setTimeout(() => {
          for (const button of form.querySelectorAll("button")) {
            button.disabled = true;
          }
        }, 0);
      });
    });
  </script>
  <script src="/theme.js"></script>
</head>
<body>
  <main>
    <h1>Approve sign-in</h1>
    <p>Confirm this IndieAuth client can complete sign-in for your profile URL.</p>
    <dl>
      <div><dt>Profile</dt><dd>{{.Me}}</dd></div>
      <div><dt>Client</dt><dd>{{.ClientID}}</dd></div>
      <div><dt>Redirect</dt><dd>{{.RedirectURI}}</dd></div>
      <div><dt>Scope</dt><dd>{{.Scope}}</dd></div>
    </dl>
    <form method="post" action="{{.FormAction}}">
      <input type="hidden" name="id" value="{{.ID}}">
      <input type="hidden" name="csrf" value="{{.CSRFToken}}">
      <button type="submit" name="decision" value="approve">Approve</button>
      <button class="secondary" type="submit" name="decision" value="deny">Deny</button>
    </form>
  </main>
</body>
</html>`))

func NewServer(cfg config.Config, store storage.Store, backendMap map[string]backends.Backend, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		cfg:        cfg,
		store:      store,
		backends:   backendMap,
		logger:     logger,
		now:        time.Now,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		limiter:    newRateLimiter(cfg.RateLimit.RequestsPerMinute, cfg.RateLimit.Burst, append(cfg.RateLimit.TrustedProxies, cfg.Server.TrustedProxies...)),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /theme.js", s.handleThemeScript)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /setup", s.handleSetup)
	mux.HandleFunc("POST /setup/check", s.handleSetupCheck)
	mux.HandleFunc("GET /test", s.handleTestClient)
	mux.HandleFunc("POST /test/start", s.handleTestStart)
	mux.HandleFunc("GET /test/callback", s.handleTestCallback)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleMetadata)
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("POST /authorize", s.handleAuthorizationCodeProfile)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.HandleFunc("GET /callback/{backend}", s.handleCallback)
	mux.HandleFunc("GET /consent", s.handleConsentGet)
	mux.HandleFunc("POST /consent", s.handleConsentPost)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("POST /introspect", s.handleIntrospect)
	mux.HandleFunc("POST /revoke", s.handleRevoke)
	mux.HandleFunc("GET /{profile}", s.handleManagedProfile)
	return s.securityHeaders(s.rateLimit(mux))
}

func (s *Server) rateLimit(next http.Handler) http.Handler {
	if !s.cfg.RateLimit.Enabled {
		return next
	}
	limited := map[string]bool{
		"/authorize":     true,
		"/auth/callback": true,
		"/setup":         true,
		"/setup/check":   true,
		"/test/start":    true,
		"/test/callback": true,
		"/consent":       true,
		"/token":         true,
		"/introspect":    true,
		"/revoke":        true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limited[r.URL.Path] || strings.HasPrefix(r.URL.Path, "/callback/") {
			if !s.limiter.allow(r.URL.Path+"|"+s.limiter.clientKey(r), s.now()) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Issuer":        s.cfg.Server.Issuer,
		"AuthorizeURL":  s.cfg.Server.PublicURL + "/authorize",
		"TokenURL":      s.cfg.Server.PublicURL + "/token",
		"MetadataURL":   s.cfg.Server.PublicURL + "/.well-known/oauth-authorization-server",
		"HealthPageURL": s.cfg.Server.PublicURL + "/health",
		"TestURL":       s.cfg.Server.PublicURL + "/test",
		"SetupURL": func() string {
			if s.cfg.DynamicProfiles.Enabled || s.cfg.ManagedProfiles.Enabled {
				return s.cfg.Server.PublicURL + "/setup"
			}
			return ""
		}(),
		"DevMode": s.cfg.Security.DevMode,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := landingTemplate.Execute(w, data); err != nil {
		s.logger.Error("landing page render failed", "err", err)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := healthTemplate.Execute(w, map[string]string{
		"HomeURL": s.cfg.Server.PublicURL + "/",
	}); err != nil {
		s.logger.Error("health page render failed", "err", err)
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         s.cfg.Server.Issuer,
		"authorization_endpoint":                         s.cfg.Server.PublicURL + "/authorize",
		"token_endpoint":                                 s.cfg.Server.PublicURL + "/token",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code"},
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": true,
		"scopes_supported":                               indieauth.SupportedScopes,
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"introspection_endpoint":                         s.cfg.Server.PublicURL + "/introspect",
		"revocation_endpoint":                            s.cfg.Server.PublicURL + "/revoke",
	})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DynamicProfiles.Enabled && !s.cfg.ManagedProfiles.Enabled {
		http.NotFound(w, r)
		return
	}
	backendName := s.cfg.DynamicProfiles.Backend
	if s.cfg.ManagedProfiles.Enabled {
		backendName = s.cfg.ManagedProfiles.Backend
	}
	backend := s.backends[backendName]
	if backend == nil {
		http.Error(w, "profile backend is not available", http.StatusInternalServerError)
		return
	}
	requestID, err := security.RandomToken()
	if err != nil {
		http.Error(w, "setup request creation failed", http.StatusInternalServerError)
		return
	}
	redirectURL, backendState, err := backend.BeginAuth(r.Context(), backends.AuthRequest{RequestID: requestID})
	if err != nil {
		s.logger.Error("setup backend begin auth failed", "backend", backendName, "err", err)
		http.Error(w, "backend authorization failed", http.StatusBadGateway)
		return
	}
	if backendState.Values == nil {
		backendState.Values = map[string]any{}
	}
	backendState.Values[backendStateSetup] = true
	now := s.now()
	if err := s.store.CreateAuthRequest(r.Context(), storage.AuthRequest{
		ID:           requestID,
		Backend:      backendName,
		BackendState: backendState,
		ExpiresAt:    now.Add(s.cfg.Security.AuthRequestTTL.Duration),
		CreatedAt:    now,
	}); err != nil {
		s.logger.Error("setup auth request creation failed", "err", err)
		http.Error(w, "setup request creation failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if responseType := q.Get("response_type"); responseType != "" && responseType != "code" {
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
	allowHTTP := s.cfg.Security.DevMode || !s.cfg.Security.RequireHTTPS
	meURL, err := security.ValidateHTTPSURL(q.Get("me"), allowHTTP)
	if err != nil {
		http.Error(w, "invalid me URL", http.StatusBadRequest)
		return
	}
	me, err := security.CanonicalURL(meURL.String())
	if err != nil {
		http.Error(w, "invalid me URL", http.StatusBadRequest)
		return
	}
	profile, staticProfile := s.cfg.ProfileByMe(me)
	managedProfile, managedProfileURL, err := s.managedProfileForMe(r.Context(), me)
	if err != nil {
		http.Error(w, "unknown managed profile", http.StatusBadRequest)
		return
	}
	if !staticProfile && !managedProfileURL && !s.cfg.DynamicProfiles.Enabled {
		http.Error(w, "unknown me URL", http.StatusBadRequest)
		return
	}
	if _, err := security.ValidateHTTPSURL(q.Get("client_id"), allowHTTP); err != nil {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}
	if err := indieauth.ValidateClientRedirect(r.Context(), s.httpClient, q.Get("client_id"), q.Get("redirect_uri"), allowHTTP, s.cfg.Security.ClientMetadataDiscoveryEnabled); err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		s.audit(r.Context(), "auth_request_rejected", "", me, q.Get("client_id"))
		return
	}
	challenge := q.Get("code_challenge")
	challengeMethod := q.Get("code_challenge_method")
	legacySignIn := legacyIndieAuthSignIn(q)
	if s.cfg.Security.RequirePKCE && !legacySignIn {
		if err := security.ValidateCodeChallenge(challenge, challengeMethod); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else if challenge != "" && challengeMethod != "S256" {
		http.Error(w, "code_challenge_method must be S256", http.StatusBadRequest)
		return
	}
	var dynamicBinding indieauth.ProfileIdentityBinding
	if managedProfileURL {
		dynamicBackend := s.cfg.ManagedProfiles.Backend
		dynamicBinding = indieauth.ProfileIdentityBinding{
			Me:      me,
			Issuer:  managedProfile.Issuer,
			Subject: managedProfile.Subject,
		}
		profile = config.ProfileConfig{
			Me:          me,
			DisplayName: managedProfile.DisplayName,
			Backend:     dynamicBackend,
		}
	} else if !staticProfile {
		dynamicBackend := s.cfg.DynamicProfiles.Backend
		backendConfig := s.cfg.Backends[dynamicBackend]
		dynamicBinding, err = indieauth.DiscoverProfileIdentity(
			r.Context(),
			s.httpClient,
			me,
			allowHTTP,
			s.cfg.DynamicProfiles.MetadataName,
			s.cfg.Server.PublicURL,
			backendConfig.Issuer,
		)
		if err != nil {
			s.logger.Warn("dynamic profile discovery rejected", "me", me, "err", err)
			s.audit(r.Context(), "profile_metadata_rejected", "", me, q.Get("client_id"))
			http.Error(w, "profile identity metadata could not be verified", http.StatusBadRequest)
			return
		}
		profile = config.ProfileConfig{
			Me:      dynamicBinding.Me,
			Backend: dynamicBackend,
		}
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
	if !staticProfile {
		if backendState.Values == nil {
			backendState.Values = map[string]any{}
		}
		backendState.Values[backendStateDynamicProfile] = true
		backendState.Values[backendStateProfileIssuer] = dynamicBinding.Issuer
		backendState.Values[backendStateProfileSubject] = dynamicBinding.Subject
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
	s.audit(r.Context(), "auth_request_created", "", profile.Me, q.Get("client_id"))
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
		s.audit(r.Context(), "backend_login_rejected", "", ar.Me, ar.ClientID)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	if setup, _ := ar.BackendState.Values[backendStateSetup].(bool); setup {
		s.renderSetupIdentity(r.Context(), w, identity, s.cfg.Backends[ar.Backend].Issuer)
		return
	}
	profileJSON := ar.ProfileJSON
	identityAllowed := false
	if dynamicProfile, _ := ar.BackendState.Values[backendStateDynamicProfile].(bool); dynamicProfile {
		expectedSubject, _ := ar.BackendState.Values[backendStateProfileSubject].(string)
		expectedIssuer, _ := ar.BackendState.Values[backendStateProfileIssuer].(string)
		identityAllowed = expectedIssuer == s.cfg.Backends[ar.Backend].Issuer &&
			security.ConstantTimeEqual(expectedSubject, identity.Subject)
		if identityAllowed {
			profileJSON, err = indieauth.DynamicProfileJSON(ar.Me, identity)
			if err != nil {
				http.Error(w, "profile encoding failed", http.StatusInternalServerError)
				return
			}
		}
	} else {
		profile, ok := s.cfg.ProfileByMe(ar.Me)
		identityAllowed = ok && indieauth.IdentityAllowed(profile, identity)
	}
	if !identityAllowed {
		s.logger.Warn("identity not allowed for profile", "backend", ar.Backend, "subject", identity.Subject, "me", ar.Me)
		s.audit(r.Context(), "identity_claim_rejected", identity.Subject, ar.Me, ar.ClientID)
		http.Error(w, "identity is not allowed for requested profile", http.StatusForbidden)
		return
	}
	if s.cfg.Security.ConsentRequired {
		consentID, err := security.RandomToken()
		if err != nil {
			http.Error(w, "consent creation failed", http.StatusInternalServerError)
			return
		}
		csrfToken, err := security.RandomToken()
		if err != nil {
			http.Error(w, "consent creation failed", http.StatusInternalServerError)
			return
		}
		now := s.now()
		err = s.store.CreateConsentRequest(r.Context(), storage.ConsentRequest{
			ID:                  consentID,
			CSRFToken:           csrfToken,
			Me:                  ar.Me,
			ClientID:            ar.ClientID,
			RedirectURI:         ar.RedirectURI,
			Scope:               ar.Scope,
			ClientState:         ar.ClientState,
			CodeChallenge:       ar.CodeChallenge,
			CodeChallengeMethod: ar.CodeChallengeMethod,
			ProfileJSON:         profileJSON,
			Subject:             identity.Subject,
			ExpiresAt:           now.Add(s.cfg.Security.CodeTTL.Duration),
			CreatedAt:           now,
		})
		if err != nil {
			s.logger.Error("store consent request failed", "err", err)
			http.Error(w, "consent creation failed", http.StatusInternalServerError)
			return
		}
		s.audit(r.Context(), "consent_required", identity.Subject, ar.Me, ar.ClientID)
		http.Redirect(w, r, s.cfg.Server.PublicURL+"/consent?id="+url.QueryEscape(consentID), http.StatusFound)
		return
	}
	if err := s.issueCodeAndRedirect(w, r, codeIssueRequest{
		Me:                  ar.Me,
		ClientID:            ar.ClientID,
		RedirectURI:         ar.RedirectURI,
		Scope:               ar.Scope,
		ClientState:         ar.ClientState,
		CodeChallenge:       ar.CodeChallenge,
		CodeChallengeMethod: ar.CodeChallengeMethod,
		ProfileJSON:         profileJSON,
		Subject:             identity.Subject,
	}); err != nil {
		s.logger.Error("issue authorization code failed", "err", err)
		http.Error(w, "code creation failed", http.StatusInternalServerError)
	}
}

func (s *Server) renderSetupIdentity(ctx context.Context, w http.ResponseWriter, identity backends.Identity, issuer string) {
	identityFragment := fmt.Sprintf(
		`<meta name="%s" content="%s %s">`,
		s.cfg.DynamicProfiles.MetadataName,
		issuer,
		identity.Subject,
	)
	discoveryFragment := strings.Join([]string{
		fmt.Sprintf(
			`<link rel="indieauth-metadata" href="%s/.well-known/oauth-authorization-server">`,
			s.cfg.Server.PublicURL,
		),
		fmt.Sprintf(
			`<link rel="authorization_endpoint" href="%s/authorize">`,
			s.cfg.Server.PublicURL,
		),
		fmt.Sprintf(
			`<link rel="token_endpoint" href="%s/token">`,
			s.cfg.Server.PublicURL,
		),
	}, "\n")
	identityToken, err := s.sealSetupIdentity(issuer, identity.Subject)
	if err != nil {
		http.Error(w, "setup page creation failed", http.StatusInternalServerError)
		return
	}
	managedProfileURL := ""
	if s.cfg.ManagedProfiles.Enabled {
		profile, err := s.ensureManagedProfile(ctx, identity, issuer)
		if err != nil {
			s.logger.Error("managed profile provisioning failed", "err", err)
			http.Error(w, "managed profile provisioning failed", http.StatusInternalServerError)
			return
		}
		managedProfileURL = s.managedProfileURL(profile.Handle)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := setupTemplate.Execute(w, map[string]any{
		"DiscoveryFragment": discoveryFragment,
		"IdentityFragment":  identityFragment,
		"IdentityToken":     identityToken,
		"ManagedProfileURL": managedProfileURL,
		"ExternalProfiles":  s.cfg.DynamicProfiles.Enabled,
		"CheckAction":       s.cfg.Server.PublicURL + "/setup/check",
		"TestURL":           s.cfg.Server.PublicURL + "/test",
		"HomeURL":           s.cfg.Server.PublicURL + "/",
	}); err != nil {
		s.logger.Error("setup page render failed", "err", err)
	}
}

type codeIssueRequest struct {
	Me                  string
	ClientID            string
	RedirectURI         string
	Scope               string
	ClientState         string
	CodeChallenge       string
	CodeChallengeMethod string
	ProfileJSON         []byte
	Subject             string
}

func (s *Server) issueCodeAndRedirect(w http.ResponseWriter, r *http.Request, req codeIssueRequest) error {
	code, err := security.RandomToken()
	if err != nil {
		return err
	}
	now := s.now()
	if err := s.store.CreateAuthorizationCode(r.Context(), code, storage.AuthorizationCode{
		Me:                  req.Me,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ProfileJSON:         req.ProfileJSON,
		ExpiresAt:           now.Add(s.cfg.Security.CodeTTL.Duration),
		CreatedAt:           now,
	}); err != nil {
		return err
	}
	s.audit(r.Context(), "authorization_code_issued", req.Subject, req.Me, req.ClientID)
	redirect, err := url.Parse(req.RedirectURI)
	if err != nil {
		return err
	}
	values := redirect.Query()
	values.Set("code", code)
	if req.ClientState != "" {
		values.Set("state", req.ClientState)
	}
	values.Set("iss", s.cfg.Server.Issuer)
	redirect.RawQuery = values.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
	return nil
}

func legacyIndieAuthSignIn(q url.Values) bool {
	return q.Get("response_type") == "" && q.Get("scope") == "" && q.Get("code_challenge") == "" && q.Get("code_challenge_method") == ""
}

func (s *Server) handleConsentGet(w http.ResponseWriter, r *http.Request) {
	consentID := r.URL.Query().Get("id")
	cr, err := s.store.GetConsentRequest(r.Context(), consentID, s.now())
	if err != nil {
		http.Error(w, "invalid or expired consent request", http.StatusBadRequest)
		return
	}
	scriptNonce, err := security.RandomToken()
	if err != nil {
		http.Error(w, "consent page creation failed", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"ID":          cr.ID,
		"CSRFToken":   cr.CSRFToken,
		"Me":          cr.Me,
		"ClientID":    cr.ClientID,
		"RedirectURI": cr.RedirectURI,
		"Scope":       displayScope(cr.Scope),
		"ScriptNonce": scriptNonce,
		"FormAction":  s.cfg.Server.PublicURL + "/consent?id=" + url.QueryEscape(cr.ID),
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Security-Policy", consentContentSecurityPolicy(scriptNonce))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := consentTemplate.Execute(w, data); err != nil {
		s.logger.Error("consent page render failed", "err", err)
	}
}

func (s *Server) handleConsentPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	consentID := r.Form.Get("id")
	if consentID == "" {
		consentID = r.URL.Query().Get("id")
	}
	cr, err := s.store.GetConsentRequest(r.Context(), consentID, s.now())
	if err != nil {
		http.Error(w, "invalid or expired consent request", http.StatusBadRequest)
		return
	}
	if !security.ConstantTimeEqual(r.Form.Get("csrf"), cr.CSRFToken) {
		s.audit(r.Context(), "consent_rejected", cr.Subject, cr.Me, cr.ClientID)
		http.Error(w, "invalid consent token", http.StatusBadRequest)
		return
	}
	defer func() {
		if err := s.store.DeleteConsentRequest(context.Background(), cr.ID); err != nil {
			s.logger.Warn("delete consent request failed", "err", err)
		}
	}()
	if r.Form.Get("decision") != "approve" {
		s.audit(r.Context(), "consent_denied", cr.Subject, cr.Me, cr.ClientID)
		s.redirectWithError(w, r, cr.RedirectURI, cr.ClientState, "access_denied")
		return
	}
	if err := s.issueCodeAndRedirect(w, r, codeIssueRequest{
		Me:                  cr.Me,
		ClientID:            cr.ClientID,
		RedirectURI:         cr.RedirectURI,
		Scope:               cr.Scope,
		ClientState:         cr.ClientState,
		CodeChallenge:       cr.CodeChallenge,
		CodeChallengeMethod: cr.CodeChallengeMethod,
		ProfileJSON:         cr.ProfileJSON,
		Subject:             cr.Subject,
	}); err != nil {
		s.logger.Error("issue authorization code failed", "err", err)
		http.Error(w, "code creation failed", http.StatusInternalServerError)
	}
}

func consentContentSecurityPolicy(scriptNonce string) string {
	return "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-" + scriptNonce + "' 'self'; base-uri 'none'; frame-ancestors 'none'"
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
		s.audit(r.Context(), "token_exchange_rejected", "", "", r.Form.Get("client_id"))
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code")
		return
	}
	code := r.Form.Get("code")
	if code == "" {
		s.audit(r.Context(), "token_exchange_rejected", "", "", r.Form.Get("client_id"))
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	rec, err := s.store.ConsumeAuthorizationCode(r.Context(), code, s.now())
	if err != nil {
		s.audit(r.Context(), "token_exchange_rejected", "", "", r.Form.Get("client_id"))
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
		return
	}
	if rec.ClientID != r.Form.Get("client_id") || rec.RedirectURI != r.Form.Get("redirect_uri") {
		s.audit(r.Context(), "token_exchange_rejected", "", rec.Me, r.Form.Get("client_id"))
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id or redirect_uri mismatch")
		return
	}
	if s.cfg.Security.RequirePKCE && rec.CodeChallenge == "" {
		s.audit(r.Context(), "token_exchange_rejected", "", rec.Me, rec.ClientID)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	if rec.CodeChallenge != "" {
		if !security.VerifyPKCES256(r.Form.Get("code_verifier"), rec.CodeChallenge) {
			s.audit(r.Context(), "token_exchange_rejected", "", rec.Me, rec.ClientID)
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
	s.audit(r.Context(), "access_token_issued", "", rec.Me, rec.ClientID)
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

func (s *Server) handleAuthorizationCodeProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	code := r.Form.Get("code")
	if code == "" {
		s.audit(r.Context(), "authorization_code_profile_rejected", "", "", r.Form.Get("client_id"))
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	rec, err := s.store.ConsumeAuthorizationCode(r.Context(), code, s.now())
	if err != nil {
		s.audit(r.Context(), "authorization_code_profile_rejected", "", "", r.Form.Get("client_id"))
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
		return
	}
	if rec.ClientID != r.Form.Get("client_id") || rec.RedirectURI != r.Form.Get("redirect_uri") {
		s.audit(r.Context(), "authorization_code_profile_rejected", "", rec.Me, r.Form.Get("client_id"))
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id or redirect_uri mismatch")
		return
	}
	if rec.CodeChallenge != "" && !security.VerifyPKCES256(r.Form.Get("code_verifier"), rec.CodeChallenge) {
		s.audit(r.Context(), "authorization_code_profile_rejected", "", rec.Me, rec.ClientID)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	s.audit(r.Context(), "authorization_code_profile_returned", "", rec.Me, rec.ClientID)
	response := map[string]any{
		"me": rec.Me,
	}
	if len(rec.ProfileJSON) > 0 {
		var profile map[string]any
		if err := json.Unmarshal(rec.ProfileJSON, &profile); err == nil {
			response["profile"] = profile
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	token := r.Form.Get("token")
	if token == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	rec, err := s.store.GetAccessToken(r.Context(), token, s.now())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	response := map[string]any{
		"active":    true,
		"client_id": rec.ClientID,
		"scope":     rec.Scope,
		"me":        rec.Me,
		"exp":       rec.ExpiresAt.Unix(),
		"iat":       rec.CreatedAt.Unix(),
	}
	if len(rec.ProfileJSON) > 0 {
		var profile map[string]any
		if err := json.Unmarshal(rec.ProfileJSON, &profile); err == nil {
			response["profile"] = profile
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	token := r.Form.Get("token")
	if token == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	if rec, err := s.store.GetAccessToken(r.Context(), token, s.now()); err == nil {
		s.audit(r.Context(), "access_token_revoked", "", rec.Me, rec.ClientID)
	}
	if err := s.store.RevokeAccessToken(r.Context(), token, s.now()); err != nil {
		s.logger.Warn("revoke token failed", "err", err)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errorCode string) {
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid stored redirect", http.StatusInternalServerError)
		return
	}
	values := redirect.Query()
	values.Set("error", errorCode)
	if state != "" {
		values.Set("state", state)
	}
	redirect.RawQuery = values.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (s *Server) audit(ctx context.Context, eventType, subject, me, clientID string) {
	if err := s.store.CreateAuditEvent(ctx, storage.AuditEvent{
		EventType: eventType,
		Subject:   subject,
		Me:        me,
		ClientID:  clientID,
		CreatedAt: s.now(),
	}); err != nil {
		s.logger.Warn("audit event write failed", "event", eventType, "err", err)
	}
}

func displayScope(scope string) string {
	if scope == "" {
		return "(none)"
	}
	return scope
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
