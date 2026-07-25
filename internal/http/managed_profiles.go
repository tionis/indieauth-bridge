package bridgehttp

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/eric/indieauth-bridge/internal/backends"
	"github.com/eric/indieauth-bridge/internal/security"
	"github.com/eric/indieauth-bridge/internal/storage"
)

const managedHandleMaxLength = 32

var reservedManagedHandles = map[string]bool{
	"admin": true, "administrator": true, "api": true, "auth": true,
	"help": true, "indieauth": true, "root": true, "security": true,
	"setup": true, "support": true, "system": true, "test": true,
}

var managedProfileTemplate = template.Must(template.New("managed-profile").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="canonical" href="{{.Me}}">
  <link rel="indieauth-metadata" href="{{.MetadataURL}}">
  <link rel="authorization_endpoint" href="{{.AuthorizationURL}}">
  <link rel="token_endpoint" href="{{.TokenURL}}">
  <title>{{.Title}} · IndieAuth profile</title>
  <style>
    :root { color-scheme: light; --bg: #f7f8f5; --surface: #fff; --ink: #1b1f23; --muted: #5f6b76; --line: #d9dfdf; --accent: #0f766e; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--ink); font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.5; }
    main { width: min(680px, calc(100% - 28px)); padding: 48px 0; }
    .card { padding: 30px; border: 1px solid var(--line); border-radius: 12px; background: var(--surface); }
    .eyebrow { color: var(--accent); font-size: 13px; font-weight: 800; letter-spacing: .07em; text-transform: uppercase; }
    h1 { margin: 10px 0 4px; font-size: clamp(36px, 8vw, 58px); line-height: 1; }
    .handle { margin: 0 0 22px; color: var(--muted); font-size: 18px; }
    p { color: var(--muted); }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 24px; }
    a { color: var(--accent); font-weight: 700; }
    a.button { padding: 10px 14px; border: 1px solid var(--accent); border-radius: 7px; background: var(--accent); color: #fff; text-decoration: none; }
    a.button.secondary { background: transparent; color: var(--accent); }
  </style>
  <script src="/theme.js"></script>
</head>
<body>
  <main class="h-card">
    <div class="card">
      <div class="eyebrow">Hosted IndieAuth profile</div>
      <h1 class="p-name">{{.Title}}</h1>
      <p class="handle">@{{.Handle}}</p>
      <p>This profile can be used as an IndieAuth identity. Enter its URL when an application asks for your website or profile.</p>
      <a class="u-url" href="{{.Me}}">{{.Me}}</a>
      <div class="actions">
        <a class="button" href="{{.TestURL}}">Test this login</a>
        <a class="button secondary" href="{{.SetupURL}}">Profile setup</a>
      </div>
    </div>
  </main>
</body>
</html>`))

func normalizeManagedHandle(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var out strings.Builder
	lastSeparator := false
	for _, r := range value {
		valid := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-'
		if valid {
			if out.Len() < managedHandleMaxLength {
				out.WriteRune(r)
			}
			lastSeparator = r == '.' || r == '_' || r == '-'
			continue
		}
		if (unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsSpace(r)) && !lastSeparator && out.Len() > 0 && out.Len() < managedHandleMaxLength {
			out.WriteByte('-')
			lastSeparator = true
		}
	}
	return strings.Trim(out.String(), "._-")
}

func managedHandleSuffix(issuer, subject string) string {
	sum := sha256.Sum256([]byte(issuer + "\x00" + subject))
	return fmt.Sprintf("%x", sum[:4])
}

func desiredManagedHandle(identity backends.Identity, issuer string) string {
	for _, candidate := range []string{identity.PreferredUsername, identity.Username, identity.Name} {
		handle := normalizeManagedHandle(candidate)
		if handle != "" {
			if reservedManagedHandles[handle] {
				return "user-" + handle
			}
			return handle
		}
	}
	return "user-" + managedHandleSuffix(issuer, identity.Subject)
}

func (s *Server) ensureManagedProfile(
	ctx context.Context,
	identity backends.Identity,
	issuer string,
) (storage.ManagedProfile, error) {
	if !s.cfg.ManagedProfiles.Enabled {
		return storage.ManagedProfile{}, storage.ErrNotFound
	}
	if strings.TrimSpace(identity.Subject) == "" {
		return storage.ManagedProfile{}, errors.New("identity subject is required")
	}
	if existing, err := s.store.GetManagedProfileByIdentity(ctx, issuer, identity.Subject); err == nil {
		displayName := strings.TrimSpace(identity.Name)
		if displayName == "" {
			displayName = "@" + existing.Handle
		}
		if displayName != existing.DisplayName {
			existing.DisplayName = displayName
			existing.UpdatedAt = s.now()
			if err := s.store.UpdateManagedProfile(ctx, existing); err != nil {
				return storage.ManagedProfile{}, err
			}
		}
		return existing, nil
	} else if !errors.Is(err, storage.ErrNotFound) {
		return storage.ManagedProfile{}, err
	}

	handle := desiredManagedHandle(identity, issuer)
	displayName := strings.TrimSpace(identity.Name)
	if displayName == "" {
		displayName = "@" + handle
	}
	now := s.now()
	profile := storage.ManagedProfile{
		Handle: handle, Issuer: issuer, Subject: identity.Subject,
		DisplayName: displayName, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateManagedProfile(ctx, profile); err == nil {
		return profile, nil
	} else if !errors.Is(err, storage.ErrConflict) {
		return storage.ManagedProfile{}, err
	}
	if existing, err := s.store.GetManagedProfileByIdentity(ctx, issuer, identity.Subject); err == nil {
		return existing, nil
	}
	suffix := managedHandleSuffix(issuer, identity.Subject)
	base := strings.TrimRight(handle[:min(len(handle), managedHandleMaxLength-len(suffix)-1)], "._-")
	profile.Handle = base + "-" + suffix
	if err := s.store.CreateManagedProfile(ctx, profile); err != nil {
		return storage.ManagedProfile{}, err
	}
	return profile, nil
}

func (s *Server) managedProfileURL(handle string) string {
	return s.cfg.Server.PublicURL + "/@" + url.PathEscape(handle)
}

func (s *Server) managedProfileForMe(ctx context.Context, me string) (storage.ManagedProfile, bool, error) {
	if !s.cfg.ManagedProfiles.Enabled {
		return storage.ManagedProfile{}, false, nil
	}
	u, err := url.Parse(me)
	if err != nil {
		return storage.ManagedProfile{}, false, nil
	}
	publicURL, err := url.Parse(s.cfg.Server.PublicURL)
	if err != nil || !security.SameOrigin(u, publicURL) || !strings.HasPrefix(u.Path, "/@") || strings.Contains(strings.TrimPrefix(u.Path, "/@"), "/") {
		return storage.ManagedProfile{}, false, nil
	}
	handle := normalizeManagedHandle(strings.TrimPrefix(u.Path, "/@"))
	if handle == "" {
		return storage.ManagedProfile{}, false, nil
	}
	profile, err := s.store.GetManagedProfileByHandle(ctx, handle)
	if errors.Is(err, storage.ErrNotFound) {
		return storage.ManagedProfile{}, true, storage.ErrNotFound
	}
	if err == nil && me != s.managedProfileURL(profile.Handle) {
		return storage.ManagedProfile{}, true, storage.ErrNotFound
	}
	return profile, true, err
}

func (s *Server) handleManagedProfile(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.ManagedProfiles.Enabled || !strings.HasPrefix(r.URL.Path, "/@") || strings.Contains(strings.TrimPrefix(r.URL.Path, "/@"), "/") {
		http.NotFound(w, r)
		return
	}
	requested := strings.TrimPrefix(r.URL.Path, "/@")
	handle := normalizeManagedHandle(requested)
	if handle == "" {
		http.NotFound(w, r)
		return
	}
	if requested != handle {
		http.Redirect(w, r, s.managedProfileURL(handle), http.StatusMovedPermanently)
		return
	}
	profile, err := s.store.GetManagedProfileByHandle(r.Context(), handle)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "profile lookup failed", http.StatusInternalServerError)
		return
	}
	me := s.managedProfileURL(profile.Handle)
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := managedProfileTemplate.Execute(w, map[string]string{
		"Title":            profile.DisplayName,
		"Handle":           profile.Handle,
		"Me":               me,
		"MetadataURL":      s.cfg.Server.PublicURL + "/.well-known/oauth-authorization-server",
		"AuthorizationURL": s.cfg.Server.PublicURL + "/authorize",
		"TokenURL":         s.cfg.Server.PublicURL + "/token",
		"TestURL":          s.cfg.Server.PublicURL + "/test?me=" + url.QueryEscape(me),
		"SetupURL":         s.cfg.Server.PublicURL + "/setup",
	}); err != nil {
		s.logger.Error("managed profile render failed", "err", err)
	}
}
