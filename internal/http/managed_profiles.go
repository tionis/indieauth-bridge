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
	"unicode/utf8"

	"github.com/eric/indieauth-bridge/internal/backends"
	"github.com/eric/indieauth-bridge/internal/security"
	"github.com/eric/indieauth-bridge/internal/storage"
)

const managedHandleMaxLength = 32
const managedDisplayNameMaxLength = 80
const managedBioMaxLength = 280

var managedProfileAccents = map[string]bool{
	"teal": true, "blue": true, "violet": true, "rose": true, "amber": true,
}

var reservedManagedHandles = map[string]bool{
	"admin": true, "administrator": true, "api": true, "auth": true,
	"help": true, "indieauth": true, "root": true, "security": true,
	"setup": true, "support": true, "system": true, "test": true,
}

var managedProfileTemplate = template.Must(template.New("managed-profile").Parse(`<!doctype html>
<html lang="en" data-accent="{{.Accent}}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="canonical" href="{{.Me}}">
  <link rel="indieauth-metadata" href="{{.MetadataURL}}">
  <link rel="authorization_endpoint" href="{{.AuthorizationURL}}">
  <link rel="token_endpoint" href="{{.TokenURL}}">
  <title>{{.Title}} · IndieAuth profile</title>
  <style>
    :root { color-scheme: light; --bg: #f4f7f6; --surface: #fff; --surface-raised: #fff; --ink: #17211f; --muted: #53635f; --line: #d4ddda; --profile-accent: #0f766e; --profile-soft: #ccfbf1; --profile-button-ink: #fff; }
    html[data-accent="blue"] { --profile-accent: #1d4ed8; --profile-soft: #dbeafe; }
    html[data-accent="violet"] { --profile-accent: #6d28d9; --profile-soft: #ede9fe; }
    html[data-accent="rose"] { --profile-accent: #be123c; --profile-soft: #ffe4e6; }
    html[data-accent="amber"] { --profile-accent: #a54808; --profile-soft: #fef3c7; }
    html[data-theme="dark"] { --profile-accent: #5eead4; --profile-soft: #143b3a; --profile-button-ink: #082f2c; }
    html[data-theme="dark"][data-accent="blue"] { --profile-accent: #7dd3fc; --profile-soft: #172f4d; --profile-button-ink: #082f49; }
    html[data-theme="dark"][data-accent="violet"] { --profile-accent: #c4b5fd; --profile-soft: #302653; --profile-button-ink: #2e1065; }
    html[data-theme="dark"][data-accent="rose"] { --profile-accent: #fda4af; --profile-soft: #4a2030; --profile-button-ink: #4c0519; }
    html[data-theme="dark"][data-accent="amber"] { --profile-accent: #fcd34d; --profile-soft: #463617; --profile-button-ink: #451a03; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; overflow-x: hidden; background: var(--bg); color: var(--ink); font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.55; }
    body::before { position: fixed; z-index: -1; width: 620px; height: 620px; top: -260px; right: -180px; border-radius: 50%; background: color-mix(in srgb, var(--profile-accent) 17%, transparent); filter: blur(12px); content: ""; }
    main { width: min(720px, calc(100% - 28px)); padding: 70px 0 48px; }
    .card { position: relative; overflow: hidden; padding: clamp(26px, 7vw, 48px); border: 1px solid var(--line); border-radius: 24px; background: color-mix(in srgb, var(--surface-raised) 96%, transparent); box-shadow: 0 24px 70px rgb(15 23 42 / 12%); }
    .identity { display: flex; align-items: center; gap: 20px; margin-bottom: 28px; }
    .avatar { display: grid; flex: 0 0 auto; width: 76px; height: 76px; place-items: center; border-radius: 22px; background: var(--profile-soft); color: var(--profile-accent); font-size: 32px; font-weight: 850; }
    .eyebrow { color: var(--profile-accent); font-size: 12px; font-weight: 850; letter-spacing: .09em; text-transform: uppercase; }
    h1 { margin: 6px 0 2px; font-size: clamp(34px, 8vw, 56px); line-height: 1; letter-spacing: -.035em; }
    .handle { margin: 0; color: var(--muted); font-size: 17px; }
    .bio { max-width: 58ch; margin: 0 0 24px; color: var(--ink); font-size: 18px; white-space: pre-line; }
    .intro { max-width: 58ch; margin: 0 0 24px; color: var(--muted); }
    .links { display: flex; flex-wrap: wrap; gap: 10px 18px; margin: 0 0 26px; }
    .links a { overflow-wrap: anywhere; color: var(--profile-accent); font-weight: 750; text-underline-offset: 3px; }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; padding-top: 24px; border-top: 1px solid var(--line); }
    a.button { padding: 10px 15px; border: 1px solid var(--profile-accent); border-radius: 9px; background: var(--profile-accent); color: var(--profile-button-ink); text-decoration: none; font-weight: 800; }
    a.button.secondary { background: transparent; color: var(--profile-accent); }
    @media (max-width: 520px) {
      main { padding-top: 64px; }
      .card { border-radius: 18px; }
      .identity { align-items: flex-start; gap: 15px; }
      .avatar { width: 60px; height: 60px; border-radius: 17px; font-size: 26px; }
    }
  </style>
  <script src="/theme.js"></script>
</head>
<body>
  <main class="h-card">
    <div class="card">
      <div class="identity">
        <div class="avatar" aria-hidden="true">{{.Initial}}</div>
        <div>
          <div class="eyebrow">IndieAuth profile</div>
          <h1 class="p-name">{{.Title}}</h1>
          <p class="handle">@{{.Handle}}</p>
        </div>
      </div>
      {{if .Bio}}<p class="bio p-note">{{.Bio}}</p>{{else}}<p class="intro">This is a ready-to-use identity for signing in to IndieAuth-compatible applications.</p>{{end}}
      <div class="links">
        <a class="u-url" href="{{.Me}}">Profile URL</a>
        {{if .WebsiteURL}}<a href="{{.WebsiteURL}}" rel="me">Personal website</a>{{end}}
      </div>
      <div class="actions">
        <a class="button" href="{{.TestURL}}">Test this login</a>
        <a class="button secondary" href="{{.SetupURL}}">Edit profile</a>
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
		if existing.Accent == "" {
			existing.Accent = "teal"
		}
		if !existing.Customized && displayName != existing.DisplayName {
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
		DisplayName: displayName, Accent: "teal", CreatedAt: now, UpdatedAt: now,
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

func managedProfileInitial(profile storage.ManagedProfile) string {
	value := strings.TrimSpace(profile.DisplayName)
	if value == "" {
		value = profile.Handle
	}
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			return string(unicode.ToUpper(r))
		}
	}
	return "@"
}

func normalizeManagedWebsite(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", errors.New("website must be a full HTTPS URL")
	}
	return u.String(), nil
}

func validManagedProfileText(value string, maxLength int, multiline bool) bool {
	if utf8.RuneCountInString(value) > maxLength {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) && !(multiline && (r == '\n' || r == '\r' || r == '\t')) {
			return false
		}
	}
	return true
}

func (s *Server) handleManagedProfileUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.ManagedProfiles.Enabled {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid profile form", http.StatusBadRequest)
		return
	}
	identity, err := s.openSetupIdentity(r.Form.Get("identity_token"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	profile, err := s.store.GetManagedProfileByIdentity(r.Context(), identity.Issuer, identity.Subject)
	if errors.Is(err, storage.ErrNotFound) {
		http.Error(w, "managed profile not found; sign in again", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "profile lookup failed", http.StatusInternalServerError)
		return
	}
	displayName := strings.TrimSpace(r.Form.Get("display_name"))
	bio := strings.TrimSpace(r.Form.Get("bio"))
	if displayName == "" || !validManagedProfileText(displayName, managedDisplayNameMaxLength, false) {
		http.Error(w, "display name must be between 1 and 80 characters", http.StatusBadRequest)
		return
	}
	if !validManagedProfileText(bio, managedBioMaxLength, true) {
		http.Error(w, "bio must be at most 280 characters", http.StatusBadRequest)
		return
	}
	websiteURL, err := normalizeManagedWebsite(r.Form.Get("website_url"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	accent := strings.TrimSpace(r.Form.Get("accent"))
	if !managedProfileAccents[accent] {
		http.Error(w, "invalid accent", http.StatusBadRequest)
		return
	}
	profile.DisplayName = displayName
	profile.Bio = bio
	profile.WebsiteURL = websiteURL
	profile.Accent = accent
	profile.Customized = true
	profile.UpdatedAt = s.now()
	if err := s.store.UpdateManagedProfile(r.Context(), profile); err != nil {
		http.Error(w, "profile update failed", http.StatusInternalServerError)
		return
	}
	me := s.managedProfileURL(profile.Handle)
	s.audit(r.Context(), "managed_profile_updated", identity.Subject, me, "")
	http.Redirect(w, r, me, http.StatusSeeOther)
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
	accent := profile.Accent
	if !managedProfileAccents[accent] {
		accent = "teal"
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := managedProfileTemplate.Execute(w, map[string]string{
		"Title":            profile.DisplayName,
		"Handle":           profile.Handle,
		"Initial":          managedProfileInitial(profile),
		"Bio":              profile.Bio,
		"WebsiteURL":       profile.WebsiteURL,
		"Accent":           accent,
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
