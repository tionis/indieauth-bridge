package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfigAndEnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(path, []byte(`
server:
  listen: ":8080"
  public_url: "https://bridge.example"
security:
  cookie_secret: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  dev_mode: false
profiles:
  - me: "https://eric.example"
    backend: "authentik"
    allowed_subjects: ["sub"]
backends:
  authentik:
    type: "authentik"
    issuer: "https://auth.example/application/o/indieauth/"
    client_id: "client"
    client_secret: "secret"
    redirect_uri: "https://bridge.example/auth/callback"
storage:
  type: "sqlite"
  path: "/data/bridge.db"
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("IAB_SERVER_LISTEN", ":9090")
	t.Setenv("IAB_BACKENDS_AUTHENTIK_CLIENT_ID", "override")
	t.Setenv("IAB_SECURITY_CONSENT_REQUIRED", "false")
	t.Setenv("IAB_RATE_LIMIT_BURST", "7")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != ":9090" {
		t.Fatalf("listen override not applied: %s", cfg.Server.Listen)
	}
	if cfg.Backends["authentik"].ClientID != "override" {
		t.Fatalf("backend override not applied")
	}
	if cfg.Security.ConsentRequired {
		t.Fatalf("consent override not applied")
	}
	if cfg.RateLimit.Burst != 7 {
		t.Fatalf("rate limit override not applied")
	}
	if cfg.Security.CodeTTL.Duration != 5*time.Minute {
		t.Fatalf("default code ttl changed: %s", cfg.Security.CodeTTL)
	}
	if cfg.Profiles[0].Me != "https://eric.example/" {
		t.Fatalf("profile URL not canonicalized: %s", cfg.Profiles[0].Me)
	}
}

func TestRejectWeakCookieSecretOutsideDev(t *testing.T) {
	cfg := Default()
	cfg.Server.PublicURL = "https://bridge.example"
	cfg.Security.CookieSecret = "change-me"
	cfg.Profiles = []ProfileConfig{{Me: "https://eric.example/", Backend: "authentik", AllowedSubjects: []string{"sub"}}}
	cfg.Backends = map[string]BackendConfig{"authentik": {
		Type: "authentik", Issuer: "https://auth.example/", ClientID: "id", ClientSecret: "secret", RedirectURI: "https://bridge.example/auth/callback",
	}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected weak secret rejection")
	}
	cfg.Security.DevMode = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("dev mode should allow placeholder secret: %v", err)
	}
}
