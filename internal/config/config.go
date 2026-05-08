package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/eric/indieauth-bridge/internal/security"
	"gopkg.in/yaml.v3"
)

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

func (d Duration) MarshalYAML() (any, error) {
	return d.String(), nil
}

type Config struct {
	Server   ServerConfig             `yaml:"server"`
	Security SecurityConfig           `yaml:"security"`
	Profiles []ProfileConfig          `yaml:"profiles"`
	Backends map[string]BackendConfig `yaml:"backends"`
	Storage  StorageConfig            `yaml:"storage"`
}

type ServerConfig struct {
	Listen         string   `yaml:"listen"`
	PublicURL      string   `yaml:"public_url"`
	Issuer         string   `yaml:"issuer"`
	TrustedProxies []string `yaml:"trusted_proxies"`
}

type SecurityConfig struct {
	CookieSecret   string   `yaml:"cookie_secret"`
	CodeTTL        Duration `yaml:"code_ttl"`
	AuthRequestTTL Duration `yaml:"auth_request_ttl"`
	AccessTokenTTL Duration `yaml:"access_token_ttl"`
	RequireHTTPS   bool     `yaml:"require_https"`
	RequirePKCE    bool     `yaml:"require_pkce"`
	DevMode        bool     `yaml:"dev_mode"`
}

type ProfileConfig struct {
	Me               string   `yaml:"me"`
	DisplayName      string   `yaml:"display_name"`
	Email            string   `yaml:"email"`
	Backend          string   `yaml:"backend"`
	AllowedSubjects  []string `yaml:"allowed_subjects"`
	AllowedUsernames []string `yaml:"allowed_usernames"`
	AllowedEmails    []string `yaml:"allowed_emails"`
	AllowedGroups    []string `yaml:"allowed_groups"`
}

type BackendConfig struct {
	Type               string   `yaml:"type"`
	Issuer             string   `yaml:"issuer"`
	ClientID           string   `yaml:"client_id"`
	ClientSecret       string   `yaml:"client_secret"`
	RedirectURI        string   `yaml:"redirect_uri"`
	Scopes             []string `yaml:"scopes"`
	InsecureSkipVerify bool     `yaml:"insecure_skip_verify"`
}

type StorageConfig struct {
	Type string `yaml:"type"`
	Path string `yaml:"path"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			Listen: ":8080",
		},
		Security: SecurityConfig{
			CodeTTL:        Duration{Duration: 5 * time.Minute},
			AuthRequestTTL: Duration{Duration: 10 * time.Minute},
			AccessTokenTTL: Duration{Duration: 24 * time.Hour},
			RequireHTTPS:   true,
			RequirePKCE:    true,
		},
		Backends: map[string]BackendConfig{},
		Storage: StorageConfig{
			Type: "sqlite",
			Path: "/data/bridge.db",
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		path = os.Getenv("IAB_CONFIG")
	}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return Config{}, err
		}
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return Config{}, err
		}
	}
	applyEnv(&cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config) {
	set := func(key string, dst *string) {
		if v := os.Getenv(key); v != "" {
			*dst = v
		}
	}
	set("IAB_SERVER_LISTEN", &cfg.Server.Listen)
	set("IAB_SERVER_PUBLIC_URL", &cfg.Server.PublicURL)
	set("IAB_SERVER_ISSUER", &cfg.Server.Issuer)
	set("IAB_SECURITY_COOKIE_SECRET", &cfg.Security.CookieSecret)
	set("IAB_STORAGE_PATH", &cfg.Storage.Path)
	if v := os.Getenv("IAB_SECURITY_DEV_MODE"); v != "" {
		cfg.Security.DevMode = parseBool(v)
	}
	if v := os.Getenv("IAB_SECURITY_REQUIRE_HTTPS"); v != "" {
		cfg.Security.RequireHTTPS = parseBool(v)
	}
	if v := os.Getenv("IAB_SECURITY_REQUIRE_PKCE"); v != "" {
		cfg.Security.RequirePKCE = parseBool(v)
	}
	if cfg.Backends == nil {
		cfg.Backends = map[string]BackendConfig{}
	}
	b := cfg.Backends["authentik"]
	set("IAB_BACKENDS_AUTHENTIK_ISSUER", &b.Issuer)
	set("IAB_BACKENDS_AUTHENTIK_CLIENT_ID", &b.ClientID)
	set("IAB_BACKENDS_AUTHENTIK_CLIENT_SECRET", &b.ClientSecret)
	set("IAB_BACKENDS_AUTHENTIK_REDIRECT_URI", &b.RedirectURI)
	if b.Type == "" && (b.Issuer != "" || b.ClientID != "" || b.ClientSecret != "") {
		b.Type = "authentik"
	}
	if b.Type != "" || b.Issuer != "" || b.ClientID != "" || b.ClientSecret != "" || b.RedirectURI != "" {
		cfg.Backends["authentik"] = b
	}
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func (cfg *Config) Validate() error {
	if cfg.Server.Listen == "" {
		return errors.New("server.listen is required")
	}
	if cfg.Server.PublicURL == "" {
		return errors.New("server.public_url is required")
	}
	publicURL, err := security.CanonicalURL(cfg.Server.PublicURL)
	if err != nil {
		return fmt.Errorf("server.public_url: %w", err)
	}
	cfg.Server.PublicURL = strings.TrimRight(publicURL, "/")
	if cfg.Server.Issuer == "" {
		cfg.Server.Issuer = cfg.Server.PublicURL
	}
	issuer, err := security.CanonicalURL(cfg.Server.Issuer)
	if err != nil {
		return fmt.Errorf("server.issuer: %w", err)
	}
	cfg.Server.Issuer = strings.TrimRight(issuer, "/")
	if cfg.Security.CookieSecret == "" || cfg.Security.CookieSecret == "change-me" {
		if !cfg.Security.DevMode {
			return errors.New("security.cookie_secret must be set to a strong value")
		}
	}
	if cfg.Security.CodeTTL.Duration <= 0 || cfg.Security.AuthRequestTTL.Duration <= 0 || cfg.Security.AccessTokenTTL.Duration <= 0 {
		return errors.New("security TTL values must be positive")
	}
	if len(cfg.Profiles) == 0 {
		return errors.New("at least one profile is required")
	}
	seenProfiles := map[string]bool{}
	for i := range cfg.Profiles {
		p := &cfg.Profiles[i]
		me, err := security.CanonicalURL(p.Me)
		if err != nil {
			return fmt.Errorf("profiles[%d].me: %w", i, err)
		}
		p.Me = me
		if seenProfiles[p.Me] {
			return fmt.Errorf("duplicate profile me %q", p.Me)
		}
		seenProfiles[p.Me] = true
		if p.Backend == "" {
			return fmt.Errorf("profiles[%d].backend is required", i)
		}
		if len(p.AllowedSubjects) == 0 && len(p.AllowedUsernames) == 0 && len(p.AllowedEmails) == 0 && len(p.AllowedGroups) == 0 {
			return fmt.Errorf("profiles[%d] must define at least one allowed identity selector", i)
		}
	}
	if len(cfg.Backends) == 0 {
		return errors.New("at least one backend is required")
	}
	for name, b := range cfg.Backends {
		if b.Type == "" {
			return fmt.Errorf("backends.%s.type is required", name)
		}
		if b.Issuer == "" || b.ClientID == "" || b.ClientSecret == "" || b.RedirectURI == "" {
			return fmt.Errorf("backends.%s issuer, client_id, client_secret, and redirect_uri are required", name)
		}
		if _, err := security.ValidateHTTPSURL(b.Issuer, cfg.Security.DevMode || !cfg.Security.RequireHTTPS); err != nil {
			return fmt.Errorf("backends.%s.issuer: %w", name, err)
		}
		if _, err := security.ValidateHTTPSURL(b.RedirectURI, cfg.Security.DevMode || !cfg.Security.RequireHTTPS); err != nil {
			return fmt.Errorf("backends.%s.redirect_uri: %w", name, err)
		}
		if len(b.Scopes) == 0 {
			b.Scopes = []string{"openid", "profile", "email"}
			cfg.Backends[name] = b
		}
	}
	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "sqlite"
	}
	if cfg.Storage.Type != "sqlite" {
		return fmt.Errorf("unsupported storage.type %q", cfg.Storage.Type)
	}
	if cfg.Storage.Path == "" {
		return errors.New("storage.path is required")
	}
	return nil
}

func (cfg Config) ProfileByMe(me string) (ProfileConfig, bool) {
	canonical, err := security.CanonicalURL(me)
	if err != nil {
		return ProfileConfig{}, false
	}
	for _, p := range cfg.Profiles {
		if p.Me == canonical {
			return p, true
		}
	}
	return ProfileConfig{}, false
}
