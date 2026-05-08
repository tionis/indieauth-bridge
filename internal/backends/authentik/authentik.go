package authentik

import (
	"context"

	"github.com/eric/indieauth-bridge/internal/backends/oidc"
)

const Name = "authentik"

type Config = oidc.Config

func New(ctx context.Context, cfg Config) (*oidc.Backend, error) {
	cfg.Name = Name
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	return oidc.New(ctx, cfg)
}
