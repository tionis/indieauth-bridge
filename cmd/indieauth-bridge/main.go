package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eric/indieauth-bridge/internal/backends"
	"github.com/eric/indieauth-bridge/internal/backends/authentik"
	oidcbackend "github.com/eric/indieauth-bridge/internal/backends/oidc"
	"github.com/eric/indieauth-bridge/internal/config"
	bridgehttp "github.com/eric/indieauth-bridge/internal/http"
	"github.com/eric/indieauth-bridge/internal/storage"
)

func main() {
	configPath := flag.String("config", "", "path to config file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("configuration failed", "err", err)
		os.Exit(1)
	}
	if cfg.Security.DevMode {
		logger.Warn("dev mode is enabled; HTTP URLs and placeholder secrets may be accepted")
	}

	store, err := storage.OpenSQLite(ctx, cfg.Storage.Path)
	if err != nil {
		logger.Error("storage open failed", "err", err)
		os.Exit(1)
	}
	defer store.Close()
	if err := store.Cleanup(ctx, time.Now()); err != nil {
		logger.Warn("startup cleanup failed", "err", err)
	}

	backendMap, err := buildBackends(ctx, cfg)
	if err != nil {
		logger.Error("backend initialization failed", "err", err)
		os.Exit(1)
	}
	app := bridgehttp.NewServer(cfg, store, backendMap, logger)
	server := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           app.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go periodicCleanup(ctx, logger, store)
	go func() {
		logger.Info("listening", "addr", cfg.Server.Listen, "issuer", cfg.Server.Issuer)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server failed", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
}

func buildBackends(ctx context.Context, cfg config.Config) (map[string]backends.Backend, error) {
	out := map[string]backends.Backend{}
	for name, b := range cfg.Backends {
		backendCfg := oidcbackend.Config{
			Name:               name,
			Issuer:             b.Issuer,
			ClientID:           b.ClientID,
			ClientSecret:       b.ClientSecret,
			RedirectURI:        b.RedirectURI,
			Scopes:             b.Scopes,
			InsecureSkipVerify: b.InsecureSkipVerify || cfg.Security.DevMode,
		}
		switch b.Type {
		case "authentik":
			backend, err := authentik.New(ctx, backendCfg)
			if err != nil {
				return nil, err
			}
			out[name] = backend
		case "oidc":
			backend, err := oidcbackend.New(ctx, backendCfg)
			if err != nil {
				return nil, err
			}
			out[name] = backend
		default:
			return nil, errors.New("unsupported backend type: " + b.Type)
		}
	}
	return out, nil
}

func periodicCleanup(ctx context.Context, logger *slog.Logger, store storage.Store) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := store.Cleanup(ctx, now); err != nil {
				logger.Warn("periodic cleanup failed", "err", err)
			}
		}
	}
}
