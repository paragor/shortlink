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
	_ "time/tzdata"

	"github.com/paragor/shortlink/internal/httpserver"
	"github.com/paragor/shortlink/internal/log"
	"github.com/paragor/shortlink/internal/shortlink"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen                     string `yaml:"listen"`
	ServerPublicUrl            string `yaml:"server_public_url"`
	DiagnosticEndpointsEnabled bool   `yaml:"diagnostic_endpoints_enabled"`

	Oidc struct {
		ClientId     string   `yaml:"client_id"`
		ClientSecret string   `yaml:"client_secret"`
		IssuerUrl    string   `yaml:"issuer_url"`
		CookieKey    string   `yaml:"cookie_key"`
		Scopes       []string `yaml:"scopes"`
		AllowedGroup string   `yaml:"allowed_group"`
	} `yaml:"oidc"`
}

func main() {
	logger := log.FromContext(context.Background())

	configPath := flag.String("config", "config.yaml", "path to config")
	dumpDefaultConfig := flag.Bool("dump-default-config", false, "dump default config")
	flag.Parse()

	cfg := &Config{}
	cfg.Listen = "127.0.0.1:8080"
	cfg.ServerPublicUrl = "http://127.0.0.1:8080"
	cfg.Oidc.Scopes = []string{"openid", "email", "profile", "offline_access"}

	if *dumpDefaultConfig {
		cfg.Oidc.CookieKey = "kiel4teof4Eoziheigiesh6ooquiepho"
		if err := yaml.NewEncoder(os.Stdout).Encode(cfg); err != nil {
			logger.With(log.Error(err)).Error("fail to dump default config")
			os.Exit(1)
		}
		os.Exit(0)
	}

	cfgContent, err := os.ReadFile(*configPath)
	if err != nil {
		logger.With(log.Error(err), slog.String("path", *configPath)).Error("fail to read config")
		os.Exit(1)
	}
	if err := yaml.Unmarshal(cfgContent, cfg); err != nil {
		logger.With(log.Error(err), slog.String("path", *configPath)).Error("fail to unmarshal config")
		os.Exit(1)
	}

	auth := &httpserver.AuthOidcConfig{
		ClientId:     cfg.Oidc.ClientId,
		ClientSecret: cfg.Oidc.ClientSecret,
		IssuerUrl:    cfg.Oidc.IssuerUrl,
		CookieKey:    cfg.Oidc.CookieKey,
		Scopes:       cfg.Oidc.Scopes,
		AllowedGroup: cfg.Oidc.AllowedGroup,
	}
	if err := auth.Validate(); err != nil {
		logger.With(log.Error(err)).Error("invalid oauth config")
		os.Exit(1)
	}

	server, err := httpserver.NewHttpServer(
		cfg.Listen,
		shortlink.NewStorage(),
		auth,
		cfg.ServerPublicUrl,
		cfg.DiagnosticEndpointsEnabled,
	)
	if err != nil {
		logger.With(log.Error(err)).Error("fail to start server")
		os.Exit(1)
	}

	mainCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("server started!")
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
		close(serverErrors)
	}()
	select {
	case <-mainCtx.Done():
		logger.Info("graceful shutdown starts...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		err := server.Shutdown(shutdownCtx)
		if err != nil {
			logger.With(log.Error(err)).Error("fail to shutdown server")
			os.Exit(1)
		}
	case err := <-serverErrors:
		logger.With(log.Error(err)).Error("fail on start server")
		os.Exit(1)
	}

	logger.Info("graceful shutdown complete!")
}
