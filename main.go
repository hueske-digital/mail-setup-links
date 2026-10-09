// Command mail-setup-links serves prefilled links that guide customers through setting up
// a mail account: signed configuration profiles for Apple devices, personalised steps for
// other mail programs.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hueske-digital/mail-setup-links/internal/config"
	"github.com/hueske-digital/mail-setup-links/internal/signing"
	"github.com/hueske-digital/mail-setup-links/internal/web"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("service stopped", "error", err)
		os.Exit(1)
	}
}

// healthcheck is the image's health probe (HEALTHCHECK of the Dockerfile).
func healthcheck() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://" + net.JoinHostPort("127.0.0.1", port) + "/healthz")
	if err != nil {
		return 1
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func run(log *slog.Logger) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	opts := web.Options{Config: cfg, Now: time.Now, Log: log}
	var manager *signing.Manager
	if cfg.ACME != nil {
		manager, err = signing.NewManager(signing.ManagerOptions{
			DirectoryURL: cfg.ACME.DirectoryURL,
			Email:        cfg.ACME.Email,
			Hostname:     cfg.PublicURL.Hostname(),
			DataDir:      cfg.ACME.DataDir,
			Now:          time.Now,
			Log:          log,
		})
		if err != nil {
			return err
		}
		opts.Signer, opts.Challenges = manager, manager
	}
	handler, err := web.New(opts)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	failed := make(chan error, 1)
	go func() { failed <- srv.ListenAndServe() }()
	log.Info("listening", "addr", cfg.ListenAddr, "signing", cfg.ACME != nil)
	if manager != nil {
		// The server above answers the HTTP-01 challenges the manager triggers.
		go manager.Run(ctx)
	}

	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
