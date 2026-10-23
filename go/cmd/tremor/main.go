// Command tremor runs the TREMOR at Scale log pipeline server.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/mokshad/tremor/internal/config"
	"github.com/mokshad/tremor/internal/server"
)

func main() {
	cfgPath := flag.String("config", "", "path to YAML config (defaults used if empty)")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := server.New(cfg, log)
	srv.PublishExpvar = true
	if err := srv.Run(ctx); err != nil {
		log.Error("exit", "err", err)
		os.Exit(1)
	}
}
