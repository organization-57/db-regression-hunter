package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/makeev/db-regression-hunter/internal/demo"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	cfg, err := demo.LoadConfig()
	if err == nil {
		err = demo.Run(ctx, cfg)
	}
	if err != nil && ctx.Err() == nil {
		slog.Error("demo stopped", "error", err)
		os.Exit(1)
	}
}
