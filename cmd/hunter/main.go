package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/config"
	"github.com/makeev/db-regression-hunter/internal/detector"
	"github.com/makeev/db-regression-hunter/internal/httpapi"
	"github.com/makeev/db-regression-hunter/internal/state"
	"github.com/makeev/db-regression-hunter/internal/telegram"
)

func main() {
	if err := run(); err != nil {
		slog.Error("hunter stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	pg, err := collector.New(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("invalid PostgreSQL connection configuration")
	}
	defer pg.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	store := &state.Store{}
	d := detector.New(cfg.BaselineSamples, cfg.ConfirmSamples, cfg.DegradationFactor)
	maxAge := 3 * cfg.PollInterval
	server := &http.Server{Addr: cfg.HTTPAddr, Handler: httpapi.Handler(store, maxAge), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	var wg sync.WaitGroup
	var bot *telegram.Bot
	notifications := make(chan detector.Incident, 16)
	if cfg.TelegramToken != "" {
		bot = telegram.New(cfg.TelegramToken, cfg.TelegramChatID, cfg.GrafanaURL)
		wg.Add(2)
		go func() {
			defer wg.Done()
			bot.Run(ctx, func() string {
				v := store.View(maxAge)
				if !v.Healthy {
					return "Сбор метрик недоступен или данные устарели"
				}
				return fmt.Sprintf("PostgreSQL доступен\nАктивных сессий: %d\nОжиданий Lock: %d\nВремя снимка: %s", v.Latest.Active, v.Latest.LockWaiters, v.Latest.At.Format(time.RFC3339))
			}, func() string {
				v := store.View(maxAge)
				if len(v.Incidents) == 0 {
					return "Расследований пока нет (возможен прогрев baseline)"
				}
				i := v.Incidents[len(v.Incidents)-1]
				return fmt.Sprintf("%s\n%s\n%s", i.ID, i.StartedAt.Format(time.RFC3339), i.Hypothesis)
			})
		}()
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case i := <-notifications:
					if err := bot.Notify(ctx, i); err != nil {
						slog.Warn("incident notification failed", "incident", i.ID, "error", err)
					}
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(cfg.PollInterval)
		defer ticker.Stop()
		for {
			s, err := pg.Collect(ctx)
			if err != nil {
				store.Failed()
				d.Reset()
				if ctx.Err() == nil {
					slog.Warn("PostgreSQL collection failed; baseline reset")
				}
			} else {
				i := d.Observe(s)
				store.Update(s, i)
				if i != nil {
					slog.Info("incident detected", "id", i.ID, "hypothesis", i.Hypothesis)
					if bot != nil {
						select {
						case notifications <- *i:
						default:
							slog.Warn("notification queue full", "incident", i.ID)
						}
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	serverErrors := make(chan error, 1)
	go func() { slog.Info("hunter listening", "addr", cfg.HTTPAddr); serverErrors <- server.ListenAndServe() }()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-serverErrors:
	}
	cancel()
	shutdownCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	err = server.Shutdown(shutdownCtx)
	wg.Wait()
	if serveErr != nil && serveErr != http.ErrServerClosed {
		return serveErr
	}
	return err
}
