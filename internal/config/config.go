package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	DatabaseURL, HTTPAddr, TelegramToken, TelegramChatID, GrafanaURL string
	PollInterval                                                     time.Duration
	BaselineSamples, ConfirmSamples                                  int
	DegradationFactor                                                float64
	SQLStatsEnabled                                                  bool
}

func Load() (Config, error) {
	c := Config{DatabaseURL: os.Getenv("DATABASE_URL"), HTTPAddr: value("HTTP_ADDR", ":8080"), TelegramToken: os.Getenv("TELEGRAM_BOT_TOKEN"), TelegramChatID: os.Getenv("TELEGRAM_CHAT_ID"), GrafanaURL: os.Getenv("GRAFANA_URL")}
	var err error
	if c.DatabaseURL == "" {
		return c, fmt.Errorf("DATABASE_URL is required")
	}
	if c.SQLStatsEnabled, err = strconv.ParseBool(value("SQL_STATS_ENABLED", "true")); err != nil {
		return c, fmt.Errorf("SQL_STATS_ENABLED must be a boolean")
	}
	if c.PollInterval, err = time.ParseDuration(value("POLL_INTERVAL", "10s")); err != nil || c.PollInterval < time.Second {
		return c, fmt.Errorf("POLL_INTERVAL must be a duration >= 1s")
	}
	if c.BaselineSamples, err = strconv.Atoi(value("BASELINE_SAMPLES", "20")); err != nil || c.BaselineSamples < 3 || c.BaselineSamples > 10000 {
		return c, fmt.Errorf("BASELINE_SAMPLES must be between 3 and 10000")
	}
	if c.ConfirmSamples, err = strconv.Atoi(value("CONFIRM_SAMPLES", "3")); err != nil || c.ConfirmSamples < 1 {
		return c, fmt.Errorf("CONFIRM_SAMPLES must be positive")
	}
	if c.DegradationFactor, err = strconv.ParseFloat(value("DEGRADATION_FACTOR", "3"), 64); err != nil || !(c.DegradationFactor > 1 && c.DegradationFactor < 1000) {
		return c, fmt.Errorf("DEGRADATION_FACTOR must be between 1 and 1000, exclusive")
	}
	if (c.TelegramToken == "") != (c.TelegramChatID == "") {
		return c, fmt.Errorf("set both TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID")
	}
	if c.TelegramChatID != "" {
		if _, err = strconv.ParseInt(c.TelegramChatID, 10, 64); err != nil {
			return c, fmt.Errorf("TELEGRAM_CHAT_ID must be an integer")
		}
	}
	return c, nil
}

func value(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
