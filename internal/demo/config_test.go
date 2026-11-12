package demo

import (
	"strings"
	"testing"
	"time"
)

func TestLoadConfigCooldown(t *testing.T) {
	t.Setenv("DEMO_DATABASE_URL", "postgres://demo:demo@localhost/demo")
	for _, key := range []string{"POLL_INTERVAL", "BASELINE_SAMPLES", "CONFIRM_SAMPLES", "DEMO_WARMUP", "DEMO_INCIDENT_DURATION", "DEMO_SCENARIOS"} {
		t.Setenv(key, "")
	}
	for _, tc := range []struct {
		name, value string
		want        time.Duration
		invalid     bool
	}{
		{name: "default", want: time.Minute},
		{name: "explicit override", value: "3m", want: 3 * time.Minute},
		{name: "minimum", value: "1s", want: time.Second},
		{name: "malformed", value: "invalid", invalid: true},
		{name: "zero", value: "0s", invalid: true},
		{name: "negative", value: "-1s", invalid: true},
		{name: "below minimum", value: "500ms", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEMO_COOLDOWN", tc.value)
			cfg, err := LoadConfig()
			if tc.invalid {
				if err == nil || !strings.Contains(err.Error(), "DEMO_COOLDOWN") {
					t.Fatalf("expected cooldown validation error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Cooldown != tc.want {
				t.Fatalf("cooldown = %s, want %s", cfg.Cooldown, tc.want)
			}
			if cfg.Warmup != 250*time.Second || cfg.Duration != time.Minute {
				t.Fatalf("unexpected other timings: warmup %s, duration %s", cfg.Warmup, cfg.Duration)
			}
		})
	}
}
