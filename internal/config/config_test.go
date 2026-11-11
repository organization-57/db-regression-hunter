package config

import "testing"

func TestSQLRegressionSettings(t *testing.T) {
	for _, test := range []struct {
		name, key, value string
		invalid          bool
	}{
		{name: "defaults"},
		{name: "min_calls", key: "SQL_MIN_CALLS", value: "10"},
		{name: "zero_calls", key: "SQL_MIN_CALLS", value: "0", invalid: true},
		{name: "invalid_calls", key: "SQL_MIN_CALLS", value: "five", invalid: true},
		{name: "negative_floor", key: "SQL_MIN_INCREASE_MS", value: "-1", invalid: true},
		{name: "nan_floor", key: "SQL_MIN_INCREASE_MS", value: "NaN", invalid: true},
		{name: "infinite_floor", key: "SQL_MIN_INCREASE_MS", value: "+Inf", invalid: true},
		{name: "zero_floor", key: "SQL_MIN_INCREASE_MS", value: "0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("DATABASE_URL", "postgres://unused/demo")
			for _, key := range []string{"SQL_MIN_CALLS", "SQL_MIN_INCREASE_MS", "SQL_STATS_ENABLED", "POLL_INTERVAL", "BASELINE_SAMPLES", "CONFIRM_SAMPLES", "DEGRADATION_FACTOR", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"} {
				t.Setenv(key, "")
			}
			if test.key != "" {
				t.Setenv(test.key, test.value)
			}
			cfg, err := Load()
			if test.invalid {
				if err == nil {
					t.Fatal("invalid SQL setting accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "defaults" && (cfg.SQLMinCalls != 5 || cfg.SQLMinIncreaseMS != 5) {
				t.Fatalf("unexpected defaults: %+v", cfg)
			}
			if test.name == "min_calls" && cfg.SQLMinCalls != 10 {
				t.Fatal("min calls not applied")
			}
			if test.name == "zero_floor" && cfg.SQLMinIncreaseMS != 0 {
				t.Fatal("zero floor not applied")
			}
		})
	}
}
