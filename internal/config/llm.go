package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const DefaultModels = "deepseek-ai/DeepSeek-V4-Flash-0731,MiniMaxAI/MiniMax-M2.7"

type LLM struct {
	APIKey, BaseURL string
	Models          []string
	Delay           time.Duration
	SQLText         bool
}

func (l LLM) Enabled() bool { return l.APIKey != "" }

func LoadLLM() (LLM, error) {
	l := LLM{APIKey: os.Getenv("GONKA_API_KEY"), BaseURL: value("GONKA_BASE_URL", "https://api.openbroker.gonka.gg/v1")}
	if !l.Enabled() {
		return l, nil
	}
	for _, m := range strings.Split(value("GONKA_MODELS", DefaultModels), ",") {
		if m = strings.TrimSpace(m); m != "" {
			l.Models = append(l.Models, m)
		}
	}
	if len(l.Models) == 0 {
		return l, fmt.Errorf("GONKA_MODELS is empty")
	}
	var err error
	if l.Delay, err = time.ParseDuration(value("ANALYSIS_DELAY", "25s")); err != nil || l.Delay <= 0 {
		return l, fmt.Errorf("ANALYSIS_DELAY must be a positive duration")
	}
	if l.SQLText, err = strconv.ParseBool(value("ANALYSIS_SQL_TEXT", "true")); err != nil {
		return l, fmt.Errorf("ANALYSIS_SQL_TEXT must be true or false")
	}
	return l, nil
}
