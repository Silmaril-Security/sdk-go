// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

package silmaril

import "fmt"

const maxPromptDisplayLen = 100

// PromptBlockedError is returned (by higher-level adapters) when a prompt's
// score meets or exceeds the configured threshold.
type PromptBlockedError struct {
	Score      float64
	Threshold  float64
	PromptText string
	RunID      string
}

func (e *PromptBlockedError) Error() string {
	runes := []rune(e.PromptText)
	truncated := e.PromptText
	if len(runes) > maxPromptDisplayLen {
		truncated = string(runes[:maxPromptDisplayLen]) + "..."
	}
	return fmt.Sprintf(
		"Prompt blocked by Silmaril Firewall (score=%.4f, threshold=%.4f): '%s'",
		e.Score, e.Threshold, truncated,
	)
}

// APIError is returned when the firewall API responds with a non-2xx status
// after any retryable response has been exhausted.
type APIError struct {
	Status     int
	StatusText string
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Silmaril API error %d %s: %s", e.Status, e.StatusText, e.Body)
}
