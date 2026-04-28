// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import "fmt"

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

// PromptBlockedError is returned by Check when a classified prompt meets or
// exceeds the effective threshold and shadow mode is not enabled.
type PromptBlockedError struct {
	Score      float64
	Threshold  float64
	PromptText string
	Hook       HookLabel
	ToolName   string
	Result     BlockResult
}

func (e *PromptBlockedError) Error() string {
	return fmt.Sprintf("firewall: prompt blocked (score=%.4f, threshold=%.4f)", e.Score, e.Threshold)
}
