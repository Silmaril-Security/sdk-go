// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import "fmt"

// MalformedInputDetails carries a prompt-minimal diagnostic returned by the API
// when malformed text still reaches tokenization.
type MalformedInputDetails struct {
	Field          string `json:"field,omitempty"`
	InputIndex     *int   `json:"inputIndex,omitempty"`
	CharOffset     *int   `json:"charOffset,omitempty"`
	MalformedToken string `json:"malformedToken,omitempty"`
	CodePoint      string `json:"codePoint,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// APIError is returned when the firewall API responds with a non-2xx status
// after any retryable response has been exhausted.
type APIError struct {
	Status     int
	StatusText string
	Body       string
	Details    *MalformedInputDetails
}

func (e *APIError) Error() string {
	if e.StatusText == "" {
		return fmt.Sprintf("Silmaril API error %d", e.Status)
	}
	return fmt.Sprintf("Silmaril API error %d %s", e.Status, e.StatusText)
}

// PromptBlockedError is returned by Classify when a classified prompt meets or
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

// BlockedBatchItem describes one blocked item in a ClassifyBatch call.
type BlockedBatchItem struct {
	Index    int
	Text     string
	Hook     HookLabel
	ToolName string
	Result   BlockResult
}

// BatchPromptBlockedError is returned by ClassifyBatch when one or more
// classified texts meet or exceed the effective threshold and shadow mode is
// not enabled.
type BatchPromptBlockedError struct {
	Blocked []BlockedBatchItem
}

func (e *BatchPromptBlockedError) Error() string {
	if len(e.Blocked) == 1 {
		item := e.Blocked[0]
		return fmt.Sprintf(
			"firewall: batch prompt blocked at index %d (score=%.4f, threshold=%.4f)",
			item.Index,
			item.Result.Score,
			item.Result.Threshold,
		)
	}
	return fmt.Sprintf("firewall: batch prompts blocked (%d items)", len(e.Blocked))
}
