// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

package firewall

import (
	"errors"
	"strings"
	"testing"
)

func TestPromptBlockedErrorFormat(t *testing.T) {
	err := &PromptBlockedError{
		Score:      0.9,
		Threshold:  0.8,
		PromptText: "bad prompt",
	}
	msg := err.Error()
	if !strings.Contains(msg, "score=0.9000") {
		t.Errorf("missing score in %q", msg)
	}
	if !strings.Contains(msg, "threshold=0.8000") {
		t.Errorf("missing threshold in %q", msg)
	}
	if !strings.Contains(msg, "bad prompt") {
		t.Errorf("missing prompt in %q", msg)
	}
}

func TestPromptBlockedErrorTruncation(t *testing.T) {
	long := strings.Repeat("a", 150)
	err := &PromptBlockedError{
		Score:      0.9,
		Threshold:  0.8,
		PromptText: long,
	}
	msg := err.Error()
	if !strings.Contains(msg, "...") {
		t.Errorf("expected truncation marker in %q", msg)
	}
	if strings.Contains(msg, strings.Repeat("a", 101)) {
		t.Error("not truncated at 100 chars")
	}
	if !strings.Contains(msg, strings.Repeat("a", 100)+"...") {
		t.Error("expected exactly 100 chars before ...")
	}
}

func TestPromptBlockedErrorNoTruncationAtBoundary(t *testing.T) {
	exactly := strings.Repeat("a", 100)
	err := &PromptBlockedError{Score: 0.9, Threshold: 0.8, PromptText: exactly}
	msg := err.Error()
	if strings.Contains(msg, "...") {
		t.Errorf("should not truncate at exactly 100 chars: %q", msg)
	}
}

func TestPromptBlockedErrorAs(t *testing.T) {
	var err error = &PromptBlockedError{Score: 0.9, Threshold: 0.8, PromptText: "x"}
	var blocked *PromptBlockedError
	if !errors.As(err, &blocked) {
		t.Fatal("errors.As failed")
	}
	if blocked.Score != 0.9 {
		t.Errorf("Score = %v", blocked.Score)
	}
}

func TestAPIErrorFormat(t *testing.T) {
	err := &APIError{Status: 429, StatusText: "Too Many Requests", Body: "rate limit"}
	msg := err.Error()
	if !strings.Contains(msg, "429") || !strings.Contains(msg, "Too Many Requests") || !strings.Contains(msg, "rate limit") {
		t.Errorf("APIError format: %q", msg)
	}
}

func TestAPIErrorAs(t *testing.T) {
	var err error = &APIError{Status: 500, StatusText: "Internal Server Error", Body: "boom"}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatal("errors.As failed")
	}
	if apiErr.Status != 500 {
		t.Errorf("Status = %v", apiErr.Status)
	}
}
