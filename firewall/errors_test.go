// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"errors"
	"strings"
	"testing"
)

func TestAPIErrorFormat(t *testing.T) {
	err := &APIError{Status: 429, StatusText: "Too Many Requests", Body: "rate limit"}
	msg := err.Error()
	if msg != "Silmaril API error 429 Too Many Requests" {
		t.Errorf("APIError format: %q", msg)
	}
	if strings.Contains(msg, err.Body) {
		t.Fatal("APIError message should not expose the body")
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
