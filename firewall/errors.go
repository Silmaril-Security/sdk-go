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
