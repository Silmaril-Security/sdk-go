// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxErrorBodyBytes = 1 << 16

func (f *Firewall) postJSON(ctx context.Context, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("firewall: marshal request: %w", err)
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.apiURL, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("firewall: build request: %w", err)
		}
		req.Header.Set("x-api-key", f.apiKey)
		req.Header.Set("content-type", "application/json")
		resp, err := f.httpClient.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if attempt < f.maxRetries {
				if err := waitBeforeRetry(ctx, f.retryDelay(attempt, nil)); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("firewall: request failed: %w", err)
		}
		if isRetryableStatus(resp.StatusCode) && attempt < f.maxRetries {
			wait := f.retryDelay(attempt, resp)
			drainAndClose(resp.Body)
			if err := waitBeforeRetry(ctx, wait); err != nil {
				return err
			}
			continue
		}
		if resp.StatusCode >= 400 {
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
			_ = resp.Body.Close()
			apiErr := &APIError{
				Status:     resp.StatusCode,
				StatusText: http.StatusText(resp.StatusCode),
				Body:       string(bodyBytes),
			}
			var parsed struct {
				Details *MalformedInputDetails `json:"details"`
			}
			if err := json.Unmarshal(bodyBytes, &parsed); err == nil {
				apiErr.Details = parsed.Details
			}
			return apiErr
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			_ = resp.Body.Close()
			return fmt.Errorf("firewall: decode response: %w", err)
		}
		_ = resp.Body.Close()
		return nil
	}
}

func isRetryableStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func (f *Firewall) retryDelay(attempt int, resp *http.Response) time.Duration {
	if resp != nil {
		if delay, ok := retryAfter(resp.Header.Get("Retry-After")); ok {
			return delay
		}
	}
	delay := cappedExponentialBackoff(f.retryBaseBackoff, f.retryMaxBackoff, attempt)
	if f.retryJitter == nil {
		return delay
	}
	return f.retryJitter(delay)
}

func cappedExponentialBackoff(base, max time.Duration, attempt int) time.Duration {
	if base <= 0 {
		return 0
	}
	if max <= 0 {
		return base
	}
	delay := base
	for i := 0; i < attempt; i++ {
		if delay >= max/2 {
			return max
		}
		delay *= 2
	}
	if delay > max {
		return max
	}
	return delay
}

func fullJitter(delay time.Duration) time.Duration {
	if delay <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(delay)))
}

func retryAfter(value string) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	delay := time.Until(when)
	if delay < 0 {
		delay = 0
	}
	return delay, true
}

func waitBeforeRetry(ctx context.Context, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func drainAndClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}
