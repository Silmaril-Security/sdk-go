// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMaxRetries = 5
	defaultTimeout    = 10 * time.Second
)

// retryBaseBackoff and retryMaxBackoff are package-level vars so tests can
// shorten the exponential backoff without waiting real seconds.
var (
	retryBaseBackoff = time.Second
	retryMaxBackoff  = 30 * time.Second
)

// Firewall is a client for the Silmaril Firewall /classify endpoint.
// Instances are safe for concurrent use.
type Firewall struct {
	apiKey         string
	apiURL         string
	threshold      float64
	timeout        time.Duration
	hookThresholds map[HookLabel]float64
	shadowMode     bool
	httpClient     *http.Client
}

// New constructs a Firewall from Options. Returns an error when APIKey or
// APIURL is empty.
func New(opts Options) (*Firewall, error) {
	if opts.APIKey == "" {
		return nil, errors.New("firewall: APIKey is required")
	}
	if opts.APIURL == "" {
		return nil, errors.New("firewall: APIURL is required")
	}
	threshold := opts.Threshold
	if threshold == 0 {
		threshold = DefaultThreshold
	}
	if !validThreshold(threshold) {
		return nil, fmt.Errorf("firewall: Threshold must be between 0 and 1, got %v", threshold)
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	hookThresholds := make(map[HookLabel]float64, len(opts.HookThresholds))
	for k, v := range opts.HookThresholds {
		if !validThreshold(v) {
			return nil, fmt.Errorf("firewall: HookThresholds[%q] must be between 0 and 1, got %v", k, v)
		}
		hookThresholds[k] = v
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	return &Firewall{
		apiKey:         opts.APIKey,
		apiURL:         opts.APIURL,
		threshold:      threshold,
		timeout:        timeout,
		hookThresholds: hookThresholds,
		shadowMode:     opts.ShadowMode,
		httpClient:     httpClient,
	}, nil
}

// Threshold returns the configured default score threshold.
func (f *Firewall) Threshold() float64 { return f.threshold }

// EffectiveThreshold returns the configured threshold for hook, falling back
// to the client's default threshold.
func (f *Firewall) EffectiveThreshold(hook HookLabel) float64 {
	if hook != "" {
		if threshold, ok := f.hookThresholds[hook]; ok {
			return threshold
		}
	}
	return f.threshold
}

// HookThresholds returns a copy of the per-hook threshold overrides.
func (f *Firewall) HookThresholds() map[HookLabel]float64 {
	out := make(map[HookLabel]float64, len(f.hookThresholds))
	for k, v := range f.hookThresholds {
		out[k] = v
	}
	return out
}

// ShadowMode reports whether the client was configured for shadow mode.
func (f *Firewall) ShadowMode() bool { return f.shadowMode }

// ShouldBlock reports whether result should block for hook under this client's
// threshold configuration. It returns false in shadow mode.
func (f *Firewall) ShouldBlock(result BlockResult, hook HookLabel) bool {
	return !f.shadowMode && result.Score >= f.EffectiveThreshold(hook)
}

type singleRequestPayload struct {
	Text      string    `json:"text"`
	Hook      HookLabel `json:"hook,omitempty"`
	ToolName  string    `json:"tool_name,omitempty"`
	Threshold float64   `json:"threshold"`
}

type batchRequestPayload struct {
	Texts     []string    `json:"texts"`
	Hooks     []HookLabel `json:"hooks,omitempty"`
	ToolNames []*string   `json:"tool_names,omitempty"`
	Threshold float64     `json:"threshold"`
}

type singleResponse struct {
	Prediction Prediction `json:"prediction"`
	Score      float64    `json:"score"`
}

type batchResponse struct {
	Predictions []singleResponse `json:"predictions"`
}

// Classify classifies a single text. Long inputs are chunked client-side
// and sent as a batch; the highest score across chunks is returned.
func (f *Firewall) Classify(ctx context.Context, text string, opts ...ClassifyOption) (BlockResult, error) {
	var cfg classifyConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	chunks, err := ChunkText(text)
	if err != nil {
		return BlockResult{}, err
	}
	if len(chunks) == 1 {
		payload := singleRequestPayload{
			Text:      chunks[0],
			Threshold: f.EffectiveThreshold(cfg.hook),
		}
		if cfg.hook != "" {
			payload.Hook = cfg.hook
		}
		if cfg.toolName != "" {
			payload.ToolName = cfg.toolName
		}
		var resp singleResponse
		if err := f.postJSON(ctx, payload, &resp); err != nil {
			return BlockResult{}, err
		}
		return f.resultForScore(resp.Score, cfg.hook), nil
	}
	results, err := f.classifyChunks(ctx, chunks, cfg)
	if err != nil {
		return BlockResult{}, err
	}
	best := results[0]
	for _, r := range results[1:] {
		if r.Score > best.Score {
			best = r
		}
	}
	return best, nil
}

func (f *Firewall) classifyChunks(ctx context.Context, chunks []string, cfg classifyConfig) ([]BlockResult, error) {
	payload := batchRequestPayload{
		Texts:     chunks,
		Threshold: f.EffectiveThreshold(cfg.hook),
	}
	if cfg.hook != "" {
		payload.Hooks = repeatHooks(cfg.hook, len(chunks))
	}
	if cfg.toolName != "" {
		payload.ToolNames = repeatToolNames(cfg.toolName, len(chunks))
	}
	var resp batchResponse
	if err := f.postJSON(ctx, payload, &resp); err != nil {
		return nil, err
	}
	if len(resp.Predictions) != len(chunks) {
		return nil, fmt.Errorf("firewall: predictions length %d does not match chunks length %d", len(resp.Predictions), len(chunks))
	}
	results := make([]BlockResult, len(resp.Predictions))
	for i, p := range resp.Predictions {
		results[i] = f.resultForScore(p.Score, cfg.hook)
	}
	return results, nil
}

func repeatHooks(hook HookLabel, n int) []HookLabel {
	hooks := make([]HookLabel, n)
	for i := range hooks {
		hooks[i] = hook
	}
	return hooks
}

func repeatToolNames(toolName string, n int) []*string {
	names := make([]*string, n)
	for i := range names {
		name := toolName
		names[i] = &name
	}
	return names
}

func (f *Firewall) resultForScore(score float64, hook HookLabel) BlockResult {
	prediction := PredictionBenign
	if score >= f.EffectiveThreshold(hook) {
		prediction = PredictionMalicious
	}
	return BlockResult{Prediction: prediction, Score: score}
}

func validThreshold(threshold float64) bool {
	return threshold >= 0 && threshold <= 1
}

func (f *Firewall) postJSON(ctx context.Context, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("firewall: marshal request: %w", err)
	}
	for attempt := 0; attempt <= defaultMaxRetries; attempt++ {
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
			if attempt < defaultMaxRetries {
				if err := waitBeforeRetry(ctx, retryDelay(attempt, nil)); err != nil {
					return err
				}
				continue
			}
			return err
		}
		if isRetryableStatus(resp.StatusCode) && attempt < defaultMaxRetries {
			wait := retryDelay(attempt, resp)
			resp.Body.Close()
			if err := waitBeforeRetry(ctx, wait); err != nil {
				return err
			}
			continue
		}
		if resp.StatusCode >= 400 {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return &APIError{
				Status:     resp.StatusCode,
				StatusText: http.StatusText(resp.StatusCode),
				Body:       string(bodyBytes),
			}
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			resp.Body.Close()
			return fmt.Errorf("firewall: decode response: %w", err)
		}
		resp.Body.Close()
		return nil
	}
	return errors.New("firewall: max retries exceeded")
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

func retryDelay(attempt int, resp *http.Response) time.Duration {
	if resp != nil {
		if delay, ok := retryAfter(resp.Header.Get("Retry-After")); ok {
			return delay
		}
	}
	delay := retryBaseBackoff * time.Duration(1<<attempt)
	if delay > retryMaxBackoff {
		return retryMaxBackoff
	}
	return delay
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
