// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMaxRetries = 5
	defaultTimeout    = 10 * time.Second
	maxErrorBodyBytes = 1 << 16
)

// Firewall is a client for the Silmaril Firewall /classify endpoint.
// Instances are safe for concurrent use.
type Firewall struct {
	apiKey           string
	apiURL           string
	threshold        float64
	hookThresholds   map[HookLabel]float64
	httpClient       *http.Client
	maxRetries       int
	retryBaseBackoff time.Duration
	retryMaxBackoff  time.Duration
	retryJitter      func(time.Duration) time.Duration
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
	threshold := DefaultThreshold
	if opts.Threshold != nil {
		threshold = *opts.Threshold
	}
	if !validThreshold(threshold) {
		return nil, fmt.Errorf("firewall: Threshold must be between 0 and 1, got %v", threshold)
	}
	timeout := opts.Timeout
	if timeout < 0 {
		return nil, fmt.Errorf("firewall: Timeout must be non-negative, got %v", timeout)
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
		if timeout == 0 {
			timeout = defaultTimeout
		}
		httpClient = &http.Client{Timeout: timeout}
	} else if timeout != 0 {
		clone := *httpClient
		clone.Timeout = timeout
		httpClient = &clone
	}
	return &Firewall{
		apiKey:           opts.APIKey,
		apiURL:           opts.APIURL,
		threshold:        threshold,
		hookThresholds:   hookThresholds,
		httpClient:       httpClient,
		maxRetries:       defaultMaxRetries,
		retryBaseBackoff: time.Second,
		retryMaxBackoff:  30 * time.Second,
		retryJitter:      fullJitter,
	}, nil
}

func (f *Firewall) effectiveThreshold(hook HookLabel) float64 {
	if hook != "" {
		if threshold, ok := f.hookThresholds[hook]; ok {
			return threshold
		}
	}
	return f.threshold
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
		threshold := f.effectiveThreshold(cfg.hook)
		payload := singleRequestPayload{
			Text:      chunks[0],
			Threshold: threshold,
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
		return blockResultFromResponse(resp, threshold)
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
	batchOpts := make([]BatchClassifyOption, 0, 3)
	if cfg.hook != "" {
		batchOpts = append(batchOpts, WithBatchHooks(repeatHooks(cfg.hook, len(chunks))))
	}
	if cfg.toolName != "" {
		batchOpts = append(batchOpts, WithBatchToolNames(repeatToolNames(cfg.toolName, len(chunks))))
	}
	batchOpts = append(batchOpts, WithBatchThreshold(f.effectiveThreshold(cfg.hook)))
	return f.ClassifyBatch(ctx, chunks, batchOpts...)
}

// ClassifyBatch classifies multiple independent texts in a single request.
// When hooks or toolNames are provided, their length must equal len(texts).
func (f *Firewall) ClassifyBatch(ctx context.Context, texts []string, opts ...BatchClassifyOption) ([]BlockResult, error) {
	var cfg batchClassifyConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if len(texts) == 0 {
		return nil, errors.New("firewall: texts must not be empty")
	}
	if len(cfg.hooks) != 0 && len(cfg.hooks) != len(texts) {
		return nil, fmt.Errorf("firewall: hooks length %d does not match texts length %d", len(cfg.hooks), len(texts))
	}
	if len(cfg.toolNames) != 0 && len(cfg.toolNames) != len(texts) {
		return nil, fmt.Errorf("firewall: toolNames length %d does not match texts length %d", len(cfg.toolNames), len(texts))
	}
	threshold := f.batchThreshold(cfg)
	if !validThreshold(threshold) {
		return nil, fmt.Errorf("firewall: batch threshold must be between 0 and 1, got %v", threshold)
	}
	payload := batchRequestPayload{
		Texts:     texts,
		Threshold: threshold,
	}
	if len(cfg.hooks) > 0 {
		payload.Hooks = cfg.hooks
	}
	if len(cfg.toolNames) > 0 {
		payload.ToolNames = batchToolNames(cfg.toolNames)
	}
	var resp batchResponse
	if err := f.postJSON(ctx, payload, &resp); err != nil {
		return nil, err
	}
	if len(resp.Predictions) != len(texts) {
		return nil, fmt.Errorf("firewall: predictions length %d does not match texts length %d", len(resp.Predictions), len(texts))
	}
	results := make([]BlockResult, len(resp.Predictions))
	for i, p := range resp.Predictions {
		result, err := blockResultFromResponse(p, threshold)
		if err != nil {
			return nil, err
		}
		results[i] = result
	}
	return results, nil
}

func (f *Firewall) batchThreshold(cfg batchClassifyConfig) float64 {
	if cfg.threshold != nil {
		return *cfg.threshold
	}
	if len(cfg.hooks) == 0 {
		return f.threshold
	}
	first := cfg.hooks[0]
	for _, hook := range cfg.hooks[1:] {
		if hook != first {
			return f.threshold
		}
	}
	return f.effectiveThreshold(first)
}

func repeatHooks(hook HookLabel, n int) []HookLabel {
	hooks := make([]HookLabel, n)
	for i := range hooks {
		hooks[i] = hook
	}
	return hooks
}

func repeatToolNames(toolName string, n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = toolName
	}
	return names
}

func batchToolNames(names []string) []*string {
	out := make([]*string, len(names))
	for i, name := range names {
		if name == "" {
			continue
		}
		name := name
		out[i] = &name
	}
	return out
}

func blockResultFromResponse(resp singleResponse, threshold float64) (BlockResult, error) {
	switch resp.Prediction {
	case PredictionBenign, PredictionMalicious:
	case "":
		resp.Prediction = predictionForScore(resp.Score, threshold)
	default:
		return BlockResult{}, fmt.Errorf("firewall: invalid prediction %q", resp.Prediction)
	}
	return BlockResult{Prediction: resp.Prediction, Score: resp.Score, Threshold: threshold}, nil
}

func predictionForScore(score, threshold float64) Prediction {
	if score >= threshold {
		return PredictionMalicious
	}
	return PredictionBenign
}

func validThreshold(threshold float64) bool {
	return threshold >= 0 && threshold <= 1
}

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
			return &APIError{
				Status:     resp.StatusCode,
				StatusText: http.StatusText(resp.StatusCode),
				Body:       string(bodyBytes),
			}
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
