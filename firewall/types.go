// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"net/http"
	"time"
)

// Prediction is the classifier's verdict for a single text.
type Prediction string

const (
	PredictionBenign    Prediction = "BENIGN"
	PredictionMalicious Prediction = "MALICIOUS"
)

// BlockResult is the output of a single classification call.
type BlockResult struct {
	Prediction Prediction `json:"prediction"`
	Score      float64    `json:"score"`
	Threshold  float64    `json:"threshold"`
}

// Options configures a Firewall client. APIKey and APIURL are required.
// Threshold is optional; nil falls back to DefaultThreshold, while a pointer
// to 0 is honored as "block everything". Timeout defaults to 10 seconds for
// the default HTTP client. When HTTPClient is set, Timeout is applied only
// when explicitly non-zero, by cloning the provided client.
type Options struct {
	APIKey         string
	APIURL         string
	Threshold      *float64
	Timeout        time.Duration
	HookThresholds map[HookLabel]float64
	HTTPClient     *http.Client
}

type classifyConfig struct {
	hook     HookLabel
	toolName string
}

// ClassifyOption customizes a single Classify call.
type ClassifyOption func(*classifyConfig)

// WithHook sets the pipeline-stage label for the classified text.
func WithHook(hook HookLabel) ClassifyOption {
	return func(c *classifyConfig) { c.hook = hook }
}

// WithToolName sets the tool name for tool-name-aware classification.
func WithToolName(name string) ClassifyOption {
	return func(c *classifyConfig) { c.toolName = name }
}

type batchClassifyConfig struct {
	hooks     []HookLabel
	toolNames []string
	threshold *float64
}

// BatchClassifyOption customizes a single ClassifyBatch call.
type BatchClassifyOption func(*batchClassifyConfig)

// WithBatchHooks sets one hook label per text. Length must match texts.
func WithBatchHooks(hooks []HookLabel) BatchClassifyOption {
	return func(c *batchClassifyConfig) { c.hooks = hooks }
}

// WithBatchToolNames sets one tool name per text. Length must match texts.
// An empty string at index i omits the tool_name for that text.
func WithBatchToolNames(names []string) BatchClassifyOption {
	return func(c *batchClassifyConfig) { c.toolNames = names }
}

// WithBatchThreshold sets the score threshold sent with a batch request.
func WithBatchThreshold(threshold float64) BatchClassifyOption {
	return func(c *batchClassifyConfig) { c.threshold = &threshold }
}
