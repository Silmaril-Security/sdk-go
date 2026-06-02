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
	Prediction     Prediction                 `json:"prediction"`
	Score          float64                    `json:"score"`
	Threshold      float64                    `json:"threshold"`
	PrimaryOutcome PrimaryOutcome             `json:"primary_outcome,omitempty"`
	OutcomeScores  map[HarmfulOutcome]float64 `json:"outcome_scores,omitempty"`
	DetectorScores map[HarmfulOutcome]float64 `json:"detector_scores,omitempty"`
	DetectorCounts map[HarmfulOutcome]int     `json:"detector_counts,omitempty"`
}

// ClassificationMetadata carries caller-provided request metadata alongside
// the classified text without embedding it in the text itself.
type ClassificationMetadata map[string]any

// Options configures a Firewall client. APIKey and APIURL are required.
// Timeout defaults to 10 seconds for the default HTTP client. When HTTPClient
// is set, Timeout is applied only when explicitly non-zero, by cloning the
// provided client. The SDK also installs a no-redirect policy on cloned clients
// whose CheckRedirect is nil; caller-provided redirect policies are preserved.
// ChunkConcurrency limits long-input Classify fanout; zero uses
// DefaultChunkConcurrency.
type Options struct {
	APIKey           string
	APIURL           string
	Timeout          time.Duration
	ChunkConcurrency int
	HTTPClient       *http.Client
	ShadowMode       bool
	OnClassify       func(ClassifyEvent)
}

type classifyConfig struct {
	hook       HookLabel
	toolName   string
	metadata   *ClassificationMetadata
	shadowMode *bool
	requestID  string
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

// WithMetadata attaches caller-provided metadata to a single Classify request.
func WithMetadata(metadata ClassificationMetadata) ClassifyOption {
	return func(c *classifyConfig) { c.metadata = &metadata }
}

// WithShadowMode overrides the client-level shadow-mode setting for a single
// Classify call.
func WithShadowMode(enabled bool) ClassifyOption {
	return func(c *classifyConfig) { c.shadowMode = &enabled }
}

// WithRequestID overrides the generated request id in metadata.silmaril.
func WithRequestID(id string) ClassifyOption {
	return func(c *classifyConfig) { c.requestID = id }
}

type batchClassifyConfig struct {
	hooks       []HookLabel
	toolNames   []string
	metadata    []ClassificationMetadata
	metadataSet bool
	shadowMode  *bool
	requestID   string
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

// WithBatchMetadata sets one metadata object per text. Length must match texts.
// A nil metadata entry is serialized as null for that text.
func WithBatchMetadata(metadata []ClassificationMetadata) BatchClassifyOption {
	return func(c *batchClassifyConfig) {
		c.metadata = metadata
		c.metadataSet = true
	}
}

// WithBatchShadowMode overrides the client-level shadow-mode setting for a
// single ClassifyBatch call.
func WithBatchShadowMode(enabled bool) BatchClassifyOption {
	return func(c *batchClassifyConfig) { c.shadowMode = &enabled }
}

// WithBatchRequestID overrides the generated request id in metadata.silmaril.
func WithBatchRequestID(id string) BatchClassifyOption {
	return func(c *batchClassifyConfig) { c.requestID = id }
}

// ClassifyEvent describes a classification decision. It is emitted for both
// enforced and shadow-mode calls.
type ClassifyEvent struct {
	Hook       HookLabel
	ToolName   string
	Text       string
	Result     BlockResult
	Blocked    bool
	ShadowMode bool
}
