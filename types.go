// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

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
}

// Options configures a Firewall client. APIKey and APIURL are required.
// Zero-valued Threshold and Timeout fall back to DefaultThreshold and a
// 10-second timeout respectively.
type Options struct {
	APIKey         string
	APIURL         string
	Threshold      float64
	Timeout        time.Duration
	HookThresholds map[HookLabel]float64
	ShadowMode     bool
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
