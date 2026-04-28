// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	defaultMaxRetries = 5
	defaultTimeout    = 10 * time.Second
)

// Firewall is a client for the Silmaril Firewall /classify endpoint.
// Instances are safe for concurrent use.
type Firewall struct {
	apiKey           string
	apiURL           string
	threshold        float64
	hookThresholds   map[HookLabel]float64
	httpClient       *http.Client
	shadowMode       bool
	onClassify       func(ClassifyEvent)
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
		shadowMode:       opts.ShadowMode,
		onClassify:       opts.OnClassify,
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

func validThreshold(threshold float64) bool {
	return threshold >= 0 && threshold <= 1
}
