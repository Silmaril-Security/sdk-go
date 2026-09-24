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
//
// One Firewall may be shared by many goroutines. Classify and ClassifyBatch
// keep request payloads, retries, and response decoding on the call stack, so
// overlapping calls do not share mutable request state. Canceling one call's
// context aborts only that call (including in-flight HTTP and retry sleep).
// Supply a distinct context per call when goroutines need independent
// deadlines. Callers remain responsible for making OnClassify, caller-owned
// metadata maps, and any custom HTTP transport safe for concurrent use.
type Firewall struct {
	apiKey           string
	apiURL           string
	httpClient       *http.Client
	mode             FirewallMode
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
	mode := opts.Mode
	if mode == "" && opts.ShadowMode {
		mode = ModeShadow
	}
	if err := validateMode(mode); err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout < 0 {
		return nil, fmt.Errorf("firewall: Timeout must be non-negative, got %v", timeout)
	}
	var httpClient *http.Client
	if opts.HTTPClient == nil {
		if timeout == 0 {
			timeout = defaultTimeout
		}
		httpClient = &http.Client{Timeout: timeout}
	} else {
		clone := *opts.HTTPClient
		if timeout != 0 {
			clone.Timeout = timeout
		}
		httpClient = &clone
	}
	if httpClient.CheckRedirect == nil {
		httpClient.CheckRedirect = useLastResponseOnRedirect
	}
	return &Firewall{
		apiKey:           opts.APIKey,
		apiURL:           opts.APIURL,
		httpClient:       httpClient,
		mode:             mode,
		shadowMode:       mode == ModeShadow,
		onClassify:       opts.OnClassify,
		maxRetries:       defaultMaxRetries,
		retryBaseBackoff: time.Second,
		retryMaxBackoff:  30 * time.Second,
		retryJitter:      fullJitter,
	}, nil
}

func useLastResponseOnRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}
