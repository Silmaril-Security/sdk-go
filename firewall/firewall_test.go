// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func float64Ptr(v float64) *float64 { return &v }

func noJitter(delay time.Duration) time.Duration { return delay }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackingBody struct {
	reader *strings.Reader
	closed bool
}

func (b *trackingBody) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

func (b *trackingBody) Close() error {
	b.closed = true
	return nil
}

func TestNewRequiresAPIKey(t *testing.T) {
	if _, err := New(Options{APIURL: "https://example.com"}); err == nil {
		t.Error("expected error for empty APIKey")
	}
}

func TestNewRequiresAPIURL(t *testing.T) {
	if _, err := New(Options{APIKey: "sk"}); err == nil {
		t.Error("expected error for empty APIURL")
	}
}

func TestNewDefaults(t *testing.T) {
	fw, err := New(Options{APIKey: "sk", APIURL: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if fw.threshold != DefaultThreshold {
		t.Errorf("threshold = %v, want %v", fw.threshold, DefaultThreshold)
	}
	if fw.httpClient.Timeout != defaultTimeout {
		t.Errorf("timeout = %v, want %v", fw.httpClient.Timeout, defaultTimeout)
	}
	if fw.shadowMode {
		t.Error("shadowMode = true, want false")
	}
	if fw.chunkConcurrency != DefaultChunkConcurrency {
		t.Errorf("chunkConcurrency = %d, want %d", fw.chunkConcurrency, DefaultChunkConcurrency)
	}
}

func TestNewHonorsChunkConcurrency(t *testing.T) {
	fw, err := New(Options{
		APIKey:           "sk",
		APIURL:           "https://example.com",
		ChunkConcurrency: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fw.chunkConcurrency != 3 {
		t.Errorf("chunkConcurrency = %d, want 3", fw.chunkConcurrency)
	}
}

func TestNewRejectsNegativeChunkConcurrency(t *testing.T) {
	_, err := New(Options{
		APIKey:           "sk",
		APIURL:           "https://example.com",
		ChunkConcurrency: -1,
	})
	if err == nil {
		t.Fatal("expected error for negative ChunkConcurrency")
	}
	if !strings.Contains(err.Error(), "ChunkConcurrency must be non-negative") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewHonorsExplicitZeroThreshold(t *testing.T) {
	fw, err := New(Options{
		APIKey:    "sk",
		APIURL:    "https://example.com",
		Threshold: float64Ptr(0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if fw.threshold != 0 {
		t.Errorf("threshold = %v, want 0", fw.threshold)
	}
}

func TestNewAppliesTimeoutToCustomHTTPClientClone(t *testing.T) {
	custom := &http.Client{Timeout: time.Minute}
	fw, err := New(Options{
		APIKey:     "sk",
		APIURL:     "https://example.com",
		Timeout:    2 * time.Second,
		HTTPClient: custom,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fw.httpClient == custom {
		t.Fatal("expected custom HTTP client to be cloned when Timeout is explicit")
	}
	if fw.httpClient.Timeout != 2*time.Second {
		t.Errorf("timeout = %v, want 2s", fw.httpClient.Timeout)
	}
	if custom.Timeout != time.Minute {
		t.Errorf("custom client mutated: timeout = %v", custom.Timeout)
	}
}

func TestClassifySingleHappyPath(t *testing.T) {
	var gotPayload singleRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-api-key"); got != "sk-test" {
			t.Errorf("x-api-key = %q", got)
		}
		if got := r.Header.Get("content-type"); got != "application/json" {
			t.Errorf("content-type = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionMalicious, Score: 0.95})
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk-test", APIURL: ts.URL, ShadowMode: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := fw.Classify(context.Background(), "hello",
		WithHook(HookUserInput),
		WithToolName("cal"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if res.Prediction != PredictionMalicious || res.Score != 0.95 {
		t.Errorf("result = %+v", res)
	}
	if res.Threshold != DefaultThreshold {
		t.Errorf("result threshold = %v, want %v", res.Threshold, DefaultThreshold)
	}
	if gotPayload.Text != "hello" || gotPayload.Hook != HookUserInput || gotPayload.ToolName != "cal" {
		t.Errorf("payload = %+v", gotPayload)
	}
	if gotPayload.Threshold != DefaultThreshold {
		t.Errorf("threshold = %v, want %v", gotPayload.Threshold, DefaultThreshold)
	}
}

func TestClassifySanitizesInvalidUTF8Payload(t *testing.T) {
	var gotPayload singleRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotPayload)
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	if _, err := fw.Classify(context.Background(), "bad "+string([]byte{0xff})+" value"); err != nil {
		t.Fatal(err)
	}
	if gotPayload.Text != "bad  value" {
		t.Fatalf("payload text = %q", gotPayload.Text)
	}
}

func TestClassifyDecodesOptionalSapphireFields(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(singleResponse{
			Prediction:     PredictionMalicious,
			Score:          0.91,
			PrimaryOutcome: "secret_exposure",
			OutcomeScores:  map[string]float64{"secret_exposure": 0.8},
			DetectorScores: map[string]float64{"secret_exposure": 1.0},
			DetectorCounts: map[string]int{"secret_exposure": 2},
		})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL, ShadowMode: true})
	res, err := fw.Classify(context.Background(), "leak token")
	if err != nil {
		t.Fatal(err)
	}
	if res.PrimaryOutcome != "secret_exposure" {
		t.Errorf("primary outcome = %q", res.PrimaryOutcome)
	}
	if res.OutcomeScores["secret_exposure"] != 0.8 {
		t.Errorf("outcome scores = %+v", res.OutcomeScores)
	}
	if res.DetectorScores["secret_exposure"] != 1.0 {
		t.Errorf("detector scores = %+v", res.DetectorScores)
	}
	if res.DetectorCounts["secret_exposure"] != 2 {
		t.Errorf("detector counts = %+v", res.DetectorCounts)
	}
}

func TestClassifyNoOptionsOmitsHookAndToolName(t *testing.T) {
	var raw map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&raw)
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	if _, err := fw.Classify(context.Background(), "hi"); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["hook"]; ok {
		t.Errorf("hook should be omitted: %v", raw)
	}
	if _, ok := raw["tool_name"]; ok {
		t.Errorf("tool_name should be omitted: %v", raw)
	}
}

func TestClassifyBatchHappyPath(t *testing.T) {
	var gotPayload batchRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotPayload)
		_ = json.NewEncoder(w).Encode(batchResponse{
			Predictions: []singleResponse{
				{Prediction: PredictionBenign, Score: 0.1},
				{Prediction: PredictionMalicious, Score: 0.9},
			},
		})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	results, err := fw.ClassifyBatch(context.Background(), []string{"a", "b"},
		WithBatchHooks([]HookLabel{HookUserInput, HookUserInput}),
		WithBatchToolNames([]string{"read_file", ""}),
		WithBatchShadowMode(true),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].Prediction != PredictionBenign || results[1].Prediction != PredictionMalicious {
		t.Errorf("results = %+v", results)
	}
	if gotPayload.Threshold != DefaultThreshold {
		t.Errorf("threshold = %v, want %v", gotPayload.Threshold, DefaultThreshold)
	}
	if len(gotPayload.Hooks) != 2 || gotPayload.Hooks[0] != HookUserInput || gotPayload.Hooks[1] != HookUserInput {
		t.Errorf("hooks = %v", gotPayload.Hooks)
	}
	if len(gotPayload.ToolNames) != 2 || gotPayload.ToolNames[0] == nil || *gotPayload.ToolNames[0] != "read_file" || gotPayload.ToolNames[1] != nil {
		t.Errorf("tool_names = %v", gotPayload.ToolNames)
	}
}

func TestClassifyBatchSanitizesInvalidUTF8Payload(t *testing.T) {
	var gotPayload batchRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotPayload)
		_ = json.NewEncoder(w).Encode(batchResponse{
			Predictions: []singleResponse{
				{Prediction: PredictionBenign, Score: 0.1},
				{Prediction: PredictionBenign, Score: 0.2},
			},
		})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	if _, err := fw.ClassifyBatch(context.Background(), []string{"bad " + string([]byte{0xff}), "ok 😀"}); err != nil {
		t.Fatal(err)
	}
	if len(gotPayload.Texts) != 2 || gotPayload.Texts[0] != "bad " || gotPayload.Texts[1] != "ok 😀" {
		t.Fatalf("payload texts = %#v", gotPayload.Texts)
	}
}

func TestClassifyBatchDecodesOptionalSapphireFields(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(batchResponse{
			Predictions: []singleResponse{
				{Prediction: PredictionBenign, Score: 0.1},
				{
					Prediction:     PredictionMalicious,
					Score:          0.9,
					PrimaryOutcome: "system_compromise",
					OutcomeScores:  map[string]float64{"system_compromise": 0.92},
					DetectorScores: map[string]float64{"information_disclosure": 0.85},
					DetectorCounts: map[string]int{"information_disclosure": 1},
				},
			},
		})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL, ShadowMode: true})
	results, err := fw.ClassifyBatch(context.Background(), []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].PrimaryOutcome != "" || results[0].OutcomeScores != nil {
		t.Errorf("unexpected Sapphire fields on binary result: %+v", results[0])
	}
	if results[1].PrimaryOutcome != "system_compromise" {
		t.Errorf("primary outcome = %q", results[1].PrimaryOutcome)
	}
	if results[1].OutcomeScores["system_compromise"] != 0.92 {
		t.Errorf("outcome scores = %+v", results[1].OutcomeScores)
	}
	if results[1].DetectorScores["information_disclosure"] != 0.85 {
		t.Errorf("detector scores = %+v", results[1].DetectorScores)
	}
	if results[1].DetectorCounts["information_disclosure"] != 1 {
		t.Errorf("detector counts = %+v", results[1].DetectorCounts)
	}
}

func TestClassifyBatchMismatchedHooks(t *testing.T) {
	fw, _ := New(Options{APIKey: "sk", APIURL: "https://example.com"})
	_, err := fw.ClassifyBatch(context.Background(), []string{"a", "b"},
		WithBatchHooks([]HookLabel{HookUserInput}),
	)
	if err == nil {
		t.Error("expected mismatch error")
	}
}

func TestClassifyAppliesConfiguredThreshold(t *testing.T) {
	var gotPayload singleRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotPayload)
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionMalicious, Score: 0.6})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL, Threshold: float64Ptr(0.7)})
	result, err := fw.Classify(context.Background(), "borderline", WithHook(HookUserInput))
	if err != nil {
		t.Fatal(err)
	}
	if gotPayload.Threshold != 0.7 {
		t.Errorf("threshold = %v, want 0.7", gotPayload.Threshold)
	}
	if result.Prediction != PredictionMalicious {
		t.Errorf("prediction = %q, want MALICIOUS", result.Prediction)
	}
	if result.Threshold != 0.7 {
		t.Errorf("result threshold = %v, want 0.7", result.Threshold)
	}
}

func TestClassifyUsesHookThreshold(t *testing.T) {
	var gotPayload singleRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotPayload)
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionMalicious, Score: 0.7})
	}))
	defer ts.Close()

	fw, _ := New(Options{
		APIKey:         "sk",
		APIURL:         ts.URL,
		Threshold:      float64Ptr(0.3),
		HookThresholds: map[HookLabel]float64{HookToolResponse: 0.8},
	})
	result, err := fw.Classify(context.Background(), "tool output", WithHook(HookToolResponse))
	if err != nil {
		t.Fatal(err)
	}
	if gotPayload.Threshold != 0.8 {
		t.Errorf("threshold = %v, want 0.8", gotPayload.Threshold)
	}
	if result.Prediction != PredictionMalicious {
		t.Errorf("prediction = %q, want MALICIOUS", result.Prediction)
	}
}

func TestClassifyTrustsServerPrediction(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.99})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL, Threshold: float64Ptr(0.5), ShadowMode: true})
	result, err := fw.Classify(context.Background(), "server-side benign")
	if err != nil {
		t.Fatal(err)
	}
	if result.Prediction != PredictionBenign {
		t.Errorf("prediction = %q, want BENIGN", result.Prediction)
	}
}

func TestNewRejectsInvalidThresholds(t *testing.T) {
	if _, err := New(Options{APIKey: "sk", APIURL: "https://example.com", Threshold: float64Ptr(1.1)}); err == nil {
		t.Fatal("expected invalid threshold error")
	}
	if _, err := New(Options{
		APIKey:         "sk",
		APIURL:         "https://example.com",
		HookThresholds: map[HookLabel]float64{HookUserInput: -0.1},
	}); err == nil {
		t.Fatal("expected invalid hook threshold error")
	}
}

func TestClassifyRetriesOn429(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	fw.retryBaseBackoff = time.Millisecond
	fw.retryJitter = noJitter
	res, err := fw.Classify(context.Background(), "hi")
	if err != nil {
		t.Fatal(err)
	}
	if res.Score != 0.1 {
		t.Errorf("result = %+v", res)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("calls = %d, want 3", got)
	}
}

func TestClassifyDrainsRetryBody(t *testing.T) {
	retryBody := &trackingBody{reader: strings.NewReader("retry body")}
	var calls atomic.Int32
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if calls.Add(1) == 1 {
				return &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     make(http.Header),
					Body:       retryBody,
					Request:    req,
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"prediction":"BENIGN","score":0.1}`)),
				Request:    req,
			}, nil
		}),
	}
	fw, _ := New(Options{APIKey: "sk", APIURL: "https://example.com", HTTPClient: client})
	fw.retryBaseBackoff = time.Millisecond
	fw.retryJitter = noJitter

	if _, err := fw.Classify(context.Background(), "hi"); err != nil {
		t.Fatal(err)
	}
	if !retryBody.closed {
		t.Fatal("retry response body was not closed")
	}
	if retryBody.reader.Len() != 0 {
		t.Fatalf("retry response body was not drained; %d bytes remain", retryBody.reader.Len())
	}
}

func TestClassifyNon2xxReturnsAPIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "boom"}`))
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	_, err := fw.Classify(context.Background(), "hi")
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is not *APIError: %T", err)
	}
	if apiErr.Status != 400 {
		t.Errorf("Status = %d", apiErr.Status)
	}
	if !strings.Contains(apiErr.Body, "boom") {
		t.Errorf("Body = %q", apiErr.Body)
	}
}

func TestClassifyNon2xxParsesMalformedDetails(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"MalformedInput","message":"Input contains malformed text that could not be tokenized","details":{"field":"texts[0]","inputIndex":0,"charOffset":12,"malformedToken":"\\uD83D","codePoint":"U+D83D","reason":"lone_high_surrogate"}}`))
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	_, err := fw.Classify(context.Background(), "hi")
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is not *APIError: %T", err)
	}
	if apiErr.Details == nil {
		t.Fatal("Details is nil")
	}
	if apiErr.Details.Field != "texts[0]" || apiErr.Details.MalformedToken != "\\uD83D" {
		t.Fatalf("Details = %+v", apiErr.Details)
	}
	if apiErr.Details.InputIndex == nil || *apiErr.Details.InputIndex != 0 {
		t.Fatalf("InputIndex = %v", apiErr.Details.InputIndex)
	}
}

func TestClassifyLimitsErrorBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(strings.Repeat("x", maxErrorBodyBytes+1024)))
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	_, err := fw.Classify(context.Background(), "hi")
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is not *APIError: %T", err)
	}
	if len(apiErr.Body) != maxErrorBodyBytes {
		t.Errorf("body length = %d, want %d", len(apiErr.Body), maxErrorBodyBytes)
	}
}

func TestClassifyRetriesOnTransient5xx(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	fw.retryBaseBackoff = time.Millisecond
	fw.retryJitter = noJitter
	_, err := fw.Classify(context.Background(), "hi")
	if err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("calls = %d, want 3", got)
	}
}

func TestClassifyRetriesNetworkErrors(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if calls.Add(1) < 3 {
				return nil, errors.New("temporary dial failure")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"prediction":"BENIGN","score":0.1}`)),
				Request:    req,
			}, nil
		}),
	}
	fw, _ := New(Options{APIKey: "sk", APIURL: "https://example.com", HTTPClient: client})
	fw.retryBaseBackoff = time.Millisecond
	fw.retryJitter = noJitter

	if _, err := fw.Classify(context.Background(), "hi"); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("calls = %d, want 3", got)
	}
}

func TestClassifyWrapsFinalNetworkError(t *testing.T) {
	baseErr := errors.New("dial failure")
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, baseErr
		}),
	}
	fw, _ := New(Options{APIKey: "sk", APIURL: "https://example.com", HTTPClient: client})
	fw.maxRetries = 2
	fw.retryBaseBackoff = 0

	_, err := fw.Classify(context.Background(), "hi")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, baseErr) {
		t.Fatalf("expected wrapped base error, got %v", err)
	}
	if !strings.Contains(err.Error(), "firewall:") {
		t.Fatalf("expected firewall prefix, got %v", err)
	}
}

func TestClassifyExhaustsRetryableStatus(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	fw.retryBaseBackoff = time.Millisecond
	fw.retryJitter = noJitter
	_, err := fw.Classify(context.Background(), "hi")
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is not *APIError: %T", err)
	}
	if apiErr.Status != http.StatusServiceUnavailable {
		t.Errorf("Status = %d, want %d", apiErr.Status, http.StatusServiceUnavailable)
	}
	if got := calls.Load(); got != int32(defaultMaxRetries+1) {
		t.Errorf("calls = %d, want %d", got, defaultMaxRetries+1)
	}
}

func TestClassifyHonorsRetryAfter(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	fw.retryBaseBackoff = time.Hour
	fw.retryJitter = noJitter
	if _, err := fw.Classify(context.Background(), "hi"); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("calls = %d, want 2", got)
	}
}

func TestRetryAfterHTTPDate(t *testing.T) {
	when := time.Now().Add(2 * time.Second).UTC().Format(http.TimeFormat)
	delay, ok := retryAfter(when)
	if !ok {
		t.Fatal("expected HTTP-date Retry-After to parse")
	}
	if delay <= 0 {
		t.Errorf("delay = %v, want positive", delay)
	}
}

func TestRetryDelayUsesJitter(t *testing.T) {
	fw, _ := New(Options{APIKey: "sk", APIURL: "https://example.com"})
	var saw time.Duration
	fw.retryBaseBackoff = 4 * time.Second
	fw.retryJitter = func(delay time.Duration) time.Duration {
		saw = delay
		return 123 * time.Millisecond
	}

	got := fw.retryDelay(2, nil)
	if saw != 16*time.Second {
		t.Fatalf("jitter saw %v, want 16s", saw)
	}
	if got != 123*time.Millisecond {
		t.Fatalf("delay = %v, want jittered value", got)
	}
}

func TestClassifyContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	fw.retryBaseBackoff = 100 * time.Millisecond
	fw.retryJitter = noJitter
	_, err := fw.Classify(ctx, "hi")
	if err == nil {
		t.Fatal("expected ctx error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded, got %v", err)
	}
}

func TestClassifyChunksLongInputAndPicksMaxScore(t *testing.T) {
	var calls atomic.Int32
	var mu sync.Mutex
	var received []singleRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callNumber := int(calls.Add(1))
		var payload singleRequestPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		received = append(received, payload)
		mu.Unlock()
		score := 0.1
		prediction := PredictionBenign
		if callNumber == 2 {
			score = 0.95
			prediction = PredictionMalicious
		}
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: prediction, Score: score})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL, ShadowMode: true})
	long := strings.Repeat("a", ChunkWindowChars*3)
	res, err := fw.Classify(context.Background(), long, WithHook(HookUserInput))
	if err != nil {
		t.Fatal(err)
	}
	if res.Prediction != PredictionMalicious || res.Score != 0.95 {
		t.Errorf("result = %+v", res)
	}
	if len(received) < 2 {
		t.Errorf("expected multiple chunk requests, got %d", len(received))
	}
	for _, payload := range received {
		if payload.Threshold != DefaultThreshold {
			t.Errorf("threshold = %v, want %v", payload.Threshold, DefaultThreshold)
		}
		if payload.Hook != HookUserInput {
			t.Errorf("hook = %q, want %q", payload.Hook, HookUserInput)
		}
		if payload.Text == "" {
			t.Error("chunk text is empty")
		}
	}
	if got := calls.Load(); got < 2 {
		t.Errorf("HTTP calls = %d, want multiple single requests", got)
	}
}

func TestClassifyChunksLongInputPropagatesToolNameToEveryChunk(t *testing.T) {
	var mu sync.Mutex
	var received []singleRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload singleRequestPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		received = append(received, payload)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	long := strings.Repeat("b", ChunkWindowChars*2)
	_, err := fw.Classify(
		context.Background(),
		long,
		WithHook(HookToolResponse),
		WithToolName("fetch_webpage"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(received) < 2 {
		t.Fatalf("expected multiple chunk requests, got %d", len(received))
	}
	for i, payload := range received {
		if payload.Hook != HookToolResponse {
			t.Errorf("hook[%d] = %q, want %q", i, payload.Hook, HookToolResponse)
		}
		if payload.ToolName != "fetch_webpage" {
			t.Errorf("tool_name[%d] = %q, want fetch_webpage", i, payload.ToolName)
		}
		if payload.Threshold != DefaultThreshold {
			t.Errorf("threshold[%d] = %v, want %v", i, payload.Threshold, DefaultThreshold)
		}
	}
}

func TestClassifyLongInputPropagatesChunkError(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "boom", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL, ShadowMode: true})
	long := strings.Repeat("a", ChunkWindowChars*3)
	_, err := fw.Classify(context.Background(), long)
	if err == nil {
		t.Fatal("expected chunk error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is not APIError: %T %v", err, err)
	}
	if calls.Load() < 2 {
		t.Fatalf("HTTP calls = %d, want multiple chunk attempts", calls.Load())
	}
}

func TestClassifyChunkConcurrencyLimit(t *testing.T) {
	var active atomic.Int32
	var maxActive atomic.Int32
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		for {
			previous := maxActive.Load()
			if current <= previous || maxActive.CompareAndSwap(previous, current) {
				break
			}
		}
		calls.Add(1)
		time.Sleep(10 * time.Millisecond)
		active.Add(-1)
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL, ChunkConcurrency: 2, ShadowMode: true})
	long := strings.Repeat("a", ChunkWindowChars*5)
	if _, err := fw.Classify(context.Background(), long); err != nil {
		t.Fatal(err)
	}
	if calls.Load() <= 2 {
		t.Fatalf("HTTP calls = %d, want more than 2", calls.Load())
	}
	if maxActive.Load() > 2 {
		t.Fatalf("max active requests = %d, want <= 2", maxActive.Load())
	}
}

func TestHookThresholdsCopy(t *testing.T) {
	custom := map[HookLabel]float64{HookUserInput: 0.3}
	var gotPayload singleRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotPayload)
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL, HookThresholds: custom})
	custom[HookUserInput] = 0.42

	if _, err := fw.Classify(context.Background(), "hello", WithHook(HookUserInput)); err != nil {
		t.Fatal(err)
	}
	if gotPayload.Threshold != 0.3 {
		t.Errorf("threshold = %v, want 0.3", gotPayload.Threshold)
	}
}
