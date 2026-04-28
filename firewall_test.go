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

	fw, err := New(Options{APIKey: "sk-test", APIURL: ts.URL})
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

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL, Threshold: float64Ptr(0.5)})
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
	var receivedBatch batchRequestPayload
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewDecoder(r.Body).Decode(&receivedBatch)
		preds := make([]singleResponse, len(receivedBatch.Texts))
		for i := range preds {
			preds[i] = singleResponse{Prediction: PredictionBenign, Score: 0.1}
		}
		preds[len(preds)-1].Score = 0.95
		preds[len(preds)-1].Prediction = PredictionMalicious
		_ = json.NewEncoder(w).Encode(batchResponse{Predictions: preds})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	long := strings.Repeat("a", ChunkWindowChars*3)
	res, err := fw.Classify(context.Background(), long, WithHook(HookUserInput))
	if err != nil {
		t.Fatal(err)
	}
	if res.Prediction != PredictionMalicious || res.Score != 0.95 {
		t.Errorf("result = %+v", res)
	}
	if len(receivedBatch.Texts) < 2 {
		t.Errorf("expected multiple chunks, got %d", len(receivedBatch.Texts))
	}
	if receivedBatch.Threshold != DefaultThreshold {
		t.Errorf("threshold = %v, want %v", receivedBatch.Threshold, DefaultThreshold)
	}
	for _, h := range receivedBatch.Hooks {
		if h != HookUserInput {
			t.Errorf("hook = %q, want %q", h, HookUserInput)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("HTTP calls = %d, want 1 batch request", got)
	}
}

func TestClassifyChunksLongInputPropagatesToolNameToEveryChunk(t *testing.T) {
	var receivedBatch batchRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedBatch)
		preds := make([]singleResponse, len(receivedBatch.Texts))
		for i := range preds {
			preds[i] = singleResponse{Prediction: PredictionBenign, Score: 0.1}
		}
		_ = json.NewEncoder(w).Encode(batchResponse{Predictions: preds})
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
	if len(receivedBatch.Texts) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(receivedBatch.Texts))
	}
	if len(receivedBatch.Hooks) != len(receivedBatch.Texts) {
		t.Fatalf("hooks length = %d, want %d", len(receivedBatch.Hooks), len(receivedBatch.Texts))
	}
	if len(receivedBatch.ToolNames) != len(receivedBatch.Texts) {
		t.Fatalf("tool_names length = %d, want %d", len(receivedBatch.ToolNames), len(receivedBatch.Texts))
	}
	if receivedBatch.Threshold != DefaultThreshold {
		t.Errorf("threshold = %v, want %v", receivedBatch.Threshold, DefaultThreshold)
	}
	for i := range receivedBatch.Texts {
		if receivedBatch.Hooks[i] != HookToolResponse {
			t.Errorf("hook[%d] = %q, want %q", i, receivedBatch.Hooks[i], HookToolResponse)
		}
		if receivedBatch.ToolNames[i] == nil || *receivedBatch.ToolNames[i] != "fetch_webpage" {
			t.Errorf("tool_names[%d] = %v, want fetch_webpage", i, receivedBatch.ToolNames[i])
		}
	}
}

func TestClassifyLongInputRejectsEmptyChunkPredictions(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(batchResponse{Predictions: []singleResponse{}})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	long := strings.Repeat("a", ChunkWindowChars*3)
	_, err := fw.Classify(context.Background(), long)
	if err == nil {
		t.Fatal("expected prediction count mismatch error")
	}
	if !strings.Contains(err.Error(), "predictions length 0") {
		t.Fatalf("unexpected error: %v", err)
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
