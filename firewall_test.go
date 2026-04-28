// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

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
	if fw.Threshold() != DefaultThreshold {
		t.Errorf("Threshold = %v, want %v", fw.Threshold(), DefaultThreshold)
	}
	if fw.ShadowMode() {
		t.Error("ShadowMode = true, want false")
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

func TestClassifyAppliesConfiguredThreshold(t *testing.T) {
	var gotPayload singleRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotPayload)
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionMalicious, Score: 0.6})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL, Threshold: 0.7})
	result, err := fw.Classify(context.Background(), "borderline", WithHook(HookUserInput))
	if err != nil {
		t.Fatal(err)
	}
	if gotPayload.Threshold != 0.7 {
		t.Errorf("threshold = %v, want 0.7", gotPayload.Threshold)
	}
	if result.Prediction != PredictionBenign {
		t.Errorf("prediction = %q, want BENIGN", result.Prediction)
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
		Threshold:      0.3,
		HookThresholds: map[HookLabel]float64{HookToolResponse: 0.8},
	})
	result, err := fw.Classify(context.Background(), "tool output", WithHook(HookToolResponse))
	if err != nil {
		t.Fatal(err)
	}
	if gotPayload.Threshold != 0.8 {
		t.Errorf("threshold = %v, want 0.8", gotPayload.Threshold)
	}
	if result.Prediction != PredictionBenign {
		t.Errorf("prediction = %q, want BENIGN", result.Prediction)
	}
	if fw.EffectiveThreshold(HookUserInput) != 0.3 {
		t.Errorf("user_input threshold = %v, want 0.3", fw.EffectiveThreshold(HookUserInput))
	}
}

func TestShouldBlockHonorsShadowMode(t *testing.T) {
	result := BlockResult{Prediction: PredictionMalicious, Score: 0.9}
	fw, _ := New(Options{APIKey: "sk", APIURL: "https://example.com", Threshold: 0.5})
	if !fw.ShouldBlock(result, HookUserInput) {
		t.Fatal("ShouldBlock = false, want true")
	}

	shadow, _ := New(Options{APIKey: "sk", APIURL: "https://example.com", Threshold: 0.5, ShadowMode: true})
	if shadow.ShouldBlock(result, HookUserInput) {
		t.Fatal("shadow ShouldBlock = true, want false")
	}
}

func TestNewRejectsInvalidThresholds(t *testing.T) {
	if _, err := New(Options{APIKey: "sk", APIURL: "https://example.com", Threshold: 1.1}); err == nil {
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
	prev := retryBaseBackoff
	retryBaseBackoff = time.Millisecond
	defer func() { retryBaseBackoff = prev }()

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

func TestClassifyRetriesOnTransient5xx(t *testing.T) {
	prev := retryBaseBackoff
	retryBaseBackoff = time.Millisecond
	defer func() { retryBaseBackoff = prev }()

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
	_, err := fw.Classify(context.Background(), "hi")
	if err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("calls = %d, want 3", got)
	}
}

func TestClassifyHonorsRetryAfter(t *testing.T) {
	prev := retryBaseBackoff
	retryBaseBackoff = time.Hour
	defer func() { retryBaseBackoff = prev }()

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
	if _, err := fw.Classify(context.Background(), "hi"); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("calls = %d, want 2", got)
	}
}

func TestClassifyContextCancellation(t *testing.T) {
	prev := retryBaseBackoff
	retryBaseBackoff = 100 * time.Millisecond
	defer func() { retryBaseBackoff = prev }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
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
	fw, _ := New(Options{APIKey: "sk", APIURL: "https://x", HookThresholds: custom})

	got := fw.HookThresholds()
	got[HookUserInput] = 0.99
	if fw.HookThresholds()[HookUserInput] != 0.3 {
		t.Error("HookThresholds should return a copy, not a reference")
	}
	custom[HookUserInput] = 0.42
	if fw.HookThresholds()[HookUserInput] != 0.3 {
		t.Error("Firewall should copy HookThresholds on construction")
	}
}
