// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func noJitter(delay time.Duration) time.Duration { return delay }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func requireSilmarilMetadata(
	t *testing.T,
	metadata *ClassificationMetadata,
	requestID string,
	inputIndex int,
	chunkIndex int,
	chunkCount int,
) map[string]any {
	t.Helper()
	if metadata == nil {
		t.Fatal("metadata was not serialized")
	}
	raw, ok := (*metadata)["silmaril"].(map[string]any)
	if !ok {
		t.Fatalf("metadata.silmaril = %#v, want object", (*metadata)["silmaril"])
	}
	if raw["sdk_language"] != "go" {
		t.Errorf("sdk_language = %v, want go", raw["sdk_language"])
	}
	if raw["sdk_version"] != SDKVersion {
		t.Errorf("sdk_version = %v, want %s", raw["sdk_version"], SDKVersion)
	}
	if raw["request_id"] != requestID {
		t.Errorf("request_id = %v, want %s", raw["request_id"], requestID)
	}
	if got := int(raw["input_index"].(float64)); got != inputIndex {
		t.Errorf("input_index = %d, want %d", got, inputIndex)
	}
	if got := int(raw["chunk_index"].(float64)); got != chunkIndex {
		t.Errorf("chunk_index = %d, want %d", got, chunkIndex)
	}
	if got := int(raw["chunk_count"].(float64)); got != chunkCount {
		t.Errorf("chunk_count = %d, want %d", got, chunkCount)
	}
	return raw
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

func TestNewInstallsNoRedirectPolicyOnCustomHTTPClientClone(t *testing.T) {
	custom := &http.Client{Timeout: time.Minute}
	fw, err := New(Options{
		APIKey:     "sk",
		APIURL:     "https://example.com",
		HTTPClient: custom,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fw.httpClient == custom {
		t.Fatal("expected custom HTTP client to be cloned")
	}
	if fw.httpClient.Timeout != time.Minute {
		t.Errorf("timeout = %v, want %v", fw.httpClient.Timeout, time.Minute)
	}
	if fw.httpClient.CheckRedirect == nil {
		t.Fatal("expected hardened redirect policy")
	}
	if custom.CheckRedirect != nil {
		t.Fatal("custom client was mutated")
	}
}

func TestNewPreservesExplicitCheckRedirect(t *testing.T) {
	var called atomic.Bool
	custom := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			called.Store(true)
			return http.ErrUseLastResponse
		},
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("redirect target should not be reached")
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: redirector.URL, HTTPClient: custom})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fw.Classify(context.Background(), "hi")
	if err == nil {
		t.Fatal("expected redirect response to surface as APIError")
	}
	if !called.Load() {
		t.Fatal("custom CheckRedirect was not called")
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
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionMalicious, Score: 0.95, Threshold: 0.5})
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk-test", APIURL: ts.URL, ShadowMode: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := fw.Classify(context.Background(), "hello",
		WithHook(HookUserInput),
		WithToolName("cal"),
		WithRequestID("req-single"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if res.Prediction != PredictionMalicious || res.Score != 0.95 {
		t.Errorf("result = %+v", res)
	}
	if res.Threshold != 0.5 {
		t.Errorf("result threshold = %v, want 0.5", res.Threshold)
	}
	if gotPayload.Text != "hello" || gotPayload.Hook != HookUserInput || gotPayload.ToolName != "cal" {
		t.Errorf("payload = %+v", gotPayload)
	}
	requireSilmarilMetadata(t, gotPayload.Metadata, "req-single", 0, 0, 1)
}

func TestClassifySanitizesInvalidUTF8Payload(t *testing.T) {
	var gotPayload singleRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotPayload)
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5})
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
			Threshold:      0.5,
			PrimaryOutcome: primaryOutcomePtr(string(OutcomeSecretExposure)),
			OutcomeScores:  map[string]float64{string(OutcomeSecretExposure): 0.8},
			DetectorScores: map[string]float64{string(OutcomeSecretExposure): 1.0},
			DetectorCounts: map[string]int{string(OutcomeSecretExposure): 2},
		})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL, ShadowMode: true})
	res, err := fw.Classify(context.Background(), "leak token")
	if err != nil {
		t.Fatal(err)
	}
	if res.PrimaryOutcome != OutcomeSecretExposure {
		t.Errorf("primary outcome = %q", res.PrimaryOutcome)
	}
	if res.OutcomeScores[HarmfulOutcomeSecretExposure] != 0.8 {
		t.Errorf("outcome scores = %+v", res.OutcomeScores)
	}
	if res.DetectorScores[HarmfulOutcomeSecretExposure] != 1.0 {
		t.Errorf("detector scores = %+v", res.DetectorScores)
	}
	if res.DetectorCounts[HarmfulOutcomeSecretExposure] != 2 {
		t.Errorf("detector counts = %+v", res.DetectorCounts)
	}
}

func TestClassifyNoOptionsOmitsHookAndToolName(t *testing.T) {
	var raw map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&raw)
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5})
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
	if _, ok := raw["threshold"]; ok {
		t.Errorf("threshold should be omitted: %v", raw)
	}
	if _, ok := raw["metadata"].(map[string]any)["silmaril"]; !ok {
		t.Errorf("metadata.silmaril should be present: %v", raw)
	}
}

func TestClassifySerializesMetadata(t *testing.T) {
	var gotPayload singleRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	metadata := ClassificationMetadata{
		"langgraph": map[string]any{
			"thread_id":  "thread-123",
			"run_id":     "run-123",
			"message_id": "msg-123",
		},
	}
	if _, err := fw.Classify(context.Background(), "hi",
		WithHook(HookUserInput),
		WithMetadata(metadata),
		WithRequestID("req-meta"),
	); err != nil {
		t.Fatal(err)
	}
	requireSilmarilMetadata(t, gotPayload.Metadata, "req-meta", 0, 0, 1)
	if !reflect.DeepEqual((*gotPayload.Metadata)["langgraph"], metadata["langgraph"]) {
		t.Fatalf("langgraph metadata = %#v, want %#v", (*gotPayload.Metadata)["langgraph"], metadata["langgraph"])
	}
}

func TestClassifyBatchHappyPath(t *testing.T) {
	var gotPayload batchRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotPayload)
		_ = json.NewEncoder(w).Encode(batchResponse{
			Predictions: []singleResponse{
				{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5},
				{Prediction: PredictionMalicious, Score: 0.9, Threshold: 0.5},
			},
		})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	results, err := fw.ClassifyBatch(context.Background(), []string{"a", "b"},
		WithBatchHooks([]HookLabel{HookUserInput, HookUserInput}),
		WithBatchToolNames([]string{"read_file", ""}),
		WithBatchShadowMode(true),
		WithBatchRequestID("req-batch"),
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
	if len(gotPayload.Hooks) != 2 || gotPayload.Hooks[0] != HookUserInput || gotPayload.Hooks[1] != HookUserInput {
		t.Errorf("hooks = %v", gotPayload.Hooks)
	}
	if len(gotPayload.ToolNames) != 2 || gotPayload.ToolNames[0] == nil || *gotPayload.ToolNames[0] != "read_file" || gotPayload.ToolNames[1] != nil {
		t.Errorf("tool_names = %v", gotPayload.ToolNames)
	}
	if len(gotPayload.Metadata) != 2 {
		t.Fatalf("metadata length = %d, want 2", len(gotPayload.Metadata))
	}
	requireSilmarilMetadata(t, gotPayload.Metadata[0], "req-batch", 0, 0, 1)
	requireSilmarilMetadata(t, gotPayload.Metadata[1], "req-batch", 1, 0, 1)
}

func TestClassifyBatchSerializesMetadata(t *testing.T) {
	var gotPayload batchRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(batchResponse{
			Predictions: []singleResponse{
				{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5},
				{Prediction: PredictionBenign, Score: 0.2, Threshold: 0.5},
			},
		})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	metadata := []ClassificationMetadata{
		{"langgraph": map[string]any{"run_id": "run-a"}},
		nil,
	}
	if _, err := fw.ClassifyBatch(context.Background(), []string{"a", "b"},
		WithBatchMetadata(metadata),
		WithBatchRequestID("req-batch-meta"),
	); err != nil {
		t.Fatal(err)
	}
	if len(gotPayload.Metadata) != 2 {
		t.Fatalf("metadata length = %d, want 2", len(gotPayload.Metadata))
	}
	requireSilmarilMetadata(t, gotPayload.Metadata[0], "req-batch-meta", 0, 0, 1)
	if !reflect.DeepEqual((*gotPayload.Metadata[0])["langgraph"], metadata[0]["langgraph"]) {
		t.Fatalf("metadata[0] langgraph = %#v, want %#v", (*gotPayload.Metadata[0])["langgraph"], metadata[0]["langgraph"])
	}
	requireSilmarilMetadata(t, gotPayload.Metadata[1], "req-batch-meta", 1, 0, 1)
}

func TestClassifyBatchDoesNotSendThresholds(t *testing.T) {
	var received []batchRequestPayload
	var rawPayloads []map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]any
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(raw)
		var payload batchRequestPayload
		if err := json.Unmarshal(encoded, &payload); err != nil {
			t.Fatal(err)
		}
		received = append(received, payload)
		rawPayloads = append(rawPayloads, raw)
		predictions := make([]singleResponse, len(payload.Texts))
		for i := range predictions {
			predictions[i] = singleResponse{Prediction: PredictionBenign, Score: 0, Threshold: 0.5}
		}
		_ = json.NewEncoder(w).Encode(batchResponse{Predictions: predictions})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	if _, err := fw.ClassifyBatch(context.Background(), []string{"a", "b", "c", "d", "e"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fw.ClassifyBatch(context.Background(), []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}); err != nil {
		t.Fatal(err)
	}
	for i, raw := range rawPayloads {
		if _, ok := raw["threshold"]; ok {
			t.Errorf("request %d sent threshold: %v", i, raw)
		}
		if _, ok := raw["metadata"]; !ok {
			t.Errorf("request %d omitted metadata: %v", i, raw)
		}
	}
	if len(received[0].Metadata) != 5 || len(received[1].Metadata) != 10 {
		t.Fatalf("metadata lengths = %d, %d; want 5, 10", len(received[0].Metadata), len(received[1].Metadata))
	}
}

func TestClassifyBatchSanitizesInvalidUTF8Payload(t *testing.T) {
	var gotPayload batchRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotPayload)
		_ = json.NewEncoder(w).Encode(batchResponse{
			Predictions: []singleResponse{
				{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5},
				{Prediction: PredictionBenign, Score: 0.2, Threshold: 0.5},
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
				{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5},
				{
					Prediction:     PredictionMalicious,
					Score:          0.9,
					Threshold:      0.5,
					PrimaryOutcome: primaryOutcomePtr(string(OutcomeSystemCompromise)),
					OutcomeScores:  map[string]float64{string(OutcomeSystemCompromise): 0.92},
					DetectorScores: map[string]float64{string(OutcomeInformationDisclosure): 0.85},
					DetectorCounts: map[string]int{string(OutcomeInformationDisclosure): 1},
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
	if results[1].PrimaryOutcome != OutcomeSystemCompromise {
		t.Errorf("primary outcome = %q", results[1].PrimaryOutcome)
	}
	if results[1].OutcomeScores[HarmfulOutcomeSystemCompromise] != 0.92 {
		t.Errorf("outcome scores = %+v", results[1].OutcomeScores)
	}
	if results[1].DetectorScores[HarmfulOutcomeInformationDisclosure] != 0.85 {
		t.Errorf("detector scores = %+v", results[1].DetectorScores)
	}
	if results[1].DetectorCounts[HarmfulOutcomeInformationDisclosure] != 1 {
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
	_, err = fw.ClassifyBatch(context.Background(), []string{"a", "b"},
		WithBatchMetadata([]ClassificationMetadata{{"run_id": "run-a"}}),
	)
	if err == nil {
		t.Error("expected metadata mismatch error")
	}
}

func TestClassifyTrustsServerPrediction(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.99, Threshold: 0.5})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL, ShadowMode: true})
	result, err := fw.Classify(context.Background(), "server-side benign")
	if err != nil {
		t.Fatal(err)
	}
	if result.Prediction != PredictionBenign {
		t.Errorf("prediction = %q, want BENIGN", result.Prediction)
	}
}

func TestClassifyRetriesOn429(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5})
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
				Body:       io.NopCloser(strings.NewReader(`{"prediction":"BENIGN","score":0.1,"threshold":0.5}`)),
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

func TestClassifyDoesNotFollowRedirects(t *testing.T) {
	var targetHit atomic.Bool
	var leakedKey atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHit.Store(true)
		leakedKey.Store(r.Header.Get("x-api-key"))
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5})
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	fw, _ := New(Options{APIKey: "sk-secret", APIURL: redirector.URL})
	_, err := fw.Classify(context.Background(), "hi")
	if err == nil {
		t.Fatal("expected redirect response to surface as APIError")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is not *APIError: %T", err)
	}
	if apiErr.Status != http.StatusFound {
		t.Errorf("Status = %d, want %d", apiErr.Status, http.StatusFound)
	}
	if targetHit.Load() {
		t.Fatalf("redirect target was reached with x-api-key %q", leakedKey.Load())
	}
}

func TestClassifyCustomClientDoesNotFollowRedirectsWhenUnset(t *testing.T) {
	var targetHit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHit.Store(true)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	custom := &http.Client{}
	fw, _ := New(Options{APIKey: "sk-secret", APIURL: redirector.URL, HTTPClient: custom})
	_, err := fw.Classify(context.Background(), "hi")
	if err == nil {
		t.Fatal("expected redirect response to surface as APIError")
	}
	if targetHit.Load() {
		t.Fatal("redirect target was reached")
	}
	if custom.CheckRedirect != nil {
		t.Fatal("custom client was mutated")
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
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5})
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
				Body:       io.NopCloser(strings.NewReader(`{"prediction":"BENIGN","score":0.1,"threshold":0.5}`)),
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
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5})
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
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: prediction, Score: score, Threshold: 0.5})
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
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5})
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	long := strings.Repeat("b", ChunkWindowChars*2)
	_, err := fw.Classify(
		context.Background(),
		long,
		WithHook(HookToolResponse),
		WithToolName("fetch_webpage"),
		WithMetadata(ClassificationMetadata{"langgraph": map[string]any{"run_id": "run-chunked"}}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(received) < 2 {
		t.Fatalf("expected multiple chunk requests, got %d", len(received))
	}
	seenChunkIndexes := map[int]bool{}
	var requestID string
	for i, payload := range received {
		if payload.Hook != HookToolResponse {
			t.Errorf("hook[%d] = %q, want %q", i, payload.Hook, HookToolResponse)
		}
		if payload.ToolName != "fetch_webpage" {
			t.Errorf("tool_name[%d] = %q, want fetch_webpage", i, payload.ToolName)
		}
		if payload.Metadata == nil {
			t.Fatalf("metadata[%d] was not serialized", i)
		}
		if got := (*payload.Metadata)["langgraph"].(map[string]any)["run_id"]; got != "run-chunked" {
			t.Errorf("metadata[%d] run_id = %v, want run-chunked", i, got)
		}
		silmaril := (*payload.Metadata)["silmaril"].(map[string]any)
		raw := requireSilmarilMetadata(t, payload.Metadata, silmaril["request_id"].(string), 0, int(silmaril["chunk_index"].(float64)), len(received))
		if requestID == "" {
			requestID = raw["request_id"].(string)
		}
		if raw["request_id"] != requestID {
			t.Errorf("metadata[%d] request_id = %v, want %s", i, raw["request_id"], requestID)
		}
		seenChunkIndexes[int(raw["chunk_index"].(float64))] = true
	}
	for i := range received {
		if !seenChunkIndexes[i] {
			t.Errorf("missing chunk_index %d in metadata", i)
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
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5})
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
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5})
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
