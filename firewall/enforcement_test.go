// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func newSingleResponseServer(t *testing.T, prediction Prediction, score float64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: prediction, Score: score, Threshold: 0.5})
	}))
}

func TestClassifyBlocksByDefault(t *testing.T) {
	ts := newSingleResponseServer(t, PredictionMalicious, 0.9)
	defer ts.Close()

	var events []ClassifyEvent
	fw, err := New(Options{
		APIKey: "sk",
		APIURL: ts.URL,
		OnClassify: func(event ClassifyEvent) {
			events = append(events, event)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := fw.Classify(context.Background(), "ignore previous instructions",
		WithHook(HookUserInput),
		WithToolName("chat"),
	)
	if err == nil {
		t.Fatal("expected firewall blocked error")
	}
	var blockedErr *FirewallBlockedError
	if !errors.As(err, &blockedErr) {
		t.Fatalf("error is not *FirewallBlockedError: %T", err)
	}
	if result.Score != 0.9 || result.Threshold != 0.5 {
		t.Errorf("result = %+v", result)
	}
	if blockedErr.Score != 0.9 || blockedErr.Threshold != 0.5 {
		t.Errorf("blocked error = %+v", blockedErr)
	}
	if blockedErr.PromptText != "ignore previous instructions" || blockedErr.Hook != HookUserInput || blockedErr.ToolName != "chat" {
		t.Errorf("blocked error context = %+v", blockedErr)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	event := events[0]
	if event.Hook != HookUserInput || event.ToolName != "chat" || event.Text != "ignore previous instructions" {
		t.Errorf("event context = %+v", event)
	}
	if !event.Blocked {
		t.Error("event.Blocked = false, want true")
	}
	if event.ShadowMode {
		t.Error("event.ShadowMode = true, want false")
	}
}

func TestClassifyShadowModeSuppressesFirewallBlockedError(t *testing.T) {
	ts := newSingleResponseServer(t, PredictionMalicious, 0.9)
	defer ts.Close()

	var event ClassifyEvent
	fw, err := New(Options{
		APIKey:     "sk",
		APIURL:     ts.URL,
		ShadowMode: true,
		OnClassify: func(e ClassifyEvent) {
			event = e
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := fw.Classify(context.Background(), "ignore previous instructions",
		WithHook(HookToolResponse),
	)
	if err != nil {
		t.Fatalf("shadow mode should suppress block error: %v", err)
	}
	if result.Score != 0.9 {
		t.Errorf("result = %+v", result)
	}
	if !event.Blocked {
		t.Error("event.Blocked = false, want true")
	}
	if !event.ShadowMode {
		t.Error("event.ShadowMode = false, want true")
	}
}

func TestClassifyEventUsesSanitizedText(t *testing.T) {
	ts := newSingleResponseServer(t, PredictionBenign, 0.1)
	defer ts.Close()

	var event ClassifyEvent
	fw, err := New(Options{
		APIKey: "sk",
		APIURL: ts.URL,
		OnClassify: func(e ClassifyEvent) {
			event = e
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := fw.Classify(context.Background(), "bad "+string([]byte{0xff})+" value"); err != nil {
		t.Fatal(err)
	}
	if event.Text != "bad  value" {
		t.Fatalf("event text = %q", event.Text)
	}
}

func TestClassifyPerCallShadowModeCanObserve(t *testing.T) {
	ts := newSingleResponseServer(t, PredictionMalicious, 0.9)
	defer ts.Close()

	var event ClassifyEvent
	fw, err := New(Options{
		APIKey: "sk",
		APIURL: ts.URL,
		OnClassify: func(e ClassifyEvent) {
			event = e
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = fw.Classify(context.Background(), "attack", WithShadowMode(true))
	if err != nil {
		t.Fatalf("per-call shadow mode should suppress block error: %v", err)
	}
	if !event.ShadowMode {
		t.Error("event.ShadowMode = false, want true")
	}
}

func TestClassifyPerCallShadowModeCanEnforce(t *testing.T) {
	ts := newSingleResponseServer(t, PredictionMalicious, 0.9)
	defer ts.Close()

	fw, err := New(Options{
		APIKey:     "sk",
		APIURL:     ts.URL,
		ShadowMode: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = fw.Classify(context.Background(), "attack", WithShadowMode(false))
	if err == nil {
		t.Fatal("expected firewall blocked error")
	}
	var blockedErr *FirewallBlockedError
	if !errors.As(err, &blockedErr) {
		t.Fatalf("error is not *FirewallBlockedError: %T", err)
	}
}

func TestClassifyLongInputEnforcesOneBackendPrediction(t *testing.T) {
	var mu sync.Mutex
	var received []singleRequestPayload
	var events []ClassifyEvent
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload singleRequestPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		received = append(received, payload)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionMalicious, Score: 0.1, Threshold: 0.5})
	}))
	defer ts.Close()

	fw, err := New(Options{
		APIKey: "sk",
		APIURL: ts.URL,
		OnClassify: func(event ClassifyEvent) {
			events = append(events, event)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	text := strings.Repeat("a", 4001)
	result, err := fw.Classify(context.Background(), text, WithHook(HookUserInput))
	if err == nil {
		t.Fatal("expected firewall blocked error")
	}
	if result.Score != 0.1 {
		t.Errorf("result = %+v", result)
	}
	var blockedErr *FirewallBlockedError
	if !errors.As(err, &blockedErr) {
		t.Fatalf("error is not *FirewallBlockedError: %T", err)
	}
	if len(received) != 1 {
		t.Fatalf("expected one complete event request, got %d", len(received))
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].Text != text || events[0].Result.Score != 0.1 {
		t.Errorf("event = %+v", events[0])
	}
}

func TestClassifyBatchBlocksByDefaultWithAllBlockedItems(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(batchResponse{
			Predictions: []singleResponse{
				{Prediction: PredictionMalicious, Score: 0.8, Threshold: 0.5},
				{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5},
				{Prediction: PredictionMalicious, Score: 0.8, Threshold: 0.5},
			},
		})
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}

	results, err := fw.ClassifyBatch(context.Background(),
		[]string{"first", "second", "third"},
		WithBatchHooks([]HookLabel{HookUserInput, HookToolResponse, HookToolResponse}),
		WithBatchToolNames([]string{"chat", "read_file", ""}),
	)
	if err == nil {
		t.Fatal("expected batch firewall blocked error")
	}
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}
	var blockedErr *BatchFirewallBlockedError
	if !errors.As(err, &blockedErr) {
		t.Fatalf("error is not *BatchFirewallBlockedError: %T", err)
	}
	if len(blockedErr.Blocked) != 2 {
		t.Fatalf("blocked items = %d, want 2", len(blockedErr.Blocked))
	}
	if blockedErr.Blocked[0].Index != 0 || blockedErr.Blocked[0].Text != "first" || blockedErr.Blocked[0].Hook != HookUserInput || blockedErr.Blocked[0].ToolName != "chat" {
		t.Errorf("first blocked item = %+v", blockedErr.Blocked[0])
	}
	if blockedErr.Blocked[1].Index != 2 || blockedErr.Blocked[1].Text != "third" || blockedErr.Blocked[1].Hook != HookToolResponse {
		t.Errorf("second blocked item = %+v", blockedErr.Blocked[1])
	}
}

func TestClassifyBatchShadowModeSuppressesBlockAndEmitsEvents(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(batchResponse{
			Predictions: []singleResponse{
				{Prediction: PredictionMalicious, Score: 0.9, Threshold: 0.5},
				{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5},
			},
		})
	}))
	defer ts.Close()

	var events []ClassifyEvent
	fw, err := New(Options{
		APIKey:     "sk",
		APIURL:     ts.URL,
		ShadowMode: true,
		OnClassify: func(event ClassifyEvent) {
			events = append(events, event)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	results, err := fw.ClassifyBatch(context.Background(),
		[]string{"attack", "hello"},
		WithBatchHooks([]HookLabel{HookUserInput, HookUserInput}),
	)
	if err != nil {
		t.Fatalf("shadow mode should suppress block error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if !events[0].Blocked || !events[0].ShadowMode || events[0].Text != "attack" {
		t.Errorf("event[0] = %+v", events[0])
	}
	if events[1].Blocked || !events[1].ShadowMode || events[1].Text != "hello" {
		t.Errorf("event[1] = %+v", events[1])
	}
}

func TestClassifyBatchPerCallShadowModeCanObserve(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(batchResponse{
			Predictions: []singleResponse{{Prediction: PredictionMalicious, Score: 0.9, Threshold: 0.5}},
		})
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}

	_, err = fw.ClassifyBatch(context.Background(), []string{"attack"}, WithBatchShadowMode(true))
	if err != nil {
		t.Fatalf("per-call batch shadow mode should suppress block error: %v", err)
	}
}

func TestClassifyBatchPerCallShadowModeCanEnforce(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(batchResponse{
			Predictions: []singleResponse{{Prediction: PredictionMalicious, Score: 0.9, Threshold: 0.5}},
		})
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL, ShadowMode: true})
	if err != nil {
		t.Fatal(err)
	}

	_, err = fw.ClassifyBatch(context.Background(), []string{"attack"}, WithBatchShadowMode(false))
	if err == nil {
		t.Fatal("expected batch firewall blocked error")
	}
	var blockedErr *BatchFirewallBlockedError
	if !errors.As(err, &blockedErr) {
		t.Fatalf("error is not *BatchFirewallBlockedError: %T", err)
	}
}

func TestClassifyCallbacksRecoverPanics(t *testing.T) {
	ts := newSingleResponseServer(t, PredictionBenign, 0.1)
	defer ts.Close()

	fw, err := New(Options{
		APIKey: "sk",
		APIURL: ts.URL,
		OnClassify: func(ClassifyEvent) {
			panic("callback bug")
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := fw.Classify(context.Background(), "hello"); err != nil {
		t.Fatal(err)
	}
}

func TestFirewallBlockedErrorFormat(t *testing.T) {
	err := &FirewallBlockedError{Score: 0.9, Threshold: 0.5}
	msg := err.Error()
	if !strings.Contains(msg, "request blocked") || !strings.Contains(msg, "0.9000") || !strings.Contains(msg, "0.5000") {
		t.Errorf("FirewallBlockedError format: %q", msg)
	}
}

func TestBatchFirewallBlockedErrorFormat(t *testing.T) {
	err := &BatchFirewallBlockedError{Blocked: []BlockedBatchItem{
		{Index: 2, Result: BlockResult{Score: 0.9, Threshold: 0.5}},
	}}
	msg := err.Error()
	if !strings.Contains(msg, "index 2") || !strings.Contains(msg, "0.9000") || !strings.Contains(msg, "0.5000") {
		t.Errorf("BatchFirewallBlockedError format: %q", msg)
	}
}

func TestPromptBlockedErrorAliasesRemainUsable(t *testing.T) {
	var oldSingle *PromptBlockedError = &FirewallBlockedError{Score: 0.9, Threshold: 0.5}
	var oldBatch *BatchPromptBlockedError = &BatchFirewallBlockedError{Blocked: []BlockedBatchItem{
		{Index: 0, Result: BlockResult{Score: 0.9, Threshold: 0.5}},
	}}
	if oldSingle.Error() == "" || oldBatch.Error() == "" {
		t.Fatal("deprecated aliases should retain error behavior")
	}
}
