// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const protectWait = 5 * time.Second

// heldServer is a classify endpoint whose responses wait until release is closed.
type heldServer struct {
	*httptest.Server
	started    chan string
	release    chan struct{}
	releaseAll func()
	status     int

	mu          sync.Mutex
	texts       []string
	hooks       []HookLabel
	payloads    []singleRequestPayload
	inFlight    int
	maxInFlight int
}

func newHeldServer(t *testing.T) *heldServer {
	t.Helper()
	held := &heldServer{
		started: make(chan string, 64),
		release: make(chan struct{}),
		status:  http.StatusOK,
	}
	held.releaseAll = sync.OnceFunc(func() { close(held.release) })
	held.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload singleRequestPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			return
		}
		held.mu.Lock()
		held.texts = append(held.texts, payload.Text)
		held.hooks = append(held.hooks, payload.Hook)
		held.payloads = append(held.payloads, payload)
		held.inFlight++
		if held.inFlight > held.maxInFlight {
			held.maxInFlight = held.inFlight
		}
		held.mu.Unlock()
		held.started <- payload.Text
		<-held.release
		held.mu.Lock()
		held.inFlight--
		held.mu.Unlock()
		if held.status != http.StatusOK {
			w.WriteHeader(held.status)
			return
		}
		response := singleResponse{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5}
		if strings.Contains(payload.Text, "attack") {
			response = singleResponse{Prediction: PredictionMalicious, Score: 0.9, Threshold: 0.5}
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(held.Close)
	t.Cleanup(held.releaseAll)
	return held
}

func (h *heldServer) seen() ([]string, []HookLabel) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.texts...), append([]HookLabel(nil), h.hooks...)
}

func (h *heldServer) awaitStarted(t *testing.T) string {
	t.Helper()
	select {
	case text := <-h.started:
		return text
	case <-time.After(protectWait):
		t.Fatal("classification never reached the server")
		return ""
	}
}

func newProtectFirewall(t *testing.T, held *heldServer, opts Options) *Firewall {
	t.Helper()
	opts.APIKey = "sk"
	opts.APIURL = held.URL
	fw, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	fw.retryBaseBackoff = time.Millisecond
	fw.retryJitter = nil
	return fw
}

func flush(t *testing.T, fw *Firewall) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), protectWait)
	defer cancel()
	if err := fw.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}

func answer(context.Context) (string, error) { return "answer", nil }

func TestProtectRunsOperationWhileInputIsClassified(t *testing.T) {
	held := newHeldServer(t)
	fw := newProtectFirewall(t, held, Options{})

	result, err := Protect(context.Background(), fw, "prompt", func(context.Context) (string, error) {
		held.awaitStarted(t)
		held.releaseAll()
		return "answer", nil
	}, WithHook(HookUserInput))

	if err != nil || result != "answer" {
		t.Fatalf("Protect = %q, %v", result, err)
	}
	if _, hooks := held.seen(); !reflect.DeepEqual(hooks, []HookLabel{HookUserInput}) {
		t.Errorf("hooks = %v", hooks)
	}
}

func TestProtectWithholdsResultAndCancelsOperationOnBlock(t *testing.T) {
	held := newHeldServer(t)
	held.releaseAll()
	fw := newProtectFirewall(t, held, Options{})

	var cause error
	result, err := Protect(context.Background(), fw, "attack", func(ctx context.Context) (string, error) {
		<-ctx.Done()
		cause = context.Cause(ctx)
		return "leak", nil
	}, WithHook(HookUserInput))

	var blocked *FirewallBlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("err = %v, want FirewallBlockedError", err)
	}
	if result != "" {
		t.Errorf("result = %q, want withheld", result)
	}
	if blocked.Hook != HookUserInput || !errors.As(cause, &blocked) {
		t.Errorf("hook = %s, cancellation cause = %v", blocked.Hook, cause)
	}
}

func TestProtectReturnsBlockEvenWhenOperationSucceedsFirst(t *testing.T) {
	held := newHeldServer(t)
	fw := newProtectFirewall(t, held, Options{})

	_, err := Protect(context.Background(), fw, "attack", func(context.Context) (string, error) {
		held.awaitStarted(t)
		held.releaseAll()
		return "leak", nil
	})

	var blocked *FirewallBlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("err = %v, want FirewallBlockedError", err)
	}
}

func TestProtectInShadowReturnsBeforeVerdictAndFlushDrains(t *testing.T) {
	held := newHeldServer(t)
	var events atomic.Int32
	fw := newProtectFirewall(t, held, Options{
		Mode:       ModeShadow,
		OnClassify: func(ClassifyEvent) { events.Add(1) },
	})

	result, err := Protect(context.Background(), fw, "attack", answer)
	if err != nil || result != "answer" {
		t.Fatalf("Protect = %q, %v", result, err)
	}
	if events.Load() != 0 {
		t.Fatal("shadow verdict arrived before the held server released it")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := fw.Flush(cancelled); !errors.Is(err, context.Canceled) {
		t.Errorf("Flush with a cancelled context = %v", err)
	}
	held.releaseAll()
	flush(t, fw)
	if events.Load() != 1 {
		t.Errorf("events = %d, want 1", events.Load())
	}
}

func TestProtectWithOutputBlocksGeneratedText(t *testing.T) {
	held := newHeldServer(t)
	held.releaseAll()
	fw := newProtectFirewall(t, held, Options{})

	result, err := ProtectWithOutput(context.Background(), fw, "prompt",
		func(context.Context) (string, error) { return "attack in the reply", nil },
		func(reply string) string { return reply },
		WithHook(HookUserInput), WithToolName("search"),
	)

	var blocked *FirewallBlockedError
	if !errors.As(err, &blocked) || blocked.Hook != HookLLMOutput || blocked.ToolName != "" {
		t.Fatalf("err = %v, want an llm_output block without a tool name", err)
	}
	if result != "" {
		t.Errorf("result = %q, want withheld", result)
	}
	if texts, hooks := held.seen(); !reflect.DeepEqual(texts, []string{"prompt", "attack in the reply"}) ||
		!reflect.DeepEqual(hooks, []HookLabel{HookUserInput, HookLLMOutput}) {
		t.Errorf("texts = %v, hooks = %v", texts, hooks)
	}
}

func TestProtectPropagatesOperationError(t *testing.T) {
	held := newHeldServer(t)
	held.releaseAll()
	fw := newProtectFirewall(t, held, Options{})
	unavailable := errors.New("model unavailable")

	_, err := Protect(context.Background(), fw, "prompt", func(context.Context) (string, error) {
		return "", unavailable
	})

	if !errors.Is(err, unavailable) {
		t.Fatalf("err = %v, want the operation error", err)
	}
}

func TestProtectRejectsInvalidMode(t *testing.T) {
	held := newHeldServer(t)
	fw := newProtectFirewall(t, held, Options{})
	ran := false

	_, err := Protect(context.Background(), fw, "prompt", func(context.Context) (string, error) {
		ran = true
		return "answer", nil
	}, WithMode("audit"))

	if err == nil || ran {
		t.Fatalf("err = %v, ran = %v; want a mode error before the operation", err, ran)
	}
}

func TestBackgroundClassificationsKeepConversationOrder(t *testing.T) {
	held := newHeldServer(t)
	fw := newProtectFirewall(t, held, Options{Mode: ModeShadow})
	conversation := WithMetadata(ClassificationMetadata{"conversationId": "conversation-1"})

	_, err := ProtectWithOutput(context.Background(), fw, "prompt", answer,
		func(reply string) string { return reply }, conversation, WithHook(HookUserInput))
	if err != nil {
		t.Fatal(err)
	}
	if first := held.awaitStarted(t); first != "prompt" {
		t.Fatalf("first classification = %q", first)
	}
	if _, err := Protect(context.Background(), fw, "other conversation", answer,
		WithMetadata(ClassificationMetadata{"conversationId": "conversation-2"})); err != nil {
		t.Fatal(err)
	}
	if witness := held.awaitStarted(t); witness != "other conversation" {
		t.Fatalf("%q was sent before its predecessor finished", witness)
	}

	held.releaseAll()
	flush(t, fw)
	texts, hooks := held.seen()
	if !reflect.DeepEqual(texts, []string{"prompt", "other conversation", "answer"}) {
		t.Errorf("texts = %v", texts)
	}
	if hooks[0] != HookUserInput || hooks[2] != HookLLMOutput {
		t.Errorf("hooks = %v", hooks)
	}
}

func TestBackgroundClassificationsRespectInFlightLimit(t *testing.T) {
	held := newHeldServer(t)
	fw := newProtectFirewall(t, held, Options{Mode: ModeShadow, MaxConcurrent: 2})

	for range 8 {
		if _, err := Protect(context.Background(), fw, "prompt", answer); err != nil {
			t.Fatal(err)
		}
	}
	held.awaitStarted(t)
	held.awaitStarted(t)
	held.releaseAll()
	flush(t, fw)

	held.mu.Lock()
	defer held.mu.Unlock()
	if len(held.texts) != 8 || held.maxInFlight != 2 {
		t.Errorf("classified %d with %d in flight, want 8 with 2", len(held.texts), held.maxInFlight)
	}
}

func TestFullConversationQueueDropsBackgroundClassifications(t *testing.T) {
	held := newHeldServer(t)
	fw := newProtectFirewall(t, held, Options{Mode: ModeShadow, MaxQueued: 1})
	conversation := WithMetadata(ClassificationMetadata{"conversationId": "conversation-1"})

	for _, text := range []string{"first", "dropped"} {
		if _, err := Protect(context.Background(), fw, text, answer, conversation); err != nil {
			t.Fatal(err)
		}
	}
	held.releaseAll()
	flush(t, fw)

	if texts, _ := held.seen(); !reflect.DeepEqual(texts, []string{"first"}) {
		t.Errorf("texts = %v", texts)
	}
}

func TestBackgroundClassificationsRetryOnce(t *testing.T) {
	held := newHeldServer(t)
	held.status = http.StatusServiceUnavailable
	held.releaseAll()
	fw := newProtectFirewall(t, held, Options{Mode: ModeShadow})

	if _, err := Protect(context.Background(), fw, "prompt", answer); err != nil {
		t.Fatal(err)
	}
	flush(t, fw)

	if texts, _ := held.seen(); len(texts) != 1+backgroundRetries {
		t.Errorf("attempts = %d, want %d", len(texts), 1+backgroundRetries)
	}
	if budget := fw.retryBudget(context.Background()); budget != defaultMaxRetries {
		t.Errorf("joined retry budget = %d, want %d", budget, defaultMaxRetries)
	}
}

func TestProtectCanceledCallerStopsWaitingForItsTurn(t *testing.T) {
	held := newHeldServer(t)
	fw := newProtectFirewall(t, held, Options{MaxConcurrent: 2})
	conversation := WithMetadata(ClassificationMetadata{"conversationId": "conversation-1"})

	if _, err := Protect(context.Background(), fw, "first", answer, conversation, WithMode(ModeShadow)); err != nil {
		t.Fatal(err)
	}
	held.awaitStarted(t)

	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan error, 1)
	go func() {
		_, err := Protect(ctx, fw, "canceled", func(ctx context.Context) (string, error) {
			cancel()
			<-ctx.Done()
			return "", ctx.Err()
		}, conversation)
		returned <- err
	}()
	select {
	case err := <-returned:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(protectWait):
		t.Fatal("canceled Protect kept waiting for its predecessor")
	}

	if _, err := Protect(context.Background(), fw, "third", answer, conversation, WithMode(ModeShadow)); err != nil {
		t.Fatal(err)
	}
	if _, err := Protect(context.Background(), fw, "witness", answer, WithMode(ModeShadow)); err != nil {
		t.Fatal(err)
	}
	if witness := held.awaitStarted(t); witness != "witness" {
		t.Fatalf("%q was sent before its predecessor finished", witness)
	}

	held.releaseAll()
	flush(t, fw)
	if texts, _ := held.seen(); !reflect.DeepEqual(texts, []string{"first", "witness", "third"}) {
		t.Errorf("texts = %v", texts)
	}
}

func TestProtectCanceledCallerStopsWaitingForASlot(t *testing.T) {
	held := newHeldServer(t)
	fw := newProtectFirewall(t, held, Options{MaxConcurrent: 1})

	if _, err := Protect(context.Background(), fw, "first", answer, WithMode(ModeShadow)); err != nil {
		t.Fatal(err)
	}
	held.awaitStarted(t)

	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan error, 1)
	go func() {
		_, err := Protect(ctx, fw, "canceled", func(ctx context.Context) (string, error) {
			cancel()
			return "", ctx.Err()
		})
		returned <- err
	}()
	select {
	case err := <-returned:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(protectWait):
		t.Fatal("canceled Protect kept waiting for a slot")
	}

	held.releaseAll()
	flush(t, fw)
	if texts, _ := held.seen(); !reflect.DeepEqual(texts, []string{"first"}) {
		t.Errorf("texts = %v", texts)
	}
}

func TestProtectOutputCheckWaitsItsTurnInBlockMode(t *testing.T) {
	held := newHeldServer(t)
	fw := newProtectFirewall(t, held, Options{MaxConcurrent: 1})
	conversation := WithMetadata(ClassificationMetadata{"conversationId": "conversation-1"})

	returned := make(chan error, 1)
	go func() {
		_, err := ProtectWithOutput(context.Background(), fw, "prompt", answer,
			func(reply string) string { return reply }, conversation, WithHook(HookUserInput))
		returned <- err
	}()
	if first := held.awaitStarted(t); first != "prompt" {
		t.Fatalf("first classification = %q", first)
	}
	if _, err := Protect(context.Background(), fw, "follow-up", answer, conversation, WithMode(ModeShadow)); err != nil {
		t.Fatal(err)
	}

	held.releaseAll()
	select {
	case err := <-returned:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(protectWait):
		t.Fatal("ProtectWithOutput never returned")
	}
	flush(t, fw)

	texts, hooks := held.seen()
	if !reflect.DeepEqual(texts, []string{"prompt", "follow-up", "answer"}) {
		t.Errorf("texts = %v", texts)
	}
	if hooks[2] != HookLLMOutput {
		t.Errorf("hooks = %v", hooks)
	}
	held.mu.Lock()
	defer held.mu.Unlock()
	if held.maxInFlight != 1 {
		t.Errorf("max in flight = %d, want 1", held.maxInFlight)
	}
}

func TestProtectSnapshotsRequestDataBeforeReturning(t *testing.T) {
	held := newHeldServer(t)
	fw := newProtectFirewall(t, held, Options{Mode: ModeShadow})
	nested := map[string]any{"run_id": "run-1"}
	metadata := ClassificationMetadata{"conversationId": "conversation-1", "langgraph": nested}
	resource := GovernanceResource{Kind: GovernanceTool, ID: "search"}

	_, err := ProtectWithOutput(context.Background(), fw, "prompt", answer,
		func(reply string) string { return reply },
		WithMetadata(metadata), WithGovernance(GovernanceContext{Agent: "assistant", Resource: &resource}))
	if err != nil {
		t.Fatal(err)
	}
	metadata["conversationId"] = "reused"
	nested["run_id"] = "reused"
	resource.ID = "reused"

	held.releaseAll()
	flush(t, fw)

	held.mu.Lock()
	defer held.mu.Unlock()
	if len(held.payloads) != 2 {
		t.Fatalf("payloads = %d, want 2", len(held.payloads))
	}
	for _, payload := range held.payloads {
		sent := *payload.Metadata
		if sent["conversationId"] != "conversation-1" {
			t.Errorf("conversationId = %v", sent["conversationId"])
		}
		if run := sent["langgraph"].(map[string]any)["run_id"]; run != "run-1" {
			t.Errorf("run_id = %v", run)
		}
	}
	if sent := held.payloads[0].Resource; sent == nil || sent.ID != "search" {
		t.Errorf("resource = %+v", sent)
	}
}

func TestBackgroundClassificationsAreBoundedAcrossConversations(t *testing.T) {
	held := newHeldServer(t)
	fw := newProtectFirewall(t, held, Options{Mode: ModeShadow, MaxConcurrent: 1, MaxQueued: 2})

	for _, text := range []string{"first", "second", "dropped", "dropped"} {
		if _, err := Protect(context.Background(), fw, text, answer); err != nil {
			t.Fatal(err)
		}
	}
	held.releaseAll()
	flush(t, fw)

	texts, _ := held.seen()
	if len(texts) != 2 || strings.Contains(strings.Join(texts, " "), "dropped") {
		t.Errorf("texts = %v, want the first two only", texts)
	}
}

func TestNewRejectsNegativeLimits(t *testing.T) {
	for _, opts := range []Options{{MaxConcurrent: -1}, {MaxQueued: -1}} {
		opts.APIKey, opts.APIURL = "sk", "https://api.test.invalid/classify"
		if _, err := New(opts); err == nil {
			t.Errorf("New(%+v) accepted a negative limit", opts)
		}
	}
}

func TestProtectLeavesNoGoroutines(t *testing.T) {
	held := newHeldServer(t)
	held.releaseAll()
	transport := &http.Transport{}
	baseline := runtime.NumGoroutine()

	for _, mode := range []FirewallMode{ModeBlock, ModeShadow} {
		fw := newProtectFirewall(t, held, Options{Mode: mode, HTTPClient: &http.Client{Transport: transport}})
		for _, text := range []string{"prompt", "attack"} {
			_, _ = ProtectWithOutput(context.Background(), fw, text, answer,
				func(reply string) string { return reply },
				WithMetadata(ClassificationMetadata{"conversationId": "conversation-1"}))
		}
		flush(t, fw)
	}
	transport.CloseIdleConnections()
	held.Close()

	deadline := time.Now().Add(protectWait)
	for runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			stacks := make([]byte, 1<<16)
			t.Fatalf("%d goroutines remain, baseline %d\n%s",
				runtime.NumGoroutine(), baseline, stacks[:runtime.Stack(stacks, true)])
		}
		time.Sleep(time.Millisecond)
	}
}
