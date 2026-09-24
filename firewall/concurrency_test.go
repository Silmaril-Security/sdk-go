// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClassifyOverlappingCallsCompleteOutOfOrder(t *testing.T) {
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseSlow) })

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload singleRequestPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			return
		}
		switch payload.Text {
		case "slow":
			close(slowStarted)
			<-releaseSlow
			_ = json.NewEncoder(w).Encode(singleResponse{
				Prediction: PredictionMalicious, Score: 0.91, Threshold: 0.5, Mode: ModeShadow,
			})
		case "fast":
			_ = json.NewEncoder(w).Encode(singleResponse{
				Prediction: PredictionBenign, Score: 0.12, Threshold: 0.5, Mode: ModeShadow,
			})
		default:
			t.Errorf("unexpected text %q", payload.Text)
		}
	}))
	defer ts.Close()
	defer release()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL, Mode: ModeShadow})
	if err != nil {
		t.Fatal(err)
	}

	type completion struct {
		label string
		res   BlockResult
		err   error
	}
	done := make(chan completion, 2)

	go func() {
		res, err := fw.Classify(context.Background(), "slow", WithRequestID("req-slow"))
		done <- completion{label: "slow", res: res, err: err}
	}()
	select {
	case <-slowStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("slow request never reached the server")
	}
	go func() {
		res, err := fw.Classify(context.Background(), "fast", WithRequestID("req-fast"))
		done <- completion{label: "fast", res: res, err: err}
	}()

	var first completion
	select {
	case first = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("fast call did not complete while the slow handler was held")
	}
	if first.err != nil {
		t.Fatalf("first completion %s: %v", first.label, first.err)
	}
	if first.label != "fast" {
		t.Fatalf("first completion = %s, want fast while slow remains blocked", first.label)
	}
	if first.res.Prediction != PredictionBenign || first.res.Score != 0.12 {
		t.Errorf("fast result = %+v", first.res)
	}

	release()
	var second completion
	select {
	case second = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("slow call did not complete after release")
	}
	if second.err != nil {
		t.Fatalf("second completion %s: %v", second.label, second.err)
	}
	if second.label != "slow" {
		t.Fatalf("second completion = %s, want slow", second.label)
	}
	if second.res.Prediction != PredictionMalicious || second.res.Score != 0.91 {
		t.Errorf("slow result = %+v", second.res)
	}
}

func TestClassifyConcurrentMetadataAndRequestIDIsolation(t *testing.T) {
	const n = 12
	type captured struct {
		text      string
		requestID string
		runID     string
	}
	var mu sync.Mutex
	got := make([]captured, 0, n)
	var maxActive atomic.Int32
	var active atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			previous := maxActive.Load()
			if current <= previous || maxActive.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		var payload singleRequestPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			return
		}
		silmaril, _ := (*payload.Metadata)["silmaril"].(map[string]any)
		runID, _ := (*payload.Metadata)["run_id"].(string)
		requestID, _ := silmaril["request_id"].(string)
		mu.Lock()
		got = append(got, captured{text: payload.Text, requestID: requestID, runID: runID})
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(singleResponse{
			Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5,
		})
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			text := "event-" + strconv.Itoa(i)
			requestID := "req-" + strconv.Itoa(i)
			metadata := ClassificationMetadata{"run_id": "run-" + strconv.Itoa(i)}
			if _, err := fw.Classify(context.Background(), text,
				WithRequestID(requestID),
				WithMetadata(metadata),
			); err != nil {
				t.Errorf("classify %s: %v", text, err)
			}
		}()
	}
	wg.Wait()

	if maxActive.Load() < 2 {
		t.Fatalf("max active requests = %d, want overlapping calls", maxActive.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != n {
		t.Fatalf("captured %d payloads, want %d", len(got), n)
	}
	seenIDs := make(map[string]string, n)
	for _, item := range got {
		if item.requestID == "" {
			t.Errorf("missing request_id for %q", item.text)
			continue
		}
		if other, ok := seenIDs[item.requestID]; ok {
			t.Errorf("request_id %q reused for %q and %q", item.requestID, other, item.text)
		}
		seenIDs[item.requestID] = item.text
		wantRun := "run-" + item.text[len("event-"):]
		if item.runID != wantRun {
			t.Errorf("text %q run_id = %q, want %q", item.text, item.runID, wantRun)
		}
		wantID := "req-" + item.text[len("event-"):]
		if item.requestID != wantID {
			t.Errorf("text %q request_id = %q, want %q", item.text, item.requestID, wantID)
		}
	}
}

func TestClassifyBatchConcurrentPreservesItemOrder(t *testing.T) {
	type capturedItem struct {
		text  string
		index int
		runID string
	}
	type captured struct {
		requestID string
		items     []capturedItem
	}
	var mu sync.Mutex
	var got []captured
	started := make(chan struct{}, 2)
	hold := make(chan struct{})
	release := sync.OnceFunc(func() { close(hold) })

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload batchRequestPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			return
		}
		if len(payload.Metadata) != len(payload.Texts) {
			t.Errorf("metadata length %d, want %d", len(payload.Metadata), len(payload.Texts))
			return
		}
		items := make([]capturedItem, len(payload.Texts))
		requestID := ""
		for i, meta := range payload.Metadata {
			silmaril, _ := (*meta)["silmaril"].(map[string]any)
			requestID, _ = silmaril["request_id"].(string)
			runID, _ := (*meta)["run_id"].(string)
			index, ok := silmaril["input_index"].(float64)
			if !ok {
				t.Errorf("input_index[%d] = %#v, want numeric", i, silmaril["input_index"])
			}
			items[i] = capturedItem{text: payload.Texts[i], index: int(index), runID: runID}
		}
		mu.Lock()
		got = append(got, captured{requestID: requestID, items: items})
		mu.Unlock()
		started <- struct{}{}
		<-hold
		predictions := make([]singleResponse, len(payload.Texts))
		for i, text := range payload.Texts {
			score := 0.1
			if len(text) > 0 {
				score = float64(text[len(text)-1]-'0') / 10
			}
			predictions[i] = singleResponse{Prediction: PredictionBenign, Score: score, Threshold: 0.5}
		}
		_ = json.NewEncoder(w).Encode(batchResponse{Predictions: predictions})
	}))
	defer ts.Close()
	defer release()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}

	type batchOutcome struct {
		id      string
		results []BlockResult
		err     error
	}
	outcomes := make(chan batchOutcome, 2)
	go func() {
		results, err := fw.ClassifyBatch(context.Background(), []string{"a1", "a2"},
			WithBatchRequestID("batch-a"),
			WithBatchMetadata([]ClassificationMetadata{
				{"run_id": "a-0"},
				{"run_id": "a-1"},
			}),
		)
		outcomes <- batchOutcome{id: "batch-a", results: results, err: err}
	}()
	go func() {
		results, err := fw.ClassifyBatch(context.Background(), []string{"b3", "b4", "b5"},
			WithBatchRequestID("batch-b"),
			WithBatchMetadata([]ClassificationMetadata{
				{"run_id": "b-0"},
				{"run_id": "b-1"},
				{"run_id": "b-2"},
			}),
		)
		outcomes <- batchOutcome{id: "batch-b", results: results, err: err}
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("batch requests did not overlap")
		}
	}
	release()

	gotA := false
	gotB := false
	for i := 0; i < 2; i++ {
		out := <-outcomes
		if out.err != nil {
			t.Fatalf("%s: %v", out.id, out.err)
		}
		switch out.id {
		case "batch-a":
			gotA = true
			if len(out.results) != 2 || out.results[0].Score != 0.1 || out.results[1].Score != 0.2 {
				t.Fatalf("batch-a results = %+v", out.results)
			}
		case "batch-b":
			gotB = true
			if len(out.results) != 3 || out.results[0].Score != 0.3 || out.results[1].Score != 0.4 || out.results[2].Score != 0.5 {
				t.Fatalf("batch-b results = %+v", out.results)
			}
		}
	}
	if !gotA || !gotB {
		t.Fatal("missing batch outcome")
	}

	want := map[string][]capturedItem{
		"batch-a": {
			{text: "a1", index: 0, runID: "a-0"},
			{text: "a2", index: 1, runID: "a-1"},
		},
		"batch-b": {
			{text: "b3", index: 0, runID: "b-0"},
			{text: "b4", index: 1, runID: "b-1"},
			{text: "b5", index: 2, runID: "b-2"},
		},
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("captured %d batch payloads, want 2", len(got))
	}
	for _, batch := range got {
		expected, ok := want[batch.requestID]
		if !ok {
			t.Errorf("unexpected or duplicated request_id %q", batch.requestID)
			continue
		}
		delete(want, batch.requestID)
		if !reflect.DeepEqual(batch.items, expected) {
			t.Errorf("%s items = %+v, want %+v", batch.requestID, batch.items, expected)
		}
	}
	for requestID := range want {
		t.Errorf("no request captured for %q", requestID)
	}
}

func TestClassifyCancelDuringHTTPDoesNotAffectSibling(t *testing.T) {
	started := make(chan string, 2)
	holdSibling := make(chan struct{})
	releaseSibling := sync.OnceFunc(func() { close(holdSibling) })
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload singleRequestPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			return
		}
		started <- payload.Text
		if payload.Text == "cancel-me" {
			<-r.Context().Done()
			return
		}
		<-holdSibling
		_ = json.NewEncoder(w).Encode(singleResponse{
			Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5,
		})
	}))
	defer ts.Close()
	defer releaseSibling()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelErr := make(chan error, 1)
	siblingRes := make(chan BlockResult, 1)
	siblingErr := make(chan error, 1)

	go func() {
		_, err := fw.Classify(ctx, "cancel-me", WithRequestID("req-cancel"))
		cancelErr <- err
	}()
	go func() {
		res, err := fw.Classify(context.Background(), "keep-me", WithRequestID("req-keep"))
		siblingRes <- res
		siblingErr <- err
	}()

	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case text := <-started:
			seen[text] = true
		case <-time.After(2 * time.Second):
			t.Fatal("overlapping HTTP calls did not start")
		}
	}
	if !seen["cancel-me"] || !seen["keep-me"] {
		t.Fatalf("started = %v", seen)
	}

	cancel()
	select {
	case err := <-cancelErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled call error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled call did not return")
	}

	releaseSibling()
	select {
	case err := <-siblingErr:
		if err != nil {
			t.Fatalf("sibling error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sibling call did not return")
	}
	res := <-siblingRes
	if res.Prediction != PredictionBenign {
		t.Errorf("sibling result = %+v", res)
	}
}

func TestClassifyCancelDuringRetrySleepDoesNotAffectSibling(t *testing.T) {
	var cancelCalls atomic.Int32
	holdSibling := make(chan struct{})
	releaseSibling := sync.OnceFunc(func() { close(holdSibling) })

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload singleRequestPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			return
		}
		if payload.Text == "cancel-me" {
			cancelCalls.Add(1)
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		<-holdSibling
		_ = json.NewEncoder(w).Encode(singleResponse{
			Prediction: PredictionBenign, Score: 0.22, Threshold: 0.5,
		})
	}))
	defer ts.Close()
	defer releaseSibling()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	// An hour-long backoff cannot elapse inside this test, so returning at all
	// means cancellation aborted the wait rather than the timer firing.
	fw.retryBaseBackoff = time.Hour
	fw.retryMaxBackoff = time.Hour
	retryDelayComputed := make(chan struct{})
	var computedOnce sync.Once
	fw.retryJitter = func(delay time.Duration) time.Duration {
		computedOnce.Do(func() { close(retryDelayComputed) })
		return delay
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelErr := make(chan error, 1)
	go func() {
		_, err := fw.Classify(ctx, "cancel-me")
		cancelErr <- err
	}()

	select {
	case <-retryDelayComputed:
	case <-time.After(2 * time.Second):
		t.Fatal("retry delay was never computed")
	}

	siblingRes := make(chan BlockResult, 1)
	siblingErr := make(chan error, 1)
	go func() {
		res, err := fw.Classify(context.Background(), "keep-me")
		siblingRes <- res
		siblingErr <- err
	}()

	cancel()
	select {
	case err := <-cancelErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled retry error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled retry did not return")
	}
	if got := cancelCalls.Load(); got != 1 {
		t.Fatalf("cancel-me HTTP calls = %d, want 1 (canceled during retry sleep)", got)
	}

	releaseSibling()
	select {
	case err := <-siblingErr:
		if err != nil {
			t.Fatalf("sibling error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sibling call did not return")
	}
	res := <-siblingRes
	if res.Score != 0.22 {
		t.Errorf("sibling result = %+v", res)
	}
}

// doneObservingContext reports the first read of Done. A select evaluates its
// channel operands on entry, so that read marks the moment waitBeforeRetry
// begins waiting.
type doneObservingContext struct {
	context.Context
	once     sync.Once
	observed chan struct{}
}

func (c *doneObservingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

func TestWaitBeforeRetryCancelsAfterEnteringWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observing := &doneObservingContext{Context: ctx, observed: make(chan struct{})}

	waitErr := make(chan error, 1)
	go func() {
		waitErr <- waitBeforeRetry(observing, time.Hour)
	}()

	select {
	case <-observing.observed:
	case <-time.After(2 * time.Second):
		t.Fatal("waitBeforeRetry never entered its wait")
	}
	select {
	case err := <-waitErr:
		t.Fatalf("waitBeforeRetry returned before cancel: %v", err)
	default:
	}

	cancel()
	select {
	case err := <-waitErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waitBeforeRetry error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitBeforeRetry did not return after cancel")
	}
}

func TestWaitBeforeRetryReturnsAfterDelay(t *testing.T) {
	if err := waitBeforeRetry(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("waitBeforeRetry error = %v, want nil", err)
	}
}
