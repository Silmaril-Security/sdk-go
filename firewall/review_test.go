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

func reviewLevelPtr(level ReviewLevel) *ReviewLevel {
	return &level
}

func TestNewRejectsInvalidReview(t *testing.T) {
	invalid := []ReviewLevel{"STANDARD", "Deep", " standard", "deep ", "other", "null"}
	for _, review := range invalid {
		_, err := New(Options{APIKey: "sk", APIURL: "https://example.com", Review: review})
		if err == nil || !strings.Contains(err.Error(), "review must be standard or deep") {
			t.Errorf("Review=%q error = %v", review, err)
		}
	}
}

func TestNewAcceptsOmittedAndValidReview(t *testing.T) {
	fw, err := New(Options{APIKey: "sk", APIURL: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if fw.review != "" {
		t.Errorf("default review = %q, want omitted", fw.review)
	}
	for _, review := range []ReviewLevel{ReviewStandard, ReviewDeep} {
		fw, err := New(Options{APIKey: "sk", APIURL: "https://example.com", Review: review})
		if err != nil {
			t.Fatalf("Review=%q: %v", review, err)
		}
		if fw.review != review {
			t.Errorf("stored review = %q, want %q", fw.review, review)
		}
	}
}

func TestWithReviewEmptyErrorsWithoutHTTP(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		t.Error("empty per-call review must not reach the network")
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL, Review: ReviewDeep})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fw.Classify(context.Background(), "hi", WithReview(""))
	if err == nil || !strings.Contains(err.Error(), `review must be standard or deep, got ""`) {
		t.Fatalf("error = %v", err)
	}
	_, err = fw.ClassifyBatch(context.Background(), []string{"hi"}, WithBatchReview(""))
	if err == nil || !strings.Contains(err.Error(), `review must be standard or deep, got ""`) {
		t.Fatalf("batch error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("HTTP calls = %d, want 0", calls.Load())
	}
}

func TestWithReviewInvalidEnumErrorsWithoutHTTP(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer ts.Close()
	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	for _, review := range []ReviewLevel{"STANDARD", "Deep", " standard", "deep\n"} {
		_, err := fw.Classify(context.Background(), "hi", WithReview(review))
		if err == nil || !strings.Contains(err.Error(), "review must be standard or deep") {
			t.Errorf("Classify %q error = %v", review, err)
		}
		_, err = fw.ClassifyBatch(context.Background(), []string{"hi"}, WithBatchReview(review))
		if err == nil || !strings.Contains(err.Error(), "review must be standard or deep") {
			t.Errorf("ClassifyBatch %q error = %v", review, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("HTTP calls = %d, want 0", calls.Load())
	}
}

func TestClassifyOmitsReviewByDefault(t *testing.T) {
	var raw map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(singleResponse{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5})
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	result, err := fw.Classify(context.Background(), "hi")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["review"]; ok {
		t.Errorf("review should be omitted: %v", raw)
	}
	if result.Review != "" {
		t.Errorf("result.Review = %q, want empty", result.Review)
	}
}

func TestClassifyExplicitReviewSingleAndBatch(t *testing.T) {
	t.Parallel()
	for _, review := range []ReviewLevel{ReviewStandard, ReviewDeep} {
		review := review
		t.Run(string(review)+"/single", func(t *testing.T) {
			var raw map[string]any
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
					t.Fatal(err)
				}
				_ = json.NewEncoder(w).Encode(singleResponse{
					Prediction: PredictionBenign,
					Score:      0.1,
					Threshold:  0.5,
					Review:     reviewLevelPtr(review),
				})
			}))
			defer ts.Close()
			fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
			if err != nil {
				t.Fatal(err)
			}
			result, err := fw.Classify(context.Background(), "hi", WithReview(review))
			if err != nil {
				t.Fatal(err)
			}
			if raw["review"] != string(review) {
				t.Errorf("payload review = %#v, want %q", raw["review"], review)
			}
			if result.Review != review {
				t.Errorf("result.Review = %q, want %q", result.Review, review)
			}
		})
		t.Run(string(review)+"/batch", func(t *testing.T) {
			var raw map[string]any
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
					t.Fatal(err)
				}
				_ = json.NewEncoder(w).Encode(batchResponse{
					Review: reviewLevelPtr(review),
					Predictions: []singleResponse{
						{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5},
						{Prediction: PredictionBenign, Score: 0.2, Threshold: 0.5},
					},
				})
			}))
			defer ts.Close()
			fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
			if err != nil {
				t.Fatal(err)
			}
			results, err := fw.ClassifyBatch(context.Background(), []string{"a", "b"}, WithBatchReview(review))
			if err != nil {
				t.Fatal(err)
			}
			if raw["review"] != string(review) {
				t.Errorf("payload review = %#v, want %q", raw["review"], review)
			}
			if len(results) != 2 || results[0].Review != review || results[1].Review != review {
				t.Errorf("results = %+v", results)
			}
		})
	}
}

func TestClassifyReviewPerCallPrecedesClientDefault(t *testing.T) {
	var raw map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(singleResponse{
			Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5, Review: reviewLevelPtr(ReviewStandard),
		})
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL, Review: ReviewDeep})
	if err != nil {
		t.Fatal(err)
	}
	result, err := fw.Classify(context.Background(), "hi", WithReview(ReviewStandard))
	if err != nil {
		t.Fatal(err)
	}
	if raw["review"] != string(ReviewStandard) {
		t.Errorf("payload review = %#v", raw["review"])
	}
	if result.Review != ReviewStandard {
		t.Errorf("result.Review = %q", result.Review)
	}
	if fw.review != ReviewDeep {
		t.Errorf("client default mutated: %q", fw.review)
	}
}

func TestClassifyReviewClientDefaultThenOmittedCall(t *testing.T) {
	var raws []map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]any
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		raws = append(raws, raw)
		ack, _ := raw["review"].(string)
		_ = json.NewEncoder(w).Encode(singleResponse{
			Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5, Review: reviewLevelPtr(ReviewLevel(ack)),
		})
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL, Review: ReviewDeep})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Classify(context.Background(), "first", WithReview(ReviewStandard)); err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Classify(context.Background(), "second"); err != nil {
		t.Fatal(err)
	}
	if len(raws) != 2 {
		t.Fatalf("calls = %d", len(raws))
	}
	if raws[0]["review"] != string(ReviewStandard) {
		t.Errorf("first review = %#v", raws[0]["review"])
	}
	if raws[1]["review"] != string(ReviewDeep) {
		t.Errorf("second review = %#v, want client default deep", raws[1]["review"])
	}
	if fw.review != ReviewDeep {
		t.Errorf("client default mutated: %q", fw.review)
	}
}

func TestClassifyBatchReviewClientDefault(t *testing.T) {
	var raw map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(batchResponse{
			Review: reviewLevelPtr(ReviewStandard),
			Predictions: []singleResponse{
				{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5},
			},
		})
	}))
	defer ts.Close()
	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL, Review: ReviewStandard})
	if err != nil {
		t.Fatal(err)
	}
	results, err := fw.ClassifyBatch(context.Background(), []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	if raw["review"] != string(ReviewStandard) {
		t.Errorf("payload review = %#v", raw["review"])
	}
	if results[0].Review != ReviewStandard {
		t.Errorf("result review = %q", results[0].Review)
	}
}

func TestClassifyReviewAckMismatchAndMissingOneAttempt(t *testing.T) {
	cases := []struct {
		name string
		body string
		got  ReviewLevel
	}{
		{name: "missing", body: `{"prediction":"MALICIOUS","score":0.99,"threshold":0.5}`},
		{name: "null", body: `{"prediction":"MALICIOUS","score":0.99,"threshold":0.5,"review":null}`},
		{name: "mismatch", body: `{"prediction":"MALICIOUS","score":0.99,"threshold":0.5,"review":"standard"}`, got: ReviewStandard},
		{name: "metadata-only", body: `{"prediction":"MALICIOUS","score":0.99,"threshold":0.5,"metadata":{"review":"deep"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			var callback atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.body)
			}))
			defer ts.Close()
			fw, err := New(Options{
				APIKey: "sk",
				APIURL: ts.URL,
				OnClassify: func(ClassifyEvent) {
					callback.Add(1)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			fw.maxRetries = 5
			fw.retryBaseBackoff = time.Millisecond
			fw.retryJitter = noJitter
			_, err = fw.Classify(context.Background(), "attack", WithReview(ReviewDeep), WithMode(ModeBlock))
			var compat *ReviewCompatibilityError
			if !errors.As(err, &compat) {
				t.Fatalf("error = %v, want ReviewCompatibilityError", err)
			}
			if compat.Requested != ReviewDeep || compat.Acknowledged != tc.got {
				t.Errorf("compat = %+v, want requested=deep acknowledged=%q", compat, tc.got)
			}
			var blocked *FirewallBlockedError
			if errors.As(err, &blocked) {
				t.Fatal("ack failure must not surface as a block error")
			}
			if calls.Load() != 1 {
				t.Errorf("HTTP calls = %d, want 1", calls.Load())
			}
			if callback.Load() != 0 {
				t.Errorf("OnClassify calls = %d, want 0", callback.Load())
			}
		})
	}
}

func TestClassifyBatchReviewAckUsesEnvelopeNotPredictions(t *testing.T) {
	var calls atomic.Int32
	var callback atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, `{
			"predictions": [
				{"prediction":"MALICIOUS","score":0.99,"threshold":0.5,"review":"deep"}
			]
		}`)
	}))
	defer ts.Close()
	fw, err := New(Options{
		APIKey: "sk",
		APIURL: ts.URL,
		OnClassify: func(ClassifyEvent) {
			callback.Add(1)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	fw.maxRetries = 4
	_, err = fw.ClassifyBatch(context.Background(), []string{"a"}, WithBatchReview(ReviewDeep))
	var compat *ReviewCompatibilityError
	if !errors.As(err, &compat) {
		t.Fatalf("error = %v, want ReviewCompatibilityError", err)
	}
	if compat.Acknowledged != "" {
		t.Errorf("acknowledged = %q, want empty for missing envelope", compat.Acknowledged)
	}
	var blocked *BatchFirewallBlockedError
	if errors.As(err, &blocked) {
		t.Fatal("ack failure must not surface as a batch block error")
	}
	if calls.Load() != 1 {
		t.Errorf("HTTP calls = %d, want 1", calls.Load())
	}
	if callback.Load() != 0 {
		t.Errorf("OnClassify calls = %d, want 0", callback.Load())
	}
}

func TestClassifyMatchingReviewAckPreservesBlockEnforcement(t *testing.T) {
	reviews := []ReviewLevel{ReviewStandard, ReviewDeep}
	for _, review := range reviews {
		review := review
		t.Run("single/"+string(review), func(t *testing.T) {
			var calls atomic.Int32
			var payload singleRequestPayload
			var events []ClassifyEvent
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
					return
				}
				_ = json.NewEncoder(w).Encode(singleResponse{
					Prediction: PredictionMalicious,
					Score:      0.91,
					Threshold:  0.5,
					Review:     reviewLevelPtr(review),
				})
			}))
			defer ts.Close()

			fw, err := New(Options{
				APIKey: "sk",
				APIURL: ts.URL,
				Mode:   ModeBlock,
				OnClassify: func(event ClassifyEvent) {
					events = append(events, event)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := fw.Classify(context.Background(), "attack",
				WithReview(review),
				WithMode(ModeBlock),
				WithHook(HookUserInput),
			)
			var blocked *FirewallBlockedError
			if !errors.As(err, &blocked) {
				t.Fatalf("error = %v, want FirewallBlockedError", err)
			}
			var compat *ReviewCompatibilityError
			if errors.As(err, &compat) {
				t.Fatal("matching acknowledgement must not return ReviewCompatibilityError")
			}
			if calls.Load() != 1 {
				t.Fatalf("HTTP calls = %d, want 1", calls.Load())
			}
			if payload.Review == nil || *payload.Review != review {
				t.Fatalf("request review = %#v, want %q", payload.Review, review)
			}
			if result.Review != review || result.Prediction != PredictionMalicious || result.Score != 0.91 {
				t.Fatalf("returned result = %+v", result)
			}
			if blocked.Result.Review != review || blocked.Result.Prediction != PredictionMalicious || blocked.Result.Score != 0.91 {
				t.Fatalf("blocked.Result = %+v", blocked.Result)
			}
			if blocked.PromptText != "attack" || blocked.Hook != HookUserInput {
				t.Fatalf("blocked evidence = %+v", blocked)
			}
			if len(events) != 1 {
				t.Fatalf("events = %d, want 1", len(events))
			}
			if !events[0].Blocked || events[0].Mode != ModeBlock || events[0].Result.Review != review {
				t.Fatalf("event = %+v", events[0])
			}
		})

		t.Run("batch/"+string(review), func(t *testing.T) {
			var calls atomic.Int32
			var payload batchRequestPayload
			var events []ClassifyEvent
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
					return
				}
				_ = json.NewEncoder(w).Encode(batchResponse{
					Review: reviewLevelPtr(review),
					Predictions: []singleResponse{
						{Prediction: PredictionBenign, Score: 0.12, Threshold: 0.5},
						{Prediction: PredictionMalicious, Score: 0.88, Threshold: 0.5},
					},
				})
			}))
			defer ts.Close()

			fw, err := New(Options{
				APIKey: "sk",
				APIURL: ts.URL,
				Mode:   ModeBlock,
				OnClassify: func(event ClassifyEvent) {
					events = append(events, event)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			results, err := fw.ClassifyBatch(context.Background(),
				[]string{"safe", "attack"},
				WithBatchReview(review),
				WithBatchMode(ModeBlock),
				WithBatchHooks([]HookLabel{HookUserInput, HookToolResponse}),
			)
			var blocked *BatchFirewallBlockedError
			if !errors.As(err, &blocked) {
				t.Fatalf("error = %v, want BatchFirewallBlockedError", err)
			}
			var compat *ReviewCompatibilityError
			if errors.As(err, &compat) {
				t.Fatal("matching acknowledgement must not return ReviewCompatibilityError")
			}
			if calls.Load() != 1 {
				t.Fatalf("HTTP calls = %d, want 1", calls.Load())
			}
			if payload.Review == nil || *payload.Review != review {
				t.Fatalf("request review = %#v, want %q", payload.Review, review)
			}
			if len(results) != 2 {
				t.Fatalf("results = %d, want 2", len(results))
			}
			if results[0].Review != review || results[0].Prediction != PredictionBenign || results[0].Score != 0.12 {
				t.Fatalf("benign result = %+v", results[0])
			}
			if results[1].Review != review || results[1].Prediction != PredictionMalicious || results[1].Score != 0.88 {
				t.Fatalf("malicious result = %+v", results[1])
			}
			if len(blocked.Blocked) != 1 {
				t.Fatalf("blocked items = %d, want 1 malicious item", len(blocked.Blocked))
			}
			item := blocked.Blocked[0]
			if item.Index != 1 || item.Text != "attack" || item.Hook != HookToolResponse {
				t.Fatalf("blocked item = %+v", item)
			}
			if item.Result.Review != review || item.Result.Prediction != PredictionMalicious || item.Result.Score != 0.88 {
				t.Fatalf("blocked item result = %+v", item.Result)
			}
			if len(events) != 2 {
				t.Fatalf("events = %d, want 2", len(events))
			}
			if events[0].Blocked || events[0].Text != "safe" || events[0].Result.Review != review {
				t.Fatalf("benign event = %+v", events[0])
			}
			if !events[1].Blocked || events[1].Mode != ModeBlock || events[1].Text != "attack" || events[1].Result.Review != review {
				t.Fatalf("malicious event = %+v", events[1])
			}
		})
	}
}

func TestClassifyRetriesPreserveReview(t *testing.T) {
	var calls atomic.Int32
	var reviews []any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]any
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		reviews = append(reviews, raw["review"])
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(singleResponse{
			Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5, Review: reviewLevelPtr(ReviewStandard),
		})
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	fw.retryBaseBackoff = time.Millisecond
	fw.retryJitter = noJitter
	result, err := fw.Classify(context.Background(), "hi", WithReview(ReviewStandard))
	if err != nil {
		t.Fatal(err)
	}
	if result.Review != ReviewStandard {
		t.Errorf("result.Review = %q", result.Review)
	}
	if calls.Load() != 3 {
		t.Errorf("calls = %d, want 3", calls.Load())
	}
	for i, review := range reviews {
		if review != string(ReviewStandard) {
			t.Errorf("attempt %d review = %#v", i, review)
		}
	}
}

func TestClassifyConcurrentMixedReviewIsolation(t *testing.T) {
	const n = 24
	type captured struct {
		text   string
		review any
		ok     bool
	}
	var mu sync.Mutex
	got := make([]captured, 0, n)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Millisecond)
		var raw map[string]any
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Error(err)
			return
		}
		review, ok := raw["review"]
		mu.Lock()
		got = append(got, captured{text: raw["text"].(string), review: review, ok: ok})
		mu.Unlock()
		resp := singleResponse{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5}
		if ok {
			level := ReviewLevel(review.(string))
			resp.Review = &level
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL, Review: ReviewDeep})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				_, err := fw.Classify(context.Background(), "omit")
				errs <- err
			case 1:
				_, err := fw.Classify(context.Background(), "standard", WithReview(ReviewStandard))
				errs <- err
			default:
				_, err := fw.Classify(context.Background(), "deep", WithReview(ReviewDeep))
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if fw.review != ReviewDeep {
		t.Errorf("client default mutated: %q", fw.review)
	}
	if len(got) != n {
		t.Fatalf("captured = %d, want %d", len(got), n)
	}
	counts := map[string]int{}
	for _, item := range got {
		switch item.text {
		case "omit":
			if !item.ok || item.review != string(ReviewDeep) {
				t.Errorf("omit payload review = %#v present=%v, want client deep", item.review, item.ok)
			}
			counts["omit"]++
		case "standard":
			if item.review != string(ReviewStandard) {
				t.Errorf("standard payload review = %#v", item.review)
			}
			counts["standard"]++
		case "deep":
			if item.review != string(ReviewDeep) {
				t.Errorf("deep payload review = %#v", item.review)
			}
			counts["deep"]++
		default:
			t.Errorf("unexpected text %q", item.text)
		}
	}
	if counts["omit"] != 8 || counts["standard"] != 8 || counts["deep"] != 8 {
		t.Errorf("counts = %v", counts)
	}
}

func TestClassifyReviewWrongTypeAck(t *testing.T) {
	wrong := []struct {
		name string
		json string
	}{
		{name: "bool", json: "false"},
		{name: "number", json: "123"},
		{name: "array", json: "[]"},
		{name: "object", json: "{}"},
	}
	for _, tc := range wrong {
		t.Run("single/"+tc.name, func(t *testing.T) {
			assertWrongTypeReviewAck(t, false, tc.json)
		})
		t.Run("batch/"+tc.name, func(t *testing.T) {
			assertWrongTypeReviewAck(t, true, tc.json)
		})
	}
}

func assertWrongTypeReviewAck(t *testing.T, batch bool, reviewJSON string) {
	t.Helper()
	var calls atomic.Int32
	var callback atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if batch {
			_, _ = io.WriteString(w, `{"predictions":[{"prediction":"MALICIOUS","score":0.99,"threshold":0.5}],"review":`+reviewJSON+`}`)
			return
		}
		_, _ = io.WriteString(w, `{"prediction":"MALICIOUS","score":0.99,"threshold":0.5,"review":`+reviewJSON+`}`)
	}))
	defer ts.Close()

	fw, err := New(Options{
		APIKey: "sk",
		APIURL: ts.URL,
		OnClassify: func(ClassifyEvent) {
			callback.Add(1)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	fw.maxRetries = 5
	fw.retryBaseBackoff = time.Millisecond
	fw.retryJitter = noJitter

	var callErr error
	if batch {
		_, callErr = fw.ClassifyBatch(context.Background(), []string{"a"}, WithBatchReview(ReviewDeep))
	} else {
		_, callErr = fw.Classify(context.Background(), "attack", WithReview(ReviewDeep), WithMode(ModeBlock))
	}
	var compat *ReviewCompatibilityError
	if !errors.As(callErr, &compat) {
		t.Fatalf("error = %v, want ReviewCompatibilityError", callErr)
	}
	if compat.Requested != ReviewDeep || compat.Acknowledged != "" {
		t.Errorf("compat = %+v, want requested=deep and empty acknowledgement", compat)
	}
	var blocked *FirewallBlockedError
	var batchBlocked *BatchFirewallBlockedError
	if errors.As(callErr, &blocked) || errors.As(callErr, &batchBlocked) {
		t.Fatal("wrong-type acknowledgement must not surface as a block error")
	}
	if calls.Load() != 1 {
		t.Errorf("HTTP calls = %d, want 1 successful response", calls.Load())
	}
	if callback.Load() != 0 {
		t.Errorf("OnClassify calls = %d, want 0", callback.Load())
	}
}

func TestClassifyOmittedIgnoresUnknownReviewType(t *testing.T) {
	bodies := []string{"false", "123", "[]", "{}"}
	for _, reviewJSON := range bodies {
		reviewJSON := reviewJSON
		t.Run("single/"+reviewJSON, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"prediction":"BENIGN","score":0.1,"threshold":0.5,"review":`+reviewJSON+`}`)
			}))
			defer ts.Close()
			fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
			if err != nil {
				t.Fatal(err)
			}
			result, err := fw.Classify(context.Background(), "hi")
			if err != nil {
				t.Fatalf("omitted review must ignore %s: %v", reviewJSON, err)
			}
			if result.Review != "" {
				t.Errorf("result.Review = %q, want empty", result.Review)
			}
		})
		t.Run("batch/"+reviewJSON, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"predictions":[{"prediction":"BENIGN","score":0.1,"threshold":0.5,"review":`+reviewJSON+`}],"review":`+reviewJSON+`}`)
			}))
			defer ts.Close()
			fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
			if err != nil {
				t.Fatal(err)
			}
			results, err := fw.ClassifyBatch(context.Background(), []string{"a"})
			if err != nil {
				t.Fatalf("omitted review must ignore %s: %v", reviewJSON, err)
			}
			if len(results) != 1 || results[0].Review != "" {
				t.Errorf("results = %+v, want one result with empty review", results)
			}
		})
	}
}

func TestClassifyOmittedIgnoresUnexpectedReviewEcho(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(singleResponse{
			Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5, Review: reviewLevelPtr(ReviewDeep),
		})
	}))
	defer ts.Close()
	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	result, err := fw.Classify(context.Background(), "hi")
	if err != nil {
		t.Fatal(err)
	}
	if result.Review != "" {
		t.Errorf("omitted request must keep result.Review empty, got %q", result.Review)
	}
}
