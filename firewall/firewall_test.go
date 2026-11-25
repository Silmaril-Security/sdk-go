// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	inputIndex *int,
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
	if inputIndex == nil {
		if _, ok := raw["input_index"]; ok {
			t.Error("input_index must be omitted for single events")
		}
	} else if value, ok := raw["input_index"]; !ok {
		t.Errorf("input_index missing, want %d", *inputIndex)
	} else if number, ok := value.(float64); !ok {
		t.Errorf("input_index = %#v, want numeric %d", value, *inputIndex)
	} else if got := int(number); got != *inputIndex {
		t.Errorf("input_index = %d, want %d", got, *inputIndex)
	}
	if _, ok := raw["chunk_index"]; ok {
		t.Error("chunk_index must be omitted")
	}
	if _, ok := raw["chunk_count"]; ok {
		t.Error("chunk_count must be omitted")
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
		if r.URL.Path != classifyPath {
			t.Errorf("path = %q, want %q", r.URL.Path, classifyPath)
		}
		writeResults(w, wireDecision{
			Action:     "block",
			Source:     ptr(SourceModel),
			Confidence: ptr("high"),
			Severity:   ptr("moderate"),
			Outcome:    ptr("control_abuse"),
			ModelID:    ptr(modelRelease),
		})
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
	want := BlockResult{
		Action:     ActionBlock,
		Source:     SourceModel,
		Confidence: ConfidenceHigh,
		Severity:   SeverityModerate,
		Outcome:    HarmfulOutcomeControlAbuse,
		ModelID:    modelRelease,
		Mode:       ModeShadow,
	}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("result = %+v, want %+v", res, want)
	}
	if gotPayload.Text != "hello" || gotPayload.Hook != HookUserInput || gotPayload.ToolName != "cal" {
		t.Errorf("payload = %+v", gotPayload)
	}
	requireSilmarilMetadata(t, gotPayload.Metadata, "req-single", nil)
}

func TestClassifySanitizesInvalidUTF8Payload(t *testing.T) {
	var gotPayload singleRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotPayload)
		writeResults(w, allowDecision)
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

func TestClassifyNoOptionsOmitsHookAndToolName(t *testing.T) {
	var raw map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&raw)
		writeResults(w, allowDecision)
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
	if _, ok := raw["review"]; ok {
		t.Errorf("review should be omitted: %v", raw)
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
		writeResults(w, allowDecision)
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
	requireSilmarilMetadata(t, gotPayload.Metadata, "req-meta", nil)
	if !reflect.DeepEqual((*gotPayload.Metadata)["langgraph"], metadata["langgraph"]) {
		t.Fatalf("langgraph metadata = %#v, want %#v", (*gotPayload.Metadata)["langgraph"], metadata["langgraph"])
	}
}

func TestClassifyBatchHappyPath(t *testing.T) {
	var gotPayload batchRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotPayload)
		if r.URL.Path != classifyPath {
			t.Errorf("path = %q, want %q", r.URL.Path, classifyPath)
		}
		writeResults(w, allowDecision, wireDecision{
			Action:     "block",
			Source:     ptr(SourceModel),
			Confidence: ptr("very_high"),
			Severity:   ptr("critical"),
			Outcome:    ptr("system_compromise"),
			ModelID:    ptr(modelRelease),
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
	want := []BlockResult{
		{Action: ActionAllow, Mode: ModeShadow},
		{
			Action:     ActionBlock,
			Source:     SourceModel,
			Confidence: ConfidenceVeryHigh,
			Severity:   SeverityCritical,
			Outcome:    HarmfulOutcomeSystemCompromise,
			ModelID:    modelRelease,
			Mode:       ModeShadow,
		},
	}
	if !reflect.DeepEqual(results, want) {
		t.Errorf("results = %+v, want %+v", results, want)
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
	index0, index1 := 0, 1
	requireSilmarilMetadata(t, gotPayload.Metadata[0], "req-batch", &index0)
	requireSilmarilMetadata(t, gotPayload.Metadata[1], "req-batch", &index1)
}

func TestClassifyBatchSerializesMetadata(t *testing.T) {
	var gotPayload batchRequestPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatal(err)
		}
		writeResults(w, allowDecision, allowDecision)
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
	index0, index1 := 0, 1
	requireSilmarilMetadata(t, gotPayload.Metadata[0], "req-batch-meta", &index0)
	if !reflect.DeepEqual((*gotPayload.Metadata[0])["langgraph"], metadata[0]["langgraph"]) {
		t.Fatalf("metadata[0] langgraph = %#v, want %#v", (*gotPayload.Metadata[0])["langgraph"], metadata[0]["langgraph"])
	}
	requireSilmarilMetadata(t, gotPayload.Metadata[1], "req-batch-meta", &index1)
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
		results := make([]wireDecision, len(payload.Texts))
		for i := range results {
			results[i] = allowDecision
		}
		writeResults(w, results...)
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
		writeResults(w, allowDecision, allowDecision)
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

func TestClassifyEnforcesOnlyOnAction(t *testing.T) {
	for _, tc := range []struct {
		name    string
		item    wireDecision
		want    BlockResult
		blocked bool
	}{
		{name: "allow", item: allowDecision, want: BlockResult{Action: ActionAllow}},
		{name: "block", item: blockDecision, want: BlockResult{Action: ActionBlock, Source: SourceModel}, blocked: true},
		{
			name:    "unfamiliar action",
			item:    wireDecision{Action: "quarantine"},
			want:    BlockResult{Action: ActionBlock},
			blocked: true,
		},
		{
			name:    "allow in another case",
			item:    wireDecision{Action: "ALLOW"},
			want:    BlockResult{Action: ActionBlock},
			blocked: true,
		},
		{
			name: "allow with unfamiliar evidence",
			item: wireDecision{
				Action:     "allow",
				Source:     ptr("future_source"),
				Confidence: ptr("certain"),
				Severity:   ptr("catastrophic"),
				Outcome:    ptr("data_exfiltration"),
				ModelID:    ptr("future-model-release"),
			},
			want: BlockResult{
				Action:     ActionAllow,
				Source:     "future_source",
				Confidence: "certain",
				Severity:   "catastrophic",
				Outcome:    "data_exfiltration",
				ModelID:    "future-model-release",
			},
		},
	} {
		for _, batch := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/batch=%t", tc.name, batch), func(t *testing.T) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					writeResults(w, tc.item)
				}))
				defer ts.Close()

				var events []ClassifyEvent
				fw, err := New(Options{
					APIKey:     "sk",
					APIURL:     ts.URL,
					OnClassify: func(event ClassifyEvent) { events = append(events, event) },
				})
				if err != nil {
					t.Fatal(err)
				}
				var result BlockResult
				var enforced bool
				if batch {
					results, err := fw.ClassifyBatch(context.Background(), []string{"input"})
					var blockedErr *BatchFirewallBlockedError
					enforced = errors.As(err, &blockedErr)
					if err != nil && !enforced {
						t.Fatal(err)
					}
					result = results[0]
				} else {
					var blockedErr *FirewallBlockedError
					result, err = fw.Classify(context.Background(), "input")
					enforced = errors.As(err, &blockedErr)
					if err != nil && !enforced {
						t.Fatal(err)
					}
				}
				if enforced != tc.blocked || len(events) != 1 || events[0].Blocked != tc.blocked {
					t.Fatalf("enforced = %t, events = %+v, want blocked = %t", enforced, events, tc.blocked)
				}
				if !reflect.DeepEqual(result, tc.want) {
					t.Fatalf("result = %+v, want %+v", result, tc.want)
				}
			})
		}
	}
}

func TestClassifyRejectsMalformedDecisions(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{name: "null results", body: `{"results":null}`, want: "results length 0 does not match texts length 1"},
		{name: "results is not an array", body: `{"results":{"action":"allow"}}`, want: "decode response"},
		{name: "too many results", body: `{"results":[{"action":"allow"},{"action":"allow"}]}`, want: "results length 2 does not match texts length 1"},
		{name: "missing action", body: `{"results":[{"source":null}]}`, want: "response action must be a non-empty string"},
		{name: "null action", body: `{"results":[{"action":null}]}`, want: "response action must be a non-empty string"},
		{name: "empty action", body: `{"results":[{"action":""}]}`, want: "response action must be a non-empty string"},
		{name: "non-string action", body: `{"results":[{"action":1}]}`, want: "decode response"},
		{name: "non-string model_id", body: `{"results":[{"action":"allow","model_id":16}]}`, want: "decode response"},
	} {
		for _, batch := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/batch=%t", tc.name, batch), func(t *testing.T) {
				callbacks := 0
				fw, err := New(Options{
					APIKey: "sk",
					APIURL: "https://firewall.test",
					HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
					})},
					OnClassify: func(ClassifyEvent) { callbacks++ },
				})
				if err != nil {
					t.Fatal(err)
				}
				if batch {
					var results []BlockResult
					results, err = fw.ClassifyBatch(context.Background(), []string{"input"})
					if results != nil {
						t.Fatalf("results = %#v, want nil", results)
					}
				} else {
					var result BlockResult
					result, err = fw.Classify(context.Background(), "input")
					if !reflect.DeepEqual(result, BlockResult{}) {
						t.Fatalf("result = %#v, want zero value", result)
					}
				}
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("error = %v, want %q", err, tc.want)
				}
				if callbacks != 0 {
					t.Errorf("OnClassify ran %d times for a malformed response", callbacks)
				}
			})
		}
	}
}

func TestClassifyIgnoresUnknownFields(t *testing.T) {
	body := `{"results":[{"action":"allow","source":null,"confidence":null,"severity":null,"outcome":null,"governance":null,"model_id":null,"mode":"shadow","score":0.9,"trace":{"id":"t-1"}}],"request_trace":"t-1"}`
	fw, err := New(Options{
		APIKey: "sk",
		APIURL: "https://firewall.test",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := fw.Classify(context.Background(), "input")
	if err != nil {
		t.Fatal(err)
	}
	if want := (BlockResult{Action: ActionAllow}); !reflect.DeepEqual(result, want) {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
}

func TestClassifyRetriesOn429(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		writeResults(w, allowDecision)
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	fw.retryBaseBackoff = time.Millisecond
	fw.retryJitter = noJitter
	res, err := fw.Classify(context.Background(), "hi")
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != ActionAllow {
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
				Body:       io.NopCloser(strings.NewReader(allowBody)),
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
		writeResults(w, allowDecision)
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
		writeResults(w, allowDecision)
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
				Body:       io.NopCloser(strings.NewReader(allowBody)),
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
		writeResults(w, allowDecision)
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

func TestClassifySendsLongInputOnce(t *testing.T) {
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
		if callNumber == 2 {
			writeResults(w, blockDecision)
			return
		}
		writeResults(w, allowDecision)
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL, ShadowMode: true})
	long := strings.Repeat("a", 4001)
	res, err := fw.Classify(context.Background(), long, WithHook(HookUserInput))
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != ActionAllow {
		t.Errorf("result = %+v", res)
	}
	if len(received) != 1 {
		t.Errorf("expected one complete event request, got %d", len(received))
	}
	for _, payload := range received {
		if payload.Hook != HookUserInput {
			t.Errorf("hook = %q, want %q", payload.Hook, HookUserInput)
		}
		if payload.Text == "" {
			t.Error("chunk text is empty")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("HTTP calls = %d, want 1", got)
	}
}

func TestClassifyLongInputPreservesToolAndMetadata(t *testing.T) {
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
		writeResults(w, allowDecision)
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL})
	long := strings.Repeat("b", 4001)
	_, err := fw.Classify(
		context.Background(),
		long,
		WithHook(HookToolResponse),
		WithToolName("fetch_webpage"),
		WithMetadata(ClassificationMetadata{"conversationId": "conversation-123", "conversation_id": "inert"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(received) != 1 {
		t.Fatalf("expected one complete event request, got %d", len(received))
	}
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
		if got := (*payload.Metadata)["conversationId"]; got != "conversation-123" {
			t.Errorf("metadata[%d] conversationId = %v", i, got)
		}
		silmaril := (*payload.Metadata)["silmaril"].(map[string]any)
		requireSilmarilMetadata(t, payload.Metadata, silmaril["request_id"].(string), nil)
	}
}

func TestClassifyLongInputPropagatesChunkError(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "boom", http.StatusBadRequest)
			return
		}
		writeResults(w, allowDecision)
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL, ShadowMode: true})
	long := strings.Repeat("a", 4001)
	_, err := fw.Classify(context.Background(), long)
	if err == nil {
		t.Fatal("expected request error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is not APIError: %T %v", err, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("HTTP calls = %d, want 1", calls.Load())
	}
}

func TestClassifyLongInputUsesOneHTTPCall(t *testing.T) {
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
		writeResults(w, allowDecision)
	}))
	defer ts.Close()

	fw, _ := New(Options{APIKey: "sk", APIURL: ts.URL, ShadowMode: true})
	long := strings.Repeat("a", 8000)
	if _, err := fw.Classify(context.Background(), long); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("HTTP calls = %d, want 1", calls.Load())
	}
	if maxActive.Load() != 1 {
		t.Fatalf("max active requests = %d, want 1", maxActive.Load())
	}
}
