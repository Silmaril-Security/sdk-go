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
	"testing"
)

const legacyBlockItem = `{"prediction":"MALICIOUS","score":0.9,"threshold":0.5,"primary_outcome":"secret_exposure","outcome_scores":{"secret_exposure":0.75},"model_id":"` + modelRelease + `"}`

type recordedRequest struct {
	target string
	apiKey string
	body   string
}

type classifyBodies struct {
	single string
	batch  string
}

var (
	currentBodies = classifyBodies{
		single: `{"results":[` + blockItem + `]}`,
		batch:  `{"results":[` + allowItem + `,` + blockItem + `]}`,
	}
	legacyBodies = classifyBodies{
		single: legacyBlockItem,
		batch:  `{"predictions":[{"prediction":"BENIGN","score":0.1,"threshold":0.5},` + legacyBlockItem + `]}`,
	}
)

// versionedRuntime answers /alpha/v2/classify with currentStatus and the given
// bodies, and /alpha/classify with legacyStatus and version 1 bodies, recording
// every request in arrival order.
type versionedRuntime struct {
	*httptest.Server

	mu       sync.Mutex
	requests []recordedRequest
}

func newVersionedRuntime(t *testing.T, currentStatus int, current classifyBodies, legacyStatus int) *versionedRuntime {
	t.Helper()
	runtime := &versionedRuntime{}
	respond := func(status int, bodies classifyBodies) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			runtime.mu.Lock()
			runtime.requests = append(runtime.requests, recordedRequest{
				target: r.URL.RequestURI(),
				apiKey: r.Header.Get("x-api-key"),
				body:   string(body),
			})
			runtime.mu.Unlock()
			w.WriteHeader(status)
			if status != http.StatusOK {
				return
			}
			var payload struct {
				Texts []string `json:"texts"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Error(err)
			}
			if payload.Texts != nil {
				_, _ = io.WriteString(w, bodies.batch)
				return
			}
			_, _ = io.WriteString(w, bodies.single)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/alpha"+classifyPath, respond(currentStatus, current))
	mux.HandleFunc("/alpha"+legacyPath, respond(legacyStatus, legacyBodies))
	runtime.Server = httptest.NewServer(mux)
	t.Cleanup(runtime.Close)
	return runtime
}

func (r *versionedRuntime) recorded() []recordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedRequest(nil), r.requests...)
}

func (r *versionedRuntime) targets() []string {
	requests := r.recorded()
	targets := make([]string, len(requests))
	for i, request := range requests {
		targets[i] = request.target
	}
	return targets
}

func (r *versionedRuntime) firewall(t *testing.T) *Firewall {
	t.Helper()
	fw, err := New(Options{APIKey: "sk-test", APIURL: r.URL + "/alpha/classify?stage=canary", Mode: ModeShadow})
	if err != nil {
		t.Fatal(err)
	}
	fw.maxRetries = 0
	return fw
}

const (
	currentTarget = "/alpha/v2/classify?stage=canary"
	legacyTarget  = "/alpha/classify?stage=canary"
)

var classifyShapes = map[string]func(*Firewall) ([]BlockResult, error){
	"single": func(fw *Firewall) ([]BlockResult, error) {
		result, err := fw.Classify(context.Background(), "attack")
		return []BlockResult{result}, err
	},
	"batch": func(fw *Firewall) ([]BlockResult, error) {
		return fw.ClassifyBatch(context.Background(), []string{"safe", "attack"})
	},
}

func TestClassifyEndpoints(t *testing.T) {
	for _, tc := range []struct {
		apiURL, current, legacy string
	}{
		{"https://firewall.test", "https://firewall.test/v2/classify", "https://firewall.test/classify"},
		{"https://firewall.test/", "https://firewall.test/v2/classify", "https://firewall.test/classify"},
		{"https://firewall.test/classify", "https://firewall.test/v2/classify", "https://firewall.test/classify"},
		{"https://firewall.test/classify/", "https://firewall.test/v2/classify", "https://firewall.test/classify"},
		{"https://firewall.test/v2/classify", "https://firewall.test/v2/classify", "https://firewall.test/classify"},
		{"https://firewall.test/v2/classify/", "https://firewall.test/v2/classify", "https://firewall.test/classify"},
		{"https://firewall.test/alpha", "https://firewall.test/alpha/v2/classify", "https://firewall.test/alpha/classify"},
		{"https://firewall.test/alpha/classify", "https://firewall.test/alpha/v2/classify", "https://firewall.test/alpha/classify"},
		{"https://firewall.test/alpha/v2/classify", "https://firewall.test/alpha/v2/classify", "https://firewall.test/alpha/classify"},
		{"https://firewall.test/v2", "https://firewall.test/v2/v2/classify", "https://firewall.test/v2/classify"},
		{"https://firewall.test/reclassify", "https://firewall.test/reclassify/v2/classify", "https://firewall.test/reclassify/classify"},
		{"https://firewall.test/team%2Falpha/classify", "https://firewall.test/team%2Falpha/v2/classify", "https://firewall.test/team%2Falpha/classify"},
		{"https://classify", "https://classify/v2/classify", "https://classify/classify"},
		{"https://firewall.test?stage=canary", "https://firewall.test/v2/classify?stage=canary", "https://firewall.test/classify?stage=canary"},
		{"https://firewall.test/classify?stage=canary&path=/classify", "https://firewall.test/v2/classify?stage=canary&path=/classify", "https://firewall.test/classify?stage=canary&path=/classify"},
		{"https://firewall.test/alpha/v2/classify/?stage=canary", "https://firewall.test/alpha/v2/classify?stage=canary", "https://firewall.test/alpha/classify?stage=canary"},
	} {
		t.Run(tc.apiURL, func(t *testing.T) {
			fw, err := New(Options{APIKey: "sk", APIURL: tc.apiURL})
			if err != nil {
				t.Fatal(err)
			}
			if fw.classifyURL != tc.current || fw.legacyURL != tc.legacy {
				t.Fatalf("endpoints = %q, %q; want %q, %q", fw.classifyURL, fw.legacyURL, tc.current, tc.legacy)
			}
		})
	}
}

func TestNewRejectsUnparsableAPIURL(t *testing.T) {
	if _, err := New(Options{APIKey: "sk", APIURL: "https://firewall.test/%zz/classify"}); err == nil {
		t.Fatal("expected error for an unparsable APIURL")
	}
}

func TestClassifyUsesVersion2WithoutFallback(t *testing.T) {
	for shape, classify := range classifyShapes {
		t.Run(shape, func(t *testing.T) {
			runtime := newVersionedRuntime(t, http.StatusOK, currentBodies, http.StatusOK)
			fw := runtime.firewall(t)
			for call := 0; call < 2; call++ {
				if _, err := classify(fw); err != nil {
					t.Fatal(err)
				}
			}
			if got, want := runtime.targets(), []string{currentTarget, currentTarget}; !reflect.DeepEqual(got, want) {
				t.Fatalf("requests = %q, want %q", got, want)
			}
		})
	}
}

func TestClassifyFallsBackAndRemembers(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed} {
		for shape, classify := range classifyShapes {
			t.Run(fmt.Sprintf("%d/%s", status, shape), func(t *testing.T) {
				runtime := newVersionedRuntime(t, status, currentBodies, http.StatusOK)
				fw := runtime.firewall(t)
				for call := 0; call < 2; call++ {
					results, err := classify(fw)
					if err != nil {
						t.Fatal(err)
					}
					want := BlockResult{
						Action:  ActionBlock,
						Source:  SourceModel,
						Outcome: HarmfulOutcomeSecretExposure,
						ModelID: modelRelease,
						Mode:    ModeShadow,
					}
					if got := results[len(results)-1]; got != want {
						t.Fatalf("adapted result = %+v, want %+v", got, want)
					}
					if len(results) == 2 && results[0] != (BlockResult{Action: ActionAllow, Mode: ModeShadow}) {
						t.Fatalf("adapted allow = %+v", results[0])
					}
				}
				if got, want := runtime.targets(), []string{currentTarget, legacyTarget, legacyTarget}; !reflect.DeepEqual(got, want) {
					t.Fatalf("requests = %q, want %q", got, want)
				}
				requests := runtime.recorded()
				first, fallback := requests[0], requests[1]
				if first.body != fallback.body || first.apiKey != "sk-test" || fallback.apiKey != "sk-test" {
					t.Fatalf("fallback request differs: %+v then %+v", first, fallback)
				}
			})
		}
	}
}

func TestClassifyDoesNotFallBackOnOtherStatuses(t *testing.T) {
	for _, status := range []int{
		http.StatusFound,
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusRequestTimeout,
		http.StatusConflict,
		http.StatusUnprocessableEntity,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
	} {
		for shape, classify := range classifyShapes {
			t.Run(fmt.Sprintf("%d/%s", status, shape), func(t *testing.T) {
				runtime := newVersionedRuntime(t, status, currentBodies, http.StatusOK)
				_, err := classify(runtime.firewall(t))
				var apiErr *APIError
				if !errors.As(err, &apiErr) || apiErr.Status != status {
					t.Fatalf("error = %v, want APIError %d", err, status)
				}
				if got, want := runtime.targets(), []string{currentTarget}; !reflect.DeepEqual(got, want) {
					t.Fatalf("requests = %q, want %q", got, want)
				}
			})
		}
	}
}

func TestClassifyFallbackErrorIsTheResultAndIsNotRemembered(t *testing.T) {
	for shape, classify := range classifyShapes {
		t.Run(shape, func(t *testing.T) {
			runtime := newVersionedRuntime(t, http.StatusNotFound, currentBodies, http.StatusUnauthorized)
			fw := runtime.firewall(t)
			for call := 0; call < 2; call++ {
				_, err := classify(fw)
				var apiErr *APIError
				if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
					t.Fatalf("error = %v, want the /classify APIError 401", err)
				}
			}
			want := []string{currentTarget, legacyTarget, currentTarget, legacyTarget}
			if got := runtime.targets(); !reflect.DeepEqual(got, want) {
				t.Fatalf("requests = %q, want %q", got, want)
			}
		})
	}
}

func TestClassifyRetriesBeforeFallingBack(t *testing.T) {
	var mu sync.Mutex
	var targets []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		targets = append(targets, r.URL.Path)
		switch len(targets) {
		case 1:
			w.WriteHeader(http.StatusServiceUnavailable)
		case 2:
			w.WriteHeader(http.StatusNotFound)
		case 3:
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			_, _ = io.WriteString(w, legacyBlockItem)
		}
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL, Mode: ModeShadow})
	if err != nil {
		t.Fatal(err)
	}
	fw.retryBaseBackoff = 0
	result, err := fw.Classify(context.Background(), "attack")
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != ActionBlock {
		t.Fatalf("result = %+v", result)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{classifyPath, classifyPath, legacyPath, legacyPath}; !reflect.DeepEqual(targets, want) {
		t.Fatalf("requests = %q, want %q", targets, want)
	}
}

func TestClassifyConcurrentFallbackIsRemembered(t *testing.T) {
	runtime := newVersionedRuntime(t, http.StatusNotFound, currentBodies, http.StatusOK)
	fw := runtime.firewall(t)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < cap(errs); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := fw.Classify(context.Background(), "attack")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fw.Classify(context.Background(), "attack"); err != nil {
		t.Fatal(err)
	}
	targets := runtime.targets()
	if last := targets[len(targets)-1]; last != legacyTarget || !fw.legacyOnly.Load() {
		t.Fatalf("last request = %q, remembered = %t", last, fw.legacyOnly.Load())
	}
}

func TestClassifyRejectsInvalidLegacyVerdictsWithoutRemembering(t *testing.T) {
	for _, body := range []string{
		`{}`,
		`{"prediction":"SUSPICIOUS","score":0.9,"threshold":0.5}`,
		`{"prediction":"SUSPICIOUS","model_prediction":"MALICIOUS","score":0.9,"threshold":0.5}`,
		`{"predictions":[{"prediction":"MALICIOUS","score":0.9,"threshold":0.5}]}`,
	} {
		t.Run(body, func(t *testing.T) {
			ts := newLegacyServer(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, body)
			})
			callbacks := 0
			fw, err := New(Options{APIKey: "sk", APIURL: ts.URL, OnClassify: func(ClassifyEvent) { callbacks++ }})
			if err != nil {
				t.Fatal(err)
			}
			result, err := fw.Classify(context.Background(), "attack")
			if err == nil || !strings.Contains(err.Error(), "invalid prediction") {
				t.Fatalf("error = %v, want invalid prediction", err)
			}
			if result != (BlockResult{}) || callbacks != 0 || fw.legacyOnly.Load() {
				t.Fatalf("result = %+v, callbacks = %d, remembered = %t", result, callbacks, fw.legacyOnly.Load())
			}
		})
	}
}

func TestClassifyRejectedFallbackResultsAreNotRemembered(t *testing.T) {
	for _, tc := range []struct {
		name, legacyBody, wantErr string
		classify                  func(*Firewall) ([]BlockResult, error)
	}{
		{
			name:       "governance without policy version",
			legacyBody: `{"prediction":"BENIGN","governance":{"action":"allow","policy_version":""}}`,
			wantErr:    "policy_version must be non-empty",
			classify:   classifyShapes["single"],
		},
		{
			name:       "results that do not match the inputs",
			legacyBody: `{"predictions":[{"prediction":"BENIGN"}]}`,
			wantErr:    "results length 1 does not match texts length 2",
			classify:   classifyShapes["batch"],
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var targets []string
			record := func(r *http.Request) int {
				mu.Lock()
				defer mu.Unlock()
				targets = append(targets, r.URL.Path)
				return len(targets)
			}
			mux := http.NewServeMux()
			mux.HandleFunc(classifyPath, func(w http.ResponseWriter, r *http.Request) {
				if record(r) == 1 {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_, _ = io.WriteString(w, `{"results":[`+allowItem+`,`+allowItem+`]}`)
			})
			mux.HandleFunc(legacyPath, func(w http.ResponseWriter, r *http.Request) {
				record(r)
				_, _ = io.WriteString(w, tc.legacyBody)
			})
			ts := httptest.NewServer(mux)
			defer ts.Close()
			fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tc.classify(fw); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
			if fw.legacyOnly.Load() {
				t.Fatal("a rejected fallback response was remembered")
			}
			if _, err := fw.ClassifyBatch(context.Background(), []string{"safe", "safe"}); err != nil {
				t.Fatal(err)
			}
			if want := []string{classifyPath, legacyPath, classifyPath}; !reflect.DeepEqual(targets, want) {
				t.Fatalf("requests = %q, want %q", targets, want)
			}
		})
	}
}

func TestClassifyAdaptedResultNeverAllowsWhatVersion1Blocked(t *testing.T) {
	for name, fields := range map[string]string{
		"benign model label without governance":    `"model_prediction":"BENIGN"`,
		"benign model label with governance allow": `"model_prediction":"BENIGN","governance":{"action":"allow","policy_version":"policy-9"}`,
		"unfamiliar model label":                   `"model_prediction":"UNKNOWN"`,
	} {
		for _, batch := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/batch=%t", name, batch), func(t *testing.T) {
				body := `{"prediction":"MALICIOUS","score":0.9,"threshold":0.5,"primary_outcome":"secret_exposure","outcome_scores":{"secret_exposure":0.75},` + fields + `}`
				if batch {
					body = `{"predictions":[` + body + `]}`
				}
				ts := newLegacyServer(t, func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.WriteString(w, body)
				})
				fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
				if err != nil {
					t.Fatal(err)
				}
				var result BlockResult
				if batch {
					results, err := fw.ClassifyBatch(context.Background(), []string{"attack"})
					var blockedErr *BatchFirewallBlockedError
					if !errors.As(err, &blockedErr) {
						t.Fatalf("error = %v, want BatchFirewallBlockedError", err)
					}
					result = results[0]
				} else {
					var blockedErr *FirewallBlockedError
					result, err = fw.Classify(context.Background(), "attack")
					if !errors.As(err, &blockedErr) {
						t.Fatalf("error = %v, want FirewallBlockedError", err)
					}
				}
				if result.Action != ActionBlock || result.Source != SourceGovernance || result.Outcome != "" {
					t.Fatalf("adapted result = %+v, want a governance-sourced block without an outcome", result)
				}
			})
		}
	}
}

func TestClassifyAdaptsVersion1BodyAnsweredByVersion2Route(t *testing.T) {
	for shape, classify := range classifyShapes {
		t.Run(shape, func(t *testing.T) {
			want, err := classify(newVersionedRuntime(t, http.StatusNotFound, currentBodies, http.StatusOK).firewall(t))
			if err != nil {
				t.Fatal(err)
			}
			routed := newVersionedRuntime(t, http.StatusOK, legacyBodies, http.StatusOK)
			fw := routed.firewall(t)
			for call := 0; call < 2; call++ {
				got, err := classify(fw)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("results = %+v, want the fallback results %+v", got, want)
				}
			}
			if got, want := routed.targets(), []string{currentTarget, currentTarget}; !reflect.DeepEqual(got, want) || fw.legacyOnly.Load() {
				t.Fatalf("requests = %q, want %q; remembered = %t", got, want, fw.legacyOnly.Load())
			}

			enforcing, err := New(Options{APIKey: "sk-test", APIURL: routed.URL + "/alpha"})
			if err != nil {
				t.Fatal(err)
			}
			results, err := classify(enforcing)
			var single *FirewallBlockedError
			var batch *BatchFirewallBlockedError
			var blocked BlockResult
			switch {
			case errors.As(err, &single):
				blocked = single.Result
			case errors.As(err, &batch) && len(batch.Blocked) == 1 && batch.Blocked[0].Index == 1:
				blocked = batch.Blocked[0].Result
			default:
				t.Fatalf("error = %v, want a blocking error for the adapted block", err)
			}
			if blocked.Action != ActionBlock || blocked.Source != SourceModel || results[len(results)-1] != blocked {
				t.Fatalf("blocked result = %+v, results = %+v", blocked, results)
			}
		})
	}
}

func TestClassifyRejectsBodyWithNeitherShape(t *testing.T) {
	for body, want := range map[string]map[string]string{
		`{}`:                    {"single": "invalid prediction", "batch": "results length 0 does not match texts length 2"},
		`{"detail":"accepted"}`: {"single": "invalid prediction", "batch": "results length 0 does not match texts length 2"},
		`[]`:                    {"single": "decode response", "batch": "decode response"},
	} {
		for shape, classify := range classifyShapes {
			t.Run(body+"/"+shape, func(t *testing.T) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.WriteString(w, body)
				}))
				defer ts.Close()
				callbacks := 0
				fw, err := New(Options{APIKey: "sk", APIURL: ts.URL, OnClassify: func(ClassifyEvent) { callbacks++ }})
				if err != nil {
					t.Fatal(err)
				}
				results, err := classify(fw)
				if err == nil || !strings.Contains(err.Error(), want[shape]) {
					t.Fatalf("error = %v, want %q", err, want[shape])
				}
				for _, result := range results {
					if result != (BlockResult{}) {
						t.Fatalf("results = %+v, want none", results)
					}
				}
				if callbacks != 0 || fw.legacyOnly.Load() {
					t.Fatalf("callbacks = %d, remembered = %t", callbacks, fw.legacyOnly.Load())
				}
			})
		}
	}
}
