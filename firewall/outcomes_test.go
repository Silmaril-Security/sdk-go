// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func primaryOutcomePtr(value string) *string {
	return &value
}

func TestOutcomeTaxonomyExportsOrderedValues(t *testing.T) {
	wantPrimary := []PrimaryOutcome{
		OutcomeBenign,
		OutcomeInformationDisclosure,
		OutcomeSecretExposure,
		OutcomeControlAbuse,
		OutcomeSystemCompromise,
		OutcomeServiceDisruption,
		OutcomeCodeGeneration,
		OutcomeStoryScriptGeneration,
		OutcomeGameGeneration,
		OutcomeWebsiteGeneration,
		OutcomeClickUpTermsViolation,
		OutcomeTraditionalAIAbuse,
	}
	primaryOutcomes := PrimaryOutcomes()
	descriptions := OutcomeDescriptions()
	if len(primaryOutcomes) != len(wantPrimary) {
		t.Fatalf("PrimaryOutcomes length = %d, want %d", len(primaryOutcomes), len(wantPrimary))
	}
	for i, want := range wantPrimary {
		if primaryOutcomes[i] != want {
			t.Fatalf("PrimaryOutcomes[%d] = %q, want %q", i, primaryOutcomes[i], want)
		}
		if descriptions[want] == "" {
			t.Fatalf("missing description for %q", want)
		}
		if !IsPrimaryOutcome(want) {
			t.Fatalf("%q should be a primary outcome", want)
		}
	}
	if IsHarmfulOutcome(HarmfulOutcome(OutcomeBenign)) {
		t.Fatal("benign should not be a harmful outcome")
	}
	if !IsHarmfulOutcome(HarmfulOutcomeSecretExposure) {
		t.Fatal("secret exposure should be a harmful outcome")
	}
}

func TestOutcomeTaxonomyAccessorsReturnCopies(t *testing.T) {
	primary := PrimaryOutcomes()
	primary[0] = "mutated"
	if PrimaryOutcomes()[0] != OutcomeBenign {
		t.Fatal("PrimaryOutcomes should return a copy")
	}

	harmful := HarmfulOutcomes()
	harmful[0] = "mutated"
	if HarmfulOutcomes()[0] != HarmfulOutcomeInformationDisclosure {
		t.Fatal("HarmfulOutcomes should return a copy")
	}

	descriptions := OutcomeDescriptions()
	descriptions[OutcomeBenign] = "mutated"
	if OutcomeDescriptions()[OutcomeBenign] == "mutated" {
		t.Fatal("OutcomeDescriptions should return a copy")
	}
}

func TestBlockResultFromResponseDecodesTypedOutcomes(t *testing.T) {
	for _, outcome := range PrimaryOutcomes() {
		resp := singleResponse{
			Prediction:     PredictionBenign,
			Score:          0.1,
			Threshold:      0.5,
			PrimaryOutcome: primaryOutcomePtr(string(outcome)),
		}
		result, err := blockResultFromResponse(resp, ModeBlock)
		if err != nil {
			t.Fatalf("outcome %q decode failed: %v", outcome, err)
		}
		if result.PrimaryOutcome != outcome {
			t.Fatalf("PrimaryOutcome = %q, want %q", result.PrimaryOutcome, outcome)
		}
	}
}

func TestBlockResultFromResponseValidatesOutcomeFields(t *testing.T) {
	cases := []struct {
		name string
		resp singleResponse
		want string
	}{
		{
			name: "empty primary",
			resp: singleResponse{Prediction: PredictionMalicious, Score: 0.9, Threshold: 0.5, PrimaryOutcome: primaryOutcomePtr("")},
			want: "invalid primary_outcome",
		},
		{
			name: "benign outcome scores",
			resp: singleResponse{Prediction: PredictionMalicious, Score: 0.9, Threshold: 0.5, OutcomeScores: map[string]float64{string(OutcomeBenign): 0.8}},
			want: "invalid outcome_scores key",
		},
		{
			name: "benign detector scores",
			resp: singleResponse{Prediction: PredictionMalicious, Score: 0.9, Threshold: 0.5, DetectorScores: map[string]float64{string(OutcomeBenign): 0.8}},
			want: "invalid detector_scores key",
		},
		{
			name: "negative outcome score",
			resp: singleResponse{Prediction: PredictionMalicious, Score: 0.9, Threshold: 0.5, OutcomeScores: map[string]float64{"future_outcome": -0.1}},
			want: "outcome_scores value",
		},
		{
			name: "detector score above one",
			resp: singleResponse{Prediction: PredictionMalicious, Score: 0.9, Threshold: 0.5, DetectorScores: map[string]float64{"future_detector": 1.1}},
			want: "detector_scores value",
		},
		{
			name: "benign detector counts",
			resp: singleResponse{Prediction: PredictionMalicious, Score: 0.9, Threshold: 0.5, DetectorCounts: map[string]int{string(OutcomeBenign): 1}},
			want: "invalid detector_counts key",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := blockResultFromResponse(tc.resp, ModeBlock)
			if err == nil {
				t.Fatal("expected error")
			}
			if got := err.Error(); !strings.Contains(got, tc.want) {
				t.Fatalf("error = %q, want substring %q", got, tc.want)
			}
		})
	}
}

func TestBlockResultFromResponseDecodesFutureOutcomeLabels(t *testing.T) {
	resp := singleResponse{
		Prediction:     PredictionMalicious,
		Score:          0.9,
		Threshold:      0.5,
		PrimaryOutcome: primaryOutcomePtr("data_exfiltration"),
		OutcomeScores:  map[string]float64{"data_exfiltration": 0.8},
		DetectorScores: map[string]float64{"new_detector": 0.7},
		DetectorCounts: map[string]int{"new_detector": 1},
	}

	result, err := blockResultFromResponse(resp, ModeBlock)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if result.PrimaryOutcome != PrimaryOutcome("data_exfiltration") {
		t.Fatalf("PrimaryOutcome = %q", result.PrimaryOutcome)
	}
	if result.OutcomeScores[HarmfulOutcome("data_exfiltration")] != 0.8 {
		t.Fatalf("OutcomeScores = %+v", result.OutcomeScores)
	}
	if result.DetectorScores[HarmfulOutcome("new_detector")] != 0.7 {
		t.Fatalf("DetectorScores = %+v", result.DetectorScores)
	}
	if result.DetectorCounts[HarmfulOutcome("new_detector")] != 1 {
		t.Fatalf("DetectorCounts = %+v", result.DetectorCounts)
	}
}

func TestClassifyRejectsPythonBlankOutcomeLabels(t *testing.T) {
	blankLabels := []struct {
		name  string
		label string
	}{
		{name: "NEL", label: "\u0085"},
		{name: "no-break space", label: "\u00a0"},
		{name: "file separator", label: "\u001c"},
		{name: "group separator", label: "\u001d"},
		{name: "record separator", label: "\u001e"},
		{name: "unit separator", label: "\u001f"},
		{
			name:  "mixed whitespace",
			label: " \t\n\v\f\r\u001c\u001d\u001e\u001f\u0085\u00a0\u1680\u2003\u2028\u2029\u202f\u205f\u3000",
		},
	}
	fields := []struct {
		name  string
		value func(string) any
	}{
		{name: "primary_outcome", value: func(label string) any { return label }},
		{name: "outcome_scores", value: func(label string) any { return map[string]float64{label: 0.2} }},
		{name: "detector_scores", value: func(label string) any { return map[string]float64{label: 0.3} }},
		{name: "detector_counts", value: func(label string) any { return map[string]int{label: 1} }},
	}

	for _, label := range blankLabels {
		for _, field := range fields {
			t.Run(label.name+"/"+field.name, func(t *testing.T) {
				_, err := classifyOutcomeResponse(t, map[string]any{field.name: field.value(label.label)})
				if err == nil {
					t.Fatal("expected blank outcome label error")
				}
				if want := "invalid " + field.name; !strings.Contains(err.Error(), want) {
					t.Fatalf("error = %q, want substring %q", err, want)
				}
			})
		}
	}
}

func TestClassifyPreservesPythonNonblankOutcomeLabels(t *testing.T) {
	labels := []struct {
		name  string
		label string
	}{
		{name: "padded unknown label", label: " \u0085future_outcome\u00a0 "},
		{name: "padded benign label", label: " benign "},
		{name: "byte order mark", label: "\u00a0\ufeff\u0085"},
	}

	for _, tc := range labels {
		t.Run(tc.name, func(t *testing.T) {
			result, err := classifyOutcomeResponse(t, map[string]any{
				"primary_outcome": tc.label,
				"outcome_scores":  map[string]float64{tc.label: 0.2},
				"detector_scores": map[string]float64{tc.label: 0.3},
				"detector_counts": map[string]int{tc.label: 1},
			})
			if err != nil {
				t.Fatal(err)
			}
			key := HarmfulOutcome(tc.label)
			if result.PrimaryOutcome != PrimaryOutcome(tc.label) {
				t.Errorf("PrimaryOutcome = %q, want %q", result.PrimaryOutcome, tc.label)
			}
			if len(result.OutcomeScores) != 1 || result.OutcomeScores[key] != 0.2 {
				t.Errorf("OutcomeScores = %#v, want exact key %q", result.OutcomeScores, tc.label)
			}
			if len(result.DetectorScores) != 1 || result.DetectorScores[key] != 0.3 {
				t.Errorf("DetectorScores = %#v, want exact key %q", result.DetectorScores, tc.label)
			}
			if len(result.DetectorCounts) != 1 || result.DetectorCounts[key] != 1 {
				t.Errorf("DetectorCounts = %#v, want exact key %q", result.DetectorCounts, tc.label)
			}
		})
	}
}

func TestClassifyOutcomeLabelsPreserveAbsentAndNull(t *testing.T) {
	cases := []struct {
		name   string
		fields map[string]any
	}{
		{name: "absent"},
		{
			name: "null",
			fields: map[string]any{
				"primary_outcome": nil,
				"outcome_scores":  nil,
				"detector_scores": nil,
				"detector_counts": nil,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := classifyOutcomeResponse(t, tc.fields)
			if err != nil {
				t.Fatal(err)
			}
			if result.PrimaryOutcome != "" {
				t.Errorf("PrimaryOutcome = %q, want empty", result.PrimaryOutcome)
			}
			if result.OutcomeScores != nil || result.DetectorScores != nil || result.DetectorCounts != nil {
				t.Errorf(
					"maps = %#v, %#v, %#v; want nil",
					result.OutcomeScores,
					result.DetectorScores,
					result.DetectorCounts,
				)
			}
		})
	}
}

func TestClassifyRejectsExactBenignHarmfulKeys(t *testing.T) {
	fields := []struct {
		name  string
		value any
	}{
		{name: "outcome_scores", value: map[string]float64{"benign": 0.2}},
		{name: "detector_scores", value: map[string]float64{"benign": 0.3}},
		{name: "detector_counts", value: map[string]int{"benign": 1}},
	}

	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			_, err := classifyOutcomeResponse(t, map[string]any{field.name: field.value})
			if err == nil {
				t.Fatal("expected benign harmful key error")
			}
			if want := "invalid " + field.name + " key"; !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %q, want substring %q", err, want)
			}
		})
	}
}

func classifyOutcomeResponse(t *testing.T, fields map[string]any) (BlockResult, error) {
	t.Helper()

	body := map[string]any{
		"prediction": "BENIGN",
		"score":      0.1,
		"threshold":  0.5,
	}
	for key, value := range fields {
		body[key] = value
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	fw, err := New(Options{
		APIKey: "sk",
		APIURL: "https://example.com",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(string(encoded))),
					Request:    req,
				}, nil
			}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return fw.Classify(context.Background(), "test")
}

func TestSingleResponseOutcomeMapsRejectInvalidElements(t *testing.T) {
	cases := []struct {
		name      string
		field     string
		value     string
		wantError string
	}{
		{
			name:      "null outcome score",
			field:     "outcome_scores",
			value:     "null",
			wantError: `firewall: outcome_scores value for "future_outcome" must not be null`,
		},
		{
			name:      "null detector score",
			field:     "detector_scores",
			value:     "null",
			wantError: `firewall: detector_scores value for "future_outcome" must not be null`,
		},
		{
			name:      "null detector count",
			field:     "detector_counts",
			value:     "null",
			wantError: `firewall: detector_counts value for "future_outcome" must not be null`,
		},
		{
			name:      "nonnumeric outcome score",
			field:     "outcome_scores",
			value:     `"invalid"`,
			wantError: `firewall: invalid outcome_scores value for "future_outcome"`,
		},
		{
			name:      "nonnumeric detector score",
			field:     "detector_scores",
			value:     `"invalid"`,
			wantError: `firewall: invalid detector_scores value for "future_outcome"`,
		},
		{
			name:      "nonnumeric detector count",
			field:     "detector_counts",
			value:     `"invalid"`,
			wantError: `firewall: invalid detector_counts value for "future_outcome"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var resp singleResponse
			body := fmt.Sprintf(`{"prediction":"BENIGN",%q:{"future_outcome":%s}}`, tc.field, tc.value)
			err := json.Unmarshal([]byte(body), &resp)
			if err == nil {
				t.Fatal("expected decode error")
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("error = %q, want substring %q", err, tc.wantError)
			}
		})
	}
}

func TestClassifyRejectsNullOutcomeMapValuesBeforeResultsOrCallbacks(t *testing.T) {
	cases := []struct {
		name  string
		field string
		batch bool
		key   string
	}{
		{name: "single outcome scores", field: "outcome_scores", key: "secret_exposure"},
		{name: "single detector scores", field: "detector_scores", key: "secret_exposure"},
		{name: "single detector counts", field: "detector_counts", key: "secret_exposure"},
		{name: "batch outcome scores with future label", field: "outcome_scores", batch: true, key: "future_outcome"},
		{name: "batch detector scores with future label", field: "detector_scores", batch: true, key: "future_outcome"},
		{name: "batch detector counts with future label", field: "detector_counts", batch: true, key: "future_outcome"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			item := fmt.Sprintf(
				`{"prediction":"BENIGN","score":0.1,"threshold":0.5,"mode":"block",%q:{%q:null}}`,
				tc.field,
				tc.key,
			)
			body := item
			if tc.batch {
				validItem := fmt.Sprintf(
					`{"prediction":"BENIGN","score":0.1,"threshold":0.5,"mode":"block",%q:{"secret_exposure":0}}`,
					tc.field,
				)
				body = fmt.Sprintf(`{"predictions":[%s,%s]}`, validItem, item)
			}

			callbacks := 0
			client := &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(body)),
						Request:    req,
					}, nil
				}),
			}
			fw, err := New(Options{
				APIKey:     "sk",
				APIURL:     "https://example.com",
				HTTPClient: client,
				OnClassify: func(ClassifyEvent) {
					callbacks++
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			var callErr error
			if tc.batch {
				var results []BlockResult
				results, callErr = fw.ClassifyBatch(context.Background(), []string{"valid", "invalid"})
				if results != nil {
					t.Fatalf("results = %#v, want nil", results)
				}
			} else {
				var result BlockResult
				result, callErr = fw.Classify(context.Background(), "invalid")
				if !reflect.DeepEqual(result, BlockResult{}) {
					t.Fatalf("result = %#v, want zero value", result)
				}
			}
			if callErr == nil {
				t.Fatal("expected null map value error")
			}
			wantError := fmt.Sprintf(`firewall: %s value for %q must not be null`, tc.field, tc.key)
			if !strings.Contains(callErr.Error(), wantError) {
				t.Fatalf("error = %q, want substring %q", callErr, wantError)
			}
			if callbacks != 0 {
				t.Errorf("OnClassify calls = %d, want 0", callbacks)
			}
		})
	}
}

func TestClassifyAcceptsCompatibleOutcomeMaps(t *testing.T) {
	cases := []struct {
		name   string
		fields string
		check  func(*testing.T, BlockResult)
	}{
		{
			name: "omitted",
			check: func(t *testing.T, result BlockResult) {
				if result.OutcomeScores != nil || result.DetectorScores != nil || result.DetectorCounts != nil {
					t.Fatalf("maps = %#v, %#v, %#v; want nil", result.OutcomeScores, result.DetectorScores, result.DetectorCounts)
				}
			},
		},
		{
			name:   "null whole maps",
			fields: `,"outcome_scores":null,"detector_scores":null,"detector_counts":null`,
			check: func(t *testing.T, result BlockResult) {
				if result.OutcomeScores != nil || result.DetectorScores != nil || result.DetectorCounts != nil {
					t.Fatalf("maps = %#v, %#v, %#v; want nil", result.OutcomeScores, result.DetectorScores, result.DetectorCounts)
				}
			},
		},
		{
			name:   "empty maps",
			fields: `,"outcome_scores":{},"detector_scores":{},"detector_counts":{}`,
			check: func(t *testing.T, result BlockResult) {
				if result.OutcomeScores == nil || result.DetectorScores == nil || result.DetectorCounts == nil {
					t.Fatalf("maps = %#v, %#v, %#v; want non-nil empty maps", result.OutcomeScores, result.DetectorScores, result.DetectorCounts)
				}
				if len(result.OutcomeScores) != 0 || len(result.DetectorScores) != 0 || len(result.DetectorCounts) != 0 {
					t.Fatalf("maps = %#v, %#v, %#v; want empty", result.OutcomeScores, result.DetectorScores, result.DetectorCounts)
				}
			},
		},
		{
			name:   "zero fractional and future values",
			fields: `,"outcome_scores":{"secret_exposure":0,"future_outcome":0.25},"detector_scores":{"control_abuse":0.5,"future_detector":0},"detector_counts":{"secret_exposure":0,"future_detector":2}`,
			check: func(t *testing.T, result BlockResult) {
				wantOutcomeScores := map[HarmfulOutcome]float64{
					HarmfulOutcomeSecretExposure: 0,
					"future_outcome":             0.25,
				}
				wantDetectorScores := map[HarmfulOutcome]float64{
					HarmfulOutcomeControlAbuse: 0.5,
					"future_detector":          0,
				}
				wantDetectorCounts := map[HarmfulOutcome]int{
					HarmfulOutcomeSecretExposure: 0,
					"future_detector":            2,
				}
				if !reflect.DeepEqual(result.OutcomeScores, wantOutcomeScores) {
					t.Errorf("OutcomeScores = %#v, want %#v", result.OutcomeScores, wantOutcomeScores)
				}
				if !reflect.DeepEqual(result.DetectorScores, wantDetectorScores) {
					t.Errorf("DetectorScores = %#v, want %#v", result.DetectorScores, wantDetectorScores)
				}
				if !reflect.DeepEqual(result.DetectorCounts, wantDetectorCounts) {
					t.Errorf("DetectorCounts = %#v, want %#v", result.DetectorCounts, wantDetectorCounts)
				}
			},
		},
	}

	for _, tc := range cases {
		for _, batch := range []bool{false, true} {
			name := "single"
			if batch {
				name = "batch"
			}
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				item := `{"prediction":"BENIGN","score":0.1,"threshold":0.5,"mode":"block"` + tc.fields + `}`
				body := item
				if batch {
					body = `{"predictions":[` + item + `]}`
				}
				callbacks := 0
				client := &http.Client{
					Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Header:     make(http.Header),
							Body:       io.NopCloser(strings.NewReader(body)),
							Request:    req,
						}, nil
					}),
				}
				fw, err := New(Options{
					APIKey:     "sk",
					APIURL:     "https://example.com",
					HTTPClient: client,
					OnClassify: func(ClassifyEvent) {
						callbacks++
					},
				})
				if err != nil {
					t.Fatal(err)
				}

				var result BlockResult
				if batch {
					results, err := fw.ClassifyBatch(context.Background(), []string{"valid"})
					if err != nil {
						t.Fatal(err)
					}
					if len(results) != 1 {
						t.Fatalf("results length = %d, want 1", len(results))
					}
					result = results[0]
				} else {
					result, err = fw.Classify(context.Background(), "valid")
					if err != nil {
						t.Fatal(err)
					}
				}
				tc.check(t, result)
				if callbacks != 1 {
					t.Errorf("OnClassify calls = %d, want 1", callbacks)
				}
			})
		}
	}
}

func TestNormalizeHarmfulOutcomeIntMapPreservesValidCounts(t *testing.T) {
	normalized, err := normalizeHarmfulOutcomeIntMap(nil, "detector_counts")
	if err != nil {
		t.Fatal(err)
	}
	if normalized != nil {
		t.Fatalf("nil map normalized to %#v, want nil", normalized)
	}

	normalized, err = normalizeHarmfulOutcomeIntMap(map[string]int{}, "detector_counts")
	if err != nil {
		t.Fatal(err)
	}
	if normalized == nil || len(normalized) != 0 {
		t.Fatalf("empty map normalized to %#v, want non-nil empty map", normalized)
	}

	normalized, err = normalizeHarmfulOutcomeIntMap(map[string]int{
		string(HarmfulOutcomeSecretExposure): 0,
		"future_detector":                    2,
	}, "detector_counts")
	if err != nil {
		t.Fatal(err)
	}
	want := map[HarmfulOutcome]int{
		HarmfulOutcomeSecretExposure: 0,
		"future_detector":            2,
	}
	if !reflect.DeepEqual(normalized, want) {
		t.Fatalf("normalized counts = %#v, want %#v", normalized, want)
	}
}

func TestClassifyRejectsNegativeDetectorCountsBeforeResultsOrCallbacks(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		batch     bool
		wantKey   string
		wantValue int
	}{
		{
			name:      "single known outcome",
			body:      `{"prediction":"BENIGN","score":0.1,"threshold":0.5,"mode":"block","detector_counts":{"secret_exposure":-1}}`,
			wantKey:   "secret_exposure",
			wantValue: -1,
		},
		{
			name:      "batch future outcome",
			body:      `{"predictions":[{"prediction":"BENIGN","score":0.1,"threshold":0.5,"mode":"block","detector_counts":{"control_abuse":0}},{"prediction":"BENIGN","score":0.2,"threshold":0.5,"mode":"block","detector_counts":{"future_detector":-2}}]}`,
			batch:     true,
			wantKey:   "future_detector",
			wantValue: -2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			callbacks := 0
			client := &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					requests++
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(tc.body)),
						Request:    req,
					}, nil
				}),
			}
			fw, err := New(Options{
				APIKey:     "sk",
				APIURL:     "https://example.com",
				HTTPClient: client,
				OnClassify: func(ClassifyEvent) {
					callbacks++
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			var callErr error
			if tc.batch {
				var results []BlockResult
				results, callErr = fw.ClassifyBatch(context.Background(), []string{"valid", "invalid"})
				if results != nil {
					t.Fatalf("results = %#v, want nil", results)
				}
			} else {
				var result BlockResult
				result, callErr = fw.Classify(context.Background(), "invalid")
				if !reflect.DeepEqual(result, BlockResult{}) {
					t.Fatalf("result = %#v, want zero value", result)
				}
			}
			if callErr == nil {
				t.Fatal("expected negative detector count error")
			}
			wantError := fmt.Sprintf(
				"firewall: detector_counts value for %q must be non-negative, got %d",
				tc.wantKey,
				tc.wantValue,
			)
			if !strings.Contains(callErr.Error(), wantError) {
				t.Fatalf("error = %q, want substring %q", callErr, wantError)
			}
			if requests != 1 {
				t.Errorf("HTTP requests = %d, want 1", requests)
			}
			if callbacks != 0 {
				t.Errorf("OnClassify calls = %d, want 0", callbacks)
			}
		})
	}
}
