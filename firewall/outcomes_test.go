// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"context"
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
