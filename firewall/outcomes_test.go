// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
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
	}
	if len(PrimaryOutcomes) != len(wantPrimary) {
		t.Fatalf("PrimaryOutcomes length = %d, want %d", len(PrimaryOutcomes), len(wantPrimary))
	}
	for i, want := range wantPrimary {
		if PrimaryOutcomes[i] != want {
			t.Fatalf("PrimaryOutcomes[%d] = %q, want %q", i, PrimaryOutcomes[i], want)
		}
		if OutcomeDescriptions[want] == "" {
			t.Fatalf("missing description for %q", want)
		}
		if !IsPrimaryOutcome(want) {
			t.Fatalf("%q should be a primary outcome", want)
		}
	}
	if IsHarmfulOutcome(OutcomeBenign) {
		t.Fatal("benign should not be a harmful outcome")
	}
	if !IsHarmfulOutcome(OutcomeSecretExposure) {
		t.Fatal("secret exposure should be a harmful outcome")
	}
}

func TestBlockResultFromResponseDecodesTypedOutcomes(t *testing.T) {
	for _, outcome := range PrimaryOutcomes {
		resp := singleResponse{
			Prediction:     PredictionBenign,
			Score:          0.1,
			Threshold:      0.5,
			PrimaryOutcome: primaryOutcomePtr(string(outcome)),
		}
		result, err := blockResultFromResponse(resp)
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
			name: "primary",
			resp: singleResponse{Prediction: PredictionMalicious, Score: 0.9, Threshold: 0.5, PrimaryOutcome: primaryOutcomePtr("unknown")},
			want: "invalid primary_outcome",
		},
		{
			name: "outcome scores",
			resp: singleResponse{Prediction: PredictionMalicious, Score: 0.9, Threshold: 0.5, OutcomeScores: map[string]float64{"unknown": 0.8}},
			want: "invalid outcome_scores key",
		},
		{
			name: "detector scores",
			resp: singleResponse{Prediction: PredictionMalicious, Score: 0.9, Threshold: 0.5, DetectorScores: map[string]float64{"unknown": 0.8}},
			want: "invalid detector_scores key",
		},
		{
			name: "detector counts",
			resp: singleResponse{Prediction: PredictionMalicious, Score: 0.9, Threshold: 0.5, DetectorCounts: map[string]int{"unknown": 1}},
			want: "invalid detector_counts key",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := blockResultFromResponse(tc.resp)
			if err == nil {
				t.Fatal("expected error")
			}
			if got := err.Error(); !strings.Contains(got, tc.want) {
				t.Fatalf("error = %q, want substring %q", got, tc.want)
			}
		})
	}
}
