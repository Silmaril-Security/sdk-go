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
