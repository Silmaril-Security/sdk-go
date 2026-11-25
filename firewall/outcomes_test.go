// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"reflect"
	"testing"
)

func TestOutcomeTaxonomyExportsOrderedValues(t *testing.T) {
	want := []HarmfulOutcome{
		HarmfulOutcomeInformationDisclosure,
		HarmfulOutcomeSecretExposure,
		HarmfulOutcomeControlAbuse,
		HarmfulOutcomeSystemCompromise,
		HarmfulOutcomeServiceDisruption,
		HarmfulOutcomeCodeGeneration,
		HarmfulOutcomeStoryScriptGeneration,
		HarmfulOutcomeGameGeneration,
		HarmfulOutcomeWebsiteGeneration,
		HarmfulOutcomeAbuse,
		HarmfulOutcomeTraditionalAIAbuse,
	}
	if got := HarmfulOutcomes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("HarmfulOutcomes = %q, want %q", got, want)
	}
	descriptions := OutcomeDescriptions()
	if len(descriptions) != len(want) {
		t.Fatalf("OutcomeDescriptions has %d entries, want %d", len(descriptions), len(want))
	}
	for _, outcome := range want {
		if descriptions[outcome] == "" {
			t.Fatalf("missing description for %q", outcome)
		}
		if !IsHarmfulOutcome(outcome) {
			t.Fatalf("%q should be a harmful outcome", outcome)
		}
	}
	for _, unknown := range []HarmfulOutcome{"", "benign", "data_exfiltration"} {
		if IsHarmfulOutcome(unknown) {
			t.Fatalf("%q should not be a canonical harmful outcome", unknown)
		}
	}
}

func TestOutcomeTaxonomyAccessorsReturnCopies(t *testing.T) {
	harmful := HarmfulOutcomes()
	harmful[0] = "mutated"
	if HarmfulOutcomes()[0] != HarmfulOutcomeInformationDisclosure {
		t.Fatal("HarmfulOutcomes should return a copy")
	}

	descriptions := OutcomeDescriptions()
	descriptions[HarmfulOutcomeSecretExposure] = "mutated"
	if OutcomeDescriptions()[HarmfulOutcomeSecretExposure] == "mutated" {
		t.Fatal("OutcomeDescriptions should return a copy")
	}
}
