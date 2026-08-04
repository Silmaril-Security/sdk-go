// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import "fmt"

// PrimaryOutcome is the canonical outcome label for a classification result.
type PrimaryOutcome string

// HarmfulOutcome is a canonical non-benign outcome label.
type HarmfulOutcome string

const (
	OutcomeBenign                PrimaryOutcome = "benign"
	OutcomeInformationDisclosure PrimaryOutcome = "information_disclosure"
	OutcomeSecretExposure        PrimaryOutcome = "secret_exposure"
	OutcomeControlAbuse          PrimaryOutcome = "control_abuse"
	OutcomeSystemCompromise      PrimaryOutcome = "system_compromise"
	OutcomeServiceDisruption     PrimaryOutcome = "service_disruption"
	OutcomeCodeGeneration        PrimaryOutcome = "code_generation"
	OutcomeStoryScriptGeneration PrimaryOutcome = "story_script_generation"
	OutcomeGameGeneration        PrimaryOutcome = "game_generation"
	OutcomeWebsiteGeneration     PrimaryOutcome = "website_generation"
	OutcomeClickUpTermsViolation PrimaryOutcome = "clickup_terms_violation"
	OutcomeTraditionalAIAbuse    PrimaryOutcome = "traditional_ai_abuse"
)

const (
	HarmfulOutcomeInformationDisclosure HarmfulOutcome = "information_disclosure"
	HarmfulOutcomeSecretExposure        HarmfulOutcome = "secret_exposure"
	HarmfulOutcomeControlAbuse          HarmfulOutcome = "control_abuse"
	HarmfulOutcomeSystemCompromise      HarmfulOutcome = "system_compromise"
	HarmfulOutcomeServiceDisruption     HarmfulOutcome = "service_disruption"
	HarmfulOutcomeCodeGeneration        HarmfulOutcome = "code_generation"
	HarmfulOutcomeStoryScriptGeneration HarmfulOutcome = "story_script_generation"
	HarmfulOutcomeGameGeneration        HarmfulOutcome = "game_generation"
	HarmfulOutcomeWebsiteGeneration     HarmfulOutcome = "website_generation"
	HarmfulOutcomeClickUpTermsViolation HarmfulOutcome = "clickup_terms_violation"
	HarmfulOutcomeTraditionalAIAbuse    HarmfulOutcome = "traditional_ai_abuse"
)

var primaryOutcomes = []PrimaryOutcome{
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

var harmfulOutcomes = []HarmfulOutcome{
	HarmfulOutcomeInformationDisclosure,
	HarmfulOutcomeSecretExposure,
	HarmfulOutcomeControlAbuse,
	HarmfulOutcomeSystemCompromise,
	HarmfulOutcomeServiceDisruption,
	HarmfulOutcomeCodeGeneration,
	HarmfulOutcomeStoryScriptGeneration,
	HarmfulOutcomeGameGeneration,
	HarmfulOutcomeWebsiteGeneration,
	HarmfulOutcomeClickUpTermsViolation,
	HarmfulOutcomeTraditionalAIAbuse,
}

var outcomeDescriptions = map[PrimaryOutcome]string{
	OutcomeBenign:                "No harmful firewall outcome detected.",
	OutcomeInformationDisclosure: "Exposes private data, documents, internal context, logs, traces, customer data, SQL rows, topology, or similar non-secret sensitive information.",
	OutcomeSecretExposure:        "Exposes credentials, tokens, API keys, cookies, passwords, signing keys, OAuth secrets, session material, or webhook secrets.",
	OutcomeControlAbuse:          "Misuses authorized tools or user privileges to send, change, approve, delete, operate, or bypass policy/RBAC without a stronger outcome.",
	OutcomeSystemCompromise:      "Enables privilege escalation, account takeover, hostile integration or plugin takeover, persistence, lateral movement, attacker webhook registration, or code/plugin execution.",
	OutcomeServiceDisruption:     "Causes downtime, lockout, degradation, alert suppression, destructive loops, resource exhaustion, cost spikes, or hidden outage evidence.",
	OutcomeCodeGeneration:        "Requests generation or material modification of executable code, scripts, workflows, or configuration.",
	OutcomeStoryScriptGeneration: "Requests generation of narrative prose, dialogue, scripts, or story artifacts.",
	OutcomeGameGeneration:        "Requests generation of a game, quest, level, mechanic, or playable experience.",
	OutcomeWebsiteGeneration:     "Requests generation of a website, landing page, storefront, or web experience.",
	OutcomeClickUpTermsViolation: "Requests content or actions that violate the configured ClickUp tenant policy.",
	OutcomeTraditionalAIAbuse:    "Requests unsafe AI assistance outside the concrete security outcome classes.",
}

// PrimaryOutcomes returns the ordered public primary-outcome taxonomy.
func PrimaryOutcomes() []PrimaryOutcome {
	return append([]PrimaryOutcome(nil), primaryOutcomes...)
}

// HarmfulOutcomes returns the ordered public harmful-outcome taxonomy.
func HarmfulOutcomes() []HarmfulOutcome {
	return append([]HarmfulOutcome(nil), harmfulOutcomes...)
}

// OutcomeDescriptions returns short public descriptions for each known outcome.
func OutcomeDescriptions() map[PrimaryOutcome]string {
	out := make(map[PrimaryOutcome]string, len(outcomeDescriptions))
	for key, value := range outcomeDescriptions {
		out[key] = value
	}
	return out
}

var primaryOutcomeSet = map[PrimaryOutcome]struct{}{
	OutcomeBenign:                {},
	OutcomeInformationDisclosure: {},
	OutcomeSecretExposure:        {},
	OutcomeControlAbuse:          {},
	OutcomeSystemCompromise:      {},
	OutcomeServiceDisruption:     {},
	OutcomeCodeGeneration:        {},
	OutcomeStoryScriptGeneration: {},
	OutcomeGameGeneration:        {},
	OutcomeWebsiteGeneration:     {},
	OutcomeClickUpTermsViolation: {},
	OutcomeTraditionalAIAbuse:    {},
}

var harmfulOutcomeSet = map[HarmfulOutcome]struct{}{
	HarmfulOutcomeInformationDisclosure: {},
	HarmfulOutcomeSecretExposure:        {},
	HarmfulOutcomeControlAbuse:          {},
	HarmfulOutcomeSystemCompromise:      {},
	HarmfulOutcomeServiceDisruption:     {},
	HarmfulOutcomeCodeGeneration:        {},
	HarmfulOutcomeStoryScriptGeneration: {},
	HarmfulOutcomeGameGeneration:        {},
	HarmfulOutcomeWebsiteGeneration:     {},
	HarmfulOutcomeClickUpTermsViolation: {},
	HarmfulOutcomeTraditionalAIAbuse:    {},
}

// IsPrimaryOutcome reports whether value is a canonical primary outcome.
func IsPrimaryOutcome(value PrimaryOutcome) bool {
	_, ok := primaryOutcomeSet[value]
	return ok
}

// IsHarmfulOutcome reports whether value is a canonical harmful outcome.
func IsHarmfulOutcome(value HarmfulOutcome) bool {
	_, ok := harmfulOutcomeSet[value]
	return ok
}

func normalizePrimaryOutcome(value string, fieldName string) (PrimaryOutcome, error) {
	if value == "" {
		return "", fmt.Errorf("firewall: invalid %s %q", fieldName, value)
	}
	return PrimaryOutcome(value), nil
}

func normalizeHarmfulOutcome(value string, fieldName string) (HarmfulOutcome, error) {
	if value == "" || value == string(OutcomeBenign) {
		return "", fmt.Errorf("firewall: invalid %s %q", fieldName, value)
	}
	return HarmfulOutcome(value), nil
}

func normalizeHarmfulOutcomeFloatMap(values map[string]float64, fieldName string) (map[HarmfulOutcome]float64, error) {
	if values == nil {
		return nil, nil
	}
	out := make(map[HarmfulOutcome]float64, len(values))
	for key, value := range values {
		outcome, err := normalizeHarmfulOutcome(key, fieldName+" key")
		if err != nil {
			return nil, err
		}
		out[outcome] = value
	}
	return out, nil
}

func normalizeHarmfulOutcomeIntMap(values map[string]int, fieldName string) (map[HarmfulOutcome]int, error) {
	if values == nil {
		return nil, nil
	}
	out := make(map[HarmfulOutcome]int, len(values))
	for key, value := range values {
		outcome, err := normalizeHarmfulOutcome(key, fieldName+" key")
		if err != nil {
			return nil, err
		}
		out[outcome] = value
	}
	return out, nil
}
