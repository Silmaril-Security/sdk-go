// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import "fmt"

// PrimaryOutcome is the canonical outcome label for a classification result.
type PrimaryOutcome string

// HarmfulOutcome is a canonical non-benign outcome label.
type HarmfulOutcome string

const (
	OutcomeBenign                = "benign"
	OutcomeInformationDisclosure = "information_disclosure"
	OutcomeSecretExposure        = "secret_exposure"
	OutcomeControlAbuse          = "control_abuse"
	OutcomeSystemCompromise      = "system_compromise"
	OutcomeServiceDisruption     = "service_disruption"
)

// PrimaryOutcomes is the ordered public primary-outcome taxonomy.
var PrimaryOutcomes = []PrimaryOutcome{
	OutcomeBenign,
	OutcomeInformationDisclosure,
	OutcomeSecretExposure,
	OutcomeControlAbuse,
	OutcomeSystemCompromise,
	OutcomeServiceDisruption,
}

// HarmfulOutcomes is the ordered public harmful-outcome taxonomy.
var HarmfulOutcomes = []HarmfulOutcome{
	OutcomeInformationDisclosure,
	OutcomeSecretExposure,
	OutcomeControlAbuse,
	OutcomeSystemCompromise,
	OutcomeServiceDisruption,
}

// OutcomeDescriptions contains short public descriptions for each outcome.
var OutcomeDescriptions = map[PrimaryOutcome]string{
	OutcomeBenign:                "No harmful firewall outcome detected.",
	OutcomeInformationDisclosure: "Exposes private data, documents, internal context, logs, traces, customer data, SQL rows, topology, or similar non-secret sensitive information.",
	OutcomeSecretExposure:        "Exposes credentials, tokens, API keys, cookies, passwords, signing keys, OAuth secrets, session material, or webhook secrets.",
	OutcomeControlAbuse:          "Misuses authorized tools or user privileges to send, change, approve, delete, operate, or bypass policy/RBAC without a stronger outcome.",
	OutcomeSystemCompromise:      "Enables privilege escalation, account takeover, hostile integration or plugin takeover, persistence, lateral movement, attacker webhook registration, or code/plugin execution.",
	OutcomeServiceDisruption:     "Causes downtime, lockout, degradation, alert suppression, destructive loops, resource exhaustion, cost spikes, or hidden outage evidence.",
}

var primaryOutcomeSet = map[PrimaryOutcome]struct{}{
	OutcomeBenign:                {},
	OutcomeInformationDisclosure: {},
	OutcomeSecretExposure:        {},
	OutcomeControlAbuse:          {},
	OutcomeSystemCompromise:      {},
	OutcomeServiceDisruption:     {},
}

var harmfulOutcomeSet = map[HarmfulOutcome]struct{}{
	OutcomeInformationDisclosure: {},
	OutcomeSecretExposure:        {},
	OutcomeControlAbuse:          {},
	OutcomeSystemCompromise:      {},
	OutcomeServiceDisruption:     {},
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
	outcome := PrimaryOutcome(value)
	if !IsPrimaryOutcome(outcome) {
		return "", fmt.Errorf("firewall: invalid %s %q", fieldName, value)
	}
	return outcome, nil
}

func normalizeHarmfulOutcome(value string, fieldName string) (HarmfulOutcome, error) {
	outcome := HarmfulOutcome(value)
	if !IsHarmfulOutcome(outcome) {
		return "", fmt.Errorf("firewall: invalid %s %q", fieldName, value)
	}
	return outcome, nil
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
