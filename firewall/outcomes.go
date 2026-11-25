// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import "maps"

// HarmfulOutcome is the harm the Firewall predicts for a model block. The type
// is open: a runtime may return a label outside the constants below, and the
// zero value means the result has no outcome.
type HarmfulOutcome string

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
	HarmfulOutcomeAbuse                 HarmfulOutcome = "abuse"
	HarmfulOutcomeTraditionalAIAbuse    HarmfulOutcome = "traditional_ai_abuse"
)

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
	HarmfulOutcomeAbuse,
	HarmfulOutcomeTraditionalAIAbuse,
}

var outcomeDescriptions = map[HarmfulOutcome]string{
	HarmfulOutcomeInformationDisclosure: "Exposes private data, documents, internal context, logs, traces, customer data, SQL rows, topology, or similar non-secret sensitive information.",
	HarmfulOutcomeSecretExposure:        "Exposes credentials, tokens, API keys, cookies, passwords, signing keys, OAuth secrets, session material, or webhook secrets.",
	HarmfulOutcomeControlAbuse:          "Misuses authorized tools or user privileges to send, change, approve, delete, operate, or bypass policy/RBAC without a stronger outcome.",
	HarmfulOutcomeSystemCompromise:      "Enables privilege escalation, account takeover, hostile integration or plugin takeover, persistence, lateral movement, attacker webhook registration, or code/plugin execution.",
	HarmfulOutcomeServiceDisruption:     "Causes downtime, lockout, degradation, alert suppression, destructive loops, resource exhaustion, cost spikes, or hidden outage evidence.",
	HarmfulOutcomeCodeGeneration:        "Requests generation or material modification of executable code, scripts, workflows, or configuration.",
	HarmfulOutcomeStoryScriptGeneration: "Requests generation of narrative prose, dialogue, scripts, or story artifacts.",
	HarmfulOutcomeGameGeneration:        "Requests generation of a game, quest, level, mechanic, or playable experience.",
	HarmfulOutcomeWebsiteGeneration:     "Requests generation of a website, landing page, storefront, or web experience.",
	HarmfulOutcomeAbuse:                 "Requests content or actions that violate the tenant's acceptable-use policy.",
	HarmfulOutcomeTraditionalAIAbuse:    "Requests unsafe AI assistance outside the concrete security outcome classes.",
}

// HarmfulOutcomes returns the ordered public harmful-outcome taxonomy.
func HarmfulOutcomes() []HarmfulOutcome {
	return append([]HarmfulOutcome(nil), harmfulOutcomes...)
}

// OutcomeDescriptions returns short public descriptions for each known outcome.
func OutcomeDescriptions() map[HarmfulOutcome]string {
	return maps.Clone(outcomeDescriptions)
}

// IsHarmfulOutcome reports whether value is a canonical harmful outcome.
func IsHarmfulOutcome(value HarmfulOutcome) bool {
	_, known := outcomeDescriptions[value]
	return known
}
