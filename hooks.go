// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

// Package firewall is the Go SDK for Silmaril Firewall: self-healing prompt
// injection defense for AI applications. It mirrors the wire contract, hook
// labels, and chunking behavior of the Python and TypeScript SDKs.
package firewall

import "fmt"

// HookLabel names an LLM pipeline stage. The firewall applies
// stage-dependent scoring based on this label.
type HookLabel string

const (
	HookUserInput    HookLabel = "user_input"
	HookSystemPrompt HookLabel = "system_prompt"
	HookToolCall     HookLabel = "tool_call"
	HookToolResponse HookLabel = "tool_response"
	HookLLMOutput    HookLabel = "llm_output"
	HookUnknown      HookLabel = "unknown"
)

// DefaultThreshold is the score at or above which a prediction is treated
// as MALICIOUS when no per-hook override is set.
const DefaultThreshold = 0.5

// DefaultHookThresholds mirrors the per-hook default thresholds shipped by
// the Python and TypeScript SDKs.
var DefaultHookThresholds = map[HookLabel]float64{
	HookUserInput:    0.5,
	HookSystemPrompt: 0.5,
	HookToolCall:     0.5,
	HookToolResponse: 0.5,
	HookLLMOutput:    0.5,
	HookUnknown:      0.5,
}

// PrependHook returns text prefixed with a [HOOK:<label>] marker so the
// model can apply stage-dependent scoring. Returns text unchanged when
// hook is empty or HookUnknown.
func PrependHook(text string, hook HookLabel) string {
	if hook == "" || hook == HookUnknown {
		return text
	}
	return fmt.Sprintf("[HOOK:%s] %s", hook, text)
}

// PrependToolName returns text prefixed with a [TOOL:<name>] marker for
// tool-name-aware classification. Returns text unchanged when name is empty.
func PrependToolName(text, toolName string) string {
	if toolName == "" {
		return text
	}
	return fmt.Sprintf("[TOOL:%s] %s", toolName, text)
}
