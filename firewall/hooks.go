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

// PrependHook returns text prefixed with a [HOOK:<label>] marker so the
// model can apply stage-dependent scoring. Returns text unchanged when
// hook is empty or HookUnknown.
//
// Deprecated: Classify and ClassifyBatch send hook labels as structured JSON
// fields. Use WithHook or WithBatchHooks for normal SDK calls.
func PrependHook(text string, hook HookLabel) string {
	if hook == "" || hook == HookUnknown {
		return text
	}
	return fmt.Sprintf("[HOOK:%s] %s", hook, text)
}

// PrependToolName returns text prefixed with a [TOOL:<name>] marker for
// tool-name-aware classification. Returns text unchanged when name is empty.
//
// Deprecated: Classify and ClassifyBatch send tool names as structured JSON
// fields. Use WithToolName or WithBatchToolNames for normal SDK calls.
func PrependToolName(text, toolName string) string {
	if toolName == "" {
		return text
	}
	return fmt.Sprintf("[TOOL:%s] %s", toolName, text)
}
