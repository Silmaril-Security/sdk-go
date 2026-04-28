// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

package silmaril

import "testing"

func TestPrependHookWithLabel(t *testing.T) {
	got := PrependHook("hello", HookUserInput)
	if want := "[HOOK:user_input] hello"; got != want {
		t.Errorf("PrependHook: got %q, want %q", got, want)
	}
}

func TestPrependHookAllLabels(t *testing.T) {
	cases := map[HookLabel]string{
		HookUserInput:    "[HOOK:user_input] x",
		HookSystemPrompt: "[HOOK:system_prompt] x",
		HookToolCall:     "[HOOK:tool_call] x",
		HookToolResponse: "[HOOK:tool_response] x",
		HookLLMOutput:    "[HOOK:llm_output] x",
	}
	for label, want := range cases {
		if got := PrependHook("x", label); got != want {
			t.Errorf("PrependHook(%q): got %q, want %q", label, got, want)
		}
	}
}

func TestPrependHookEmpty(t *testing.T) {
	if got := PrependHook("hello", ""); got != "hello" {
		t.Errorf("empty hook: got %q, want unchanged", got)
	}
}

func TestPrependHookUnknown(t *testing.T) {
	if got := PrependHook("hello", HookUnknown); got != "hello" {
		t.Errorf("unknown hook: got %q, want unchanged", got)
	}
}

func TestPrependToolName(t *testing.T) {
	got := PrependToolName("hello", "calendar")
	if want := "[TOOL:calendar] hello"; got != want {
		t.Errorf("PrependToolName: got %q, want %q", got, want)
	}
}

func TestPrependToolNameEmpty(t *testing.T) {
	if got := PrependToolName("hello", ""); got != "hello" {
		t.Errorf("empty tool name: got %q, want unchanged", got)
	}
}

func TestDefaultHookThresholds(t *testing.T) {
	labels := []HookLabel{
		HookUserInput, HookSystemPrompt, HookToolCall,
		HookToolResponse, HookLLMOutput, HookUnknown,
	}
	for _, label := range labels {
		v, ok := DefaultHookThresholds[label]
		if !ok {
			t.Errorf("DefaultHookThresholds missing %q", label)
			continue
		}
		if v != 0.5 {
			t.Errorf("DefaultHookThresholds[%q] = %v, want 0.5", label, v)
		}
	}
	if len(DefaultHookThresholds) != len(labels) {
		t.Errorf("DefaultHookThresholds size = %d, want %d", len(DefaultHookThresholds), len(labels))
	}
}

func TestDefaultThresholdValue(t *testing.T) {
	if DefaultThreshold != 0.5 {
		t.Errorf("DefaultThreshold = %v, want 0.5", DefaultThreshold)
	}
}
