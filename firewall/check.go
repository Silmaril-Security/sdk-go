// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import "context"

// Check classifies text and returns PromptBlockedError when the score meets or
// exceeds the effective threshold. In shadow mode it still classifies and emits
// ClassifyEvent, but suppresses PromptBlockedError so live traffic can continue.
func (f *Firewall) Check(ctx context.Context, text string, opts ...CheckOption) (BlockResult, error) {
	event, err := f.CheckEvent(ctx, text, opts...)
	if err != nil {
		return BlockResult{}, err
	}
	if event.Blocked && !event.ShadowMode {
		return event.Result, &PromptBlockedError{
			Score:      event.Result.Score,
			Threshold:  event.Result.Threshold,
			PromptText: text,
			Hook:       event.Hook,
			ToolName:   event.ToolName,
			Result:     event.Result,
		}
	}
	return event.Result, nil
}

// CheckEvent classifies text and returns the blocking decision without raising
// PromptBlockedError. It still emits configured callbacks.
func (f *Firewall) CheckEvent(ctx context.Context, text string, opts ...CheckOption) (ClassifyEvent, error) {
	var cfg checkConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	classifyOpts := make([]ClassifyOption, 0, 2)
	if cfg.hook != "" {
		classifyOpts = append(classifyOpts, WithHook(cfg.hook))
	}
	if cfg.toolName != "" {
		classifyOpts = append(classifyOpts, WithToolName(cfg.toolName))
	}
	result, err := f.Classify(ctx, text, classifyOpts...)
	if err != nil {
		return ClassifyEvent{}, err
	}

	hook := cfg.hook
	if hook == "" {
		hook = HookUnknown
	}
	event := ClassifyEvent{
		Hook:       hook,
		ToolName:   cfg.toolName,
		Text:       text,
		Result:     result,
		Blocked:    result.Score >= result.Threshold,
		ShadowMode: f.effectiveShadowMode(cfg),
	}
	f.fireClassifyEvent(event, cfg.onClassify)
	return event, nil
}

func (f *Firewall) effectiveShadowMode(cfg checkConfig) bool {
	if cfg.shadowMode != nil {
		return *cfg.shadowMode
	}
	return f.shadowMode
}

func (f *Firewall) fireClassifyEvent(event ClassifyEvent, perCall func(ClassifyEvent)) {
	if f.onClassify != nil {
		safeClassifyCallback(f.onClassify, event)
	}
	if perCall != nil {
		safeClassifyCallback(perCall, event)
	}
}

func safeClassifyCallback(fn func(ClassifyEvent), event ClassifyEvent) {
	defer func() {
		_ = recover()
	}()
	fn(event)
}
