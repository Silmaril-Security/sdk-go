// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"context"
	"errors"
	"fmt"
)

type singleRequestPayload struct {
	Text     string                  `json:"text"`
	Hook     HookLabel               `json:"hook,omitempty"`
	ToolName string                  `json:"tool_name,omitempty"`
	Metadata *ClassificationMetadata `json:"metadata,omitempty"`
}

type batchRequestPayload struct {
	Texts     []string                  `json:"texts"`
	Hooks     []HookLabel               `json:"hooks,omitempty"`
	ToolNames []*string                 `json:"tool_names,omitempty"`
	Metadata  []*ClassificationMetadata `json:"metadata,omitempty"`
}

type singleResponse struct {
	Prediction     Prediction         `json:"prediction"`
	Score          float64            `json:"score"`
	Threshold      float64            `json:"threshold"`
	PrimaryOutcome *string            `json:"primary_outcome"`
	OutcomeScores  map[string]float64 `json:"outcome_scores"`
	DetectorScores map[string]float64 `json:"detector_scores"`
	DetectorCounts map[string]int     `json:"detector_counts"`
}

type batchResponse struct {
	Predictions []singleResponse `json:"predictions"`
}

// Classify classifies one complete logical event in a single request.
func (f *Firewall) Classify(ctx context.Context, text string, opts ...ClassifyOption) (BlockResult, error) {
	var cfg classifyConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.requestID == "" {
		cfg.requestID = newRequestID()
	}
	text = sanitizeText(text)
	result, err := f.classifySingleRaw(ctx, text, cfg)
	if err != nil {
		return BlockResult{}, err
	}
	event := f.newClassifyEvent(text, cfg.hook, cfg.toolName, result, f.effectiveShadowMode(cfg.shadowMode))
	f.fireClassifyEvent(event)
	if event.Blocked && !event.ShadowMode {
		return result, firewallBlockedErrorFromEvent(event)
	}
	return result, nil
}

func (f *Firewall) classifySingleRaw(ctx context.Context, text string, cfg classifyConfig) (BlockResult, error) {
	metadata, err := sdkMetadata(cfg.metadata, cfg.requestID, nil)
	if err != nil {
		return BlockResult{}, err
	}
	payload := singleRequestPayload{
		Text:     text,
		Metadata: metadata,
	}
	if cfg.hook != "" {
		payload.Hook = cfg.hook
	}
	if cfg.toolName != "" {
		payload.ToolName = cfg.toolName
	}
	var resp singleResponse
	if err := f.postJSON(ctx, payload, &resp); err != nil {
		return BlockResult{}, err
	}
	return blockResultFromResponse(resp)
}

// ClassifyBatch classifies multiple independent texts in a single request.
// When hooks or toolNames are provided, their length must equal len(texts).
func (f *Firewall) ClassifyBatch(ctx context.Context, texts []string, opts ...BatchClassifyOption) ([]BlockResult, error) {
	var cfg batchClassifyConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.requestID == "" {
		cfg.requestID = newRequestID()
	}
	texts = sanitizeTexts(texts)
	results, err := f.classifyBatchRaw(ctx, texts, cfg)
	if err != nil {
		return nil, err
	}
	shadowMode := f.effectiveShadowMode(cfg.shadowMode)
	blocked := make([]BlockedBatchItem, 0)
	for i, result := range results {
		event := f.newClassifyEvent(texts[i], batchHookAt(cfg, i), batchToolNameAt(cfg, i), result, shadowMode)
		f.fireClassifyEvent(event)
		if event.Blocked && !event.ShadowMode {
			blocked = append(blocked, BlockedBatchItem{
				Index:    i,
				Text:     texts[i],
				Hook:     event.Hook,
				ToolName: event.ToolName,
				Result:   result,
			})
		}
	}
	if len(blocked) > 0 {
		return results, &BatchFirewallBlockedError{Blocked: blocked}
	}
	return results, nil
}

func (f *Firewall) classifyBatchRaw(ctx context.Context, texts []string, cfg batchClassifyConfig) ([]BlockResult, error) {
	if len(texts) == 0 {
		return nil, errors.New("firewall: texts must not be empty")
	}
	if len(cfg.hooks) != 0 && len(cfg.hooks) != len(texts) {
		return nil, fmt.Errorf("firewall: hooks length %d does not match texts length %d", len(cfg.hooks), len(texts))
	}
	if len(cfg.toolNames) != 0 && len(cfg.toolNames) != len(texts) {
		return nil, fmt.Errorf("firewall: toolNames length %d does not match texts length %d", len(cfg.toolNames), len(texts))
	}
	if cfg.metadataSet && len(cfg.metadata) != len(texts) {
		return nil, fmt.Errorf("firewall: metadata length %d does not match texts length %d", len(cfg.metadata), len(texts))
	}
	payload := batchRequestPayload{
		Texts: texts,
	}
	if len(cfg.hooks) > 0 {
		payload.Hooks = cfg.hooks
	}
	if len(cfg.toolNames) > 0 {
		payload.ToolNames = batchToolNames(cfg.toolNames)
	}
	metadata, err := batchMetadata(cfg, len(texts))
	if err != nil {
		return nil, err
	}
	payload.Metadata = metadata
	var resp batchResponse
	if err := f.postJSON(ctx, payload, &resp); err != nil {
		return nil, err
	}
	if len(resp.Predictions) != len(texts) {
		return nil, fmt.Errorf("firewall: predictions length %d does not match texts length %d", len(resp.Predictions), len(texts))
	}
	results := make([]BlockResult, len(resp.Predictions))
	for i, p := range resp.Predictions {
		result, err := blockResultFromResponse(p)
		if err != nil {
			return nil, err
		}
		results[i] = result
	}
	return results, nil
}

func (f *Firewall) newClassifyEvent(text string, hook HookLabel, toolName string, result BlockResult, shadowMode bool) ClassifyEvent {
	if hook == "" {
		hook = HookUnknown
	}
	return ClassifyEvent{
		Hook:       hook,
		ToolName:   toolName,
		Text:       text,
		Result:     result,
		Blocked:    result.Prediction == PredictionMalicious,
		ShadowMode: shadowMode,
	}
}

func (f *Firewall) effectiveShadowMode(shadowMode *bool) bool {
	if shadowMode != nil {
		return *shadowMode
	}
	return f.shadowMode
}

func (f *Firewall) fireClassifyEvent(event ClassifyEvent) {
	if f.onClassify != nil {
		safeClassifyCallback(f.onClassify, event)
	}
}

func safeClassifyCallback(fn func(ClassifyEvent), event ClassifyEvent) {
	defer func() {
		_ = recover()
	}()
	fn(event)
}

func firewallBlockedErrorFromEvent(event ClassifyEvent) *FirewallBlockedError {
	return &FirewallBlockedError{
		Score:      event.Result.Score,
		Threshold:  event.Result.Threshold,
		PromptText: event.Text,
		Hook:       event.Hook,
		ToolName:   event.ToolName,
		Result:     event.Result,
	}
}

func batchHookAt(cfg batchClassifyConfig, index int) HookLabel {
	if len(cfg.hooks) == 0 {
		return HookUnknown
	}
	if cfg.hooks[index] == "" {
		return HookUnknown
	}
	return cfg.hooks[index]
}

func batchToolNameAt(cfg batchClassifyConfig, index int) string {
	if len(cfg.toolNames) == 0 {
		return ""
	}
	return cfg.toolNames[index]
}

func repeatHooks(hook HookLabel, n int) []HookLabel {
	hooks := make([]HookLabel, n)
	for i := range hooks {
		hooks[i] = hook
	}
	return hooks
}

func repeatToolNames(toolName string, n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = toolName
	}
	return names
}

func batchToolNames(names []string) []*string {
	out := make([]*string, len(names))
	for i, name := range names {
		if name == "" {
			continue
		}
		name := name
		out[i] = &name
	}
	return out
}

func batchMetadata(cfg batchClassifyConfig, length int) ([]*ClassificationMetadata, error) {
	out := make([]*ClassificationMetadata, length)
	for i := 0; i < length; i++ {
		var item *ClassificationMetadata
		if cfg.metadataSet && cfg.metadata[i] != nil {
			item = &cfg.metadata[i]
		}
		metadata, err := sdkMetadata(item, cfg.requestID, &i)
		if err != nil {
			return nil, err
		}
		out[i] = metadata
	}
	return out, nil
}

func blockResultFromResponse(resp singleResponse) (BlockResult, error) {
	switch resp.Prediction {
	case PredictionBenign, PredictionMalicious:
	default:
		return BlockResult{}, fmt.Errorf("firewall: invalid prediction %q", resp.Prediction)
	}
	var primary PrimaryOutcome
	if resp.PrimaryOutcome != nil {
		normalized, err := normalizePrimaryOutcome(*resp.PrimaryOutcome, "primary_outcome")
		if err != nil {
			return BlockResult{}, err
		}
		primary = normalized
	}
	outcomeScores, err := normalizeHarmfulOutcomeFloatMap(resp.OutcomeScores, "outcome_scores")
	if err != nil {
		return BlockResult{}, err
	}
	detectorScores, err := normalizeHarmfulOutcomeFloatMap(resp.DetectorScores, "detector_scores")
	if err != nil {
		return BlockResult{}, err
	}
	detectorCounts, err := normalizeHarmfulOutcomeIntMap(resp.DetectorCounts, "detector_counts")
	if err != nil {
		return BlockResult{}, err
	}
	return BlockResult{
		Prediction:     resp.Prediction,
		Score:          resp.Score,
		Threshold:      resp.Threshold,
		PrimaryOutcome: primary,
		OutcomeScores:  outcomeScores,
		DetectorScores: detectorScores,
		DetectorCounts: detectorCounts,
	}, nil
}
