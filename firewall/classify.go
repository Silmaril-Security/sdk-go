// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

type singleRequestPayload struct {
	Text      string                  `json:"text"`
	Hook      HookLabel               `json:"hook,omitempty"`
	ToolName  string                  `json:"tool_name,omitempty"`
	Metadata  *ClassificationMetadata `json:"metadata,omitempty"`
	Threshold float64                 `json:"threshold"`
}

type batchRequestPayload struct {
	Texts     []string                  `json:"texts"`
	Hooks     []HookLabel               `json:"hooks,omitempty"`
	ToolNames []*string                 `json:"tool_names,omitempty"`
	Metadata  []*ClassificationMetadata `json:"metadata,omitempty"`
	Threshold float64                   `json:"threshold"`
}

type singleResponse struct {
	Prediction     Prediction         `json:"prediction"`
	Score          float64            `json:"score"`
	PrimaryOutcome string             `json:"primary_outcome"`
	OutcomeScores  map[string]float64 `json:"outcome_scores"`
	DetectorScores map[string]float64 `json:"detector_scores"`
	DetectorCounts map[string]int     `json:"detector_counts"`
}

type batchResponse struct {
	Predictions []singleResponse `json:"predictions"`
}

// Classify classifies a single text. Long inputs are chunked client-side and
// fanned out as bounded parallel single-text requests; the highest score across
// chunks is returned.
func (f *Firewall) Classify(ctx context.Context, text string, opts ...ClassifyOption) (BlockResult, error) {
	var cfg classifyConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	text = sanitizeText(text)
	result, err := f.classifyRaw(ctx, text, cfg)
	if err != nil {
		return BlockResult{}, err
	}
	event := f.newClassifyEvent(text, cfg.hook, cfg.toolName, result, f.effectiveShadowMode(cfg.shadowMode))
	f.fireClassifyEvent(event)
	if event.Blocked && !event.ShadowMode {
		return result, promptBlockedErrorFromEvent(event)
	}
	return result, nil
}

func (f *Firewall) classifyRaw(ctx context.Context, text string, cfg classifyConfig) (BlockResult, error) {
	chunks, err := ChunkText(text)
	if err != nil {
		return BlockResult{}, err
	}
	threshold := adaptiveThreshold(len(chunks))
	if len(chunks) == 1 {
		return f.classifySingleRaw(ctx, chunks[0], cfg, threshold)
	}
	results, err := f.classifyChunksRaw(ctx, chunks, cfg, threshold)
	if err != nil {
		return BlockResult{}, err
	}
	best := results[0]
	for _, r := range results[1:] {
		if r.Score > best.Score {
			best = r
		}
	}
	return best, nil
}

func (f *Firewall) classifySingleRaw(ctx context.Context, text string, cfg classifyConfig, threshold float64) (BlockResult, error) {
	payload := singleRequestPayload{
		Text:      text,
		Threshold: threshold,
	}
	if cfg.hook != "" {
		payload.Hook = cfg.hook
	}
	if cfg.toolName != "" {
		payload.ToolName = cfg.toolName
	}
	if cfg.metadata != nil {
		payload.Metadata = cfg.metadata
	}
	var resp singleResponse
	if err := f.postJSON(ctx, payload, &resp); err != nil {
		return BlockResult{}, err
	}
	return blockResultFromResponse(resp, threshold)
}

func (f *Firewall) classifyChunksRaw(ctx context.Context, chunks []string, cfg classifyConfig, threshold float64) ([]BlockResult, error) {
	workers := f.chunkConcurrency
	if workers > len(chunks) {
		workers = len(chunks)
	}
	results := make([]BlockResult, len(chunks))
	jobs := make(chan int)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				result, err := f.classifySingleRaw(ctx, chunks[index], cfg, threshold)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					continue
				}
				results[index] = result
			}
		}()
	}

	for i := range chunks {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return results, nil
}

// ClassifyBatch classifies multiple independent texts in a single request.
// When hooks or toolNames are provided, their length must equal len(texts).
func (f *Firewall) ClassifyBatch(ctx context.Context, texts []string, opts ...BatchClassifyOption) ([]BlockResult, error) {
	var cfg batchClassifyConfig
	for _, opt := range opts {
		opt(&cfg)
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
		return results, &BatchPromptBlockedError{Blocked: blocked}
	}
	return results, nil
}

func (f *Firewall) classifyBatchRaw(ctx context.Context, texts []string, cfg batchClassifyConfig) ([]BlockResult, error) {
	texts = sanitizeTexts(texts)
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
	threshold := adaptiveThreshold(len(texts))
	payload := batchRequestPayload{
		Texts:     texts,
		Threshold: threshold,
	}
	if len(cfg.hooks) > 0 {
		payload.Hooks = cfg.hooks
	}
	if len(cfg.toolNames) > 0 {
		payload.ToolNames = batchToolNames(cfg.toolNames)
	}
	if cfg.metadataSet {
		payload.Metadata = batchMetadata(cfg.metadata)
	}
	var resp batchResponse
	if err := f.postJSON(ctx, payload, &resp); err != nil {
		return nil, err
	}
	if len(resp.Predictions) != len(texts) {
		return nil, fmt.Errorf("firewall: predictions length %d does not match texts length %d", len(resp.Predictions), len(texts))
	}
	results := make([]BlockResult, len(resp.Predictions))
	for i, p := range resp.Predictions {
		result, err := blockResultFromResponse(p, threshold)
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
		Blocked:    result.Score >= result.Threshold,
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

func promptBlockedErrorFromEvent(event ClassifyEvent) *PromptBlockedError {
	return &PromptBlockedError{
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

func batchMetadata(metadata []ClassificationMetadata) []*ClassificationMetadata {
	out := make([]*ClassificationMetadata, len(metadata))
	for i, item := range metadata {
		if item == nil {
			continue
		}
		item := item
		out[i] = &item
	}
	return out
}

func blockResultFromResponse(resp singleResponse, threshold float64) (BlockResult, error) {
	switch resp.Prediction {
	case PredictionBenign, PredictionMalicious:
	case "":
		resp.Prediction = predictionForScore(resp.Score, threshold)
	default:
		return BlockResult{}, fmt.Errorf("firewall: invalid prediction %q", resp.Prediction)
	}
	return BlockResult{
		Prediction:     resp.Prediction,
		Score:          resp.Score,
		Threshold:      threshold,
		PrimaryOutcome: resp.PrimaryOutcome,
		OutcomeScores:  resp.OutcomeScores,
		DetectorScores: resp.DetectorScores,
		DetectorCounts: resp.DetectorCounts,
	}, nil
}

func predictionForScore(score, threshold float64) Prediction {
	if score >= threshold {
		return PredictionMalicious
	}
	return PredictionBenign
}
