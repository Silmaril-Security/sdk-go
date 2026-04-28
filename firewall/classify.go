// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"context"
	"errors"
	"fmt"
)

type singleRequestPayload struct {
	Text      string    `json:"text"`
	Hook      HookLabel `json:"hook,omitempty"`
	ToolName  string    `json:"tool_name,omitempty"`
	Threshold float64   `json:"threshold"`
}

type batchRequestPayload struct {
	Texts     []string    `json:"texts"`
	Hooks     []HookLabel `json:"hooks,omitempty"`
	ToolNames []*string   `json:"tool_names,omitempty"`
	Threshold float64     `json:"threshold"`
}

type singleResponse struct {
	Prediction Prediction `json:"prediction"`
	Score      float64    `json:"score"`
}

type batchResponse struct {
	Predictions []singleResponse `json:"predictions"`
}

// Classify classifies a single text. Long inputs are chunked client-side
// and sent as a batch; the highest score across chunks is returned.
func (f *Firewall) Classify(ctx context.Context, text string, opts ...ClassifyOption) (BlockResult, error) {
	var cfg classifyConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	chunks, err := ChunkText(text)
	if err != nil {
		return BlockResult{}, err
	}
	if len(chunks) == 1 {
		threshold := f.effectiveThreshold(cfg.hook)
		payload := singleRequestPayload{
			Text:      chunks[0],
			Threshold: threshold,
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
		return blockResultFromResponse(resp, threshold)
	}
	results, err := f.classifyChunks(ctx, chunks, cfg)
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

func (f *Firewall) classifyChunks(ctx context.Context, chunks []string, cfg classifyConfig) ([]BlockResult, error) {
	batchOpts := make([]BatchClassifyOption, 0, 3)
	if cfg.hook != "" {
		batchOpts = append(batchOpts, WithBatchHooks(repeatHooks(cfg.hook, len(chunks))))
	}
	if cfg.toolName != "" {
		batchOpts = append(batchOpts, WithBatchToolNames(repeatToolNames(cfg.toolName, len(chunks))))
	}
	batchOpts = append(batchOpts, WithBatchThreshold(f.effectiveThreshold(cfg.hook)))
	return f.ClassifyBatch(ctx, chunks, batchOpts...)
}

// ClassifyBatch classifies multiple independent texts in a single request.
// When hooks or toolNames are provided, their length must equal len(texts).
func (f *Firewall) ClassifyBatch(ctx context.Context, texts []string, opts ...BatchClassifyOption) ([]BlockResult, error) {
	var cfg batchClassifyConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if len(texts) == 0 {
		return nil, errors.New("firewall: texts must not be empty")
	}
	if len(cfg.hooks) != 0 && len(cfg.hooks) != len(texts) {
		return nil, fmt.Errorf("firewall: hooks length %d does not match texts length %d", len(cfg.hooks), len(texts))
	}
	if len(cfg.toolNames) != 0 && len(cfg.toolNames) != len(texts) {
		return nil, fmt.Errorf("firewall: toolNames length %d does not match texts length %d", len(cfg.toolNames), len(texts))
	}
	threshold := f.batchThreshold(cfg)
	if !validThreshold(threshold) {
		return nil, fmt.Errorf("firewall: batch threshold must be between 0 and 1, got %v", threshold)
	}
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

func (f *Firewall) batchThreshold(cfg batchClassifyConfig) float64 {
	if cfg.threshold != nil {
		return *cfg.threshold
	}
	if len(cfg.hooks) == 0 {
		return f.threshold
	}
	first := cfg.hooks[0]
	for _, hook := range cfg.hooks[1:] {
		if hook != first {
			return f.threshold
		}
	}
	return f.effectiveThreshold(first)
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

func blockResultFromResponse(resp singleResponse, threshold float64) (BlockResult, error) {
	switch resp.Prediction {
	case PredictionBenign, PredictionMalicious:
	case "":
		resp.Prediction = predictionForScore(resp.Score, threshold)
	default:
		return BlockResult{}, fmt.Errorf("firewall: invalid prediction %q", resp.Prediction)
	}
	return BlockResult{Prediction: resp.Prediction, Score: resp.Score, Threshold: threshold}, nil
}

func predictionForScore(score, threshold float64) Prediction {
	if score >= threshold {
		return PredictionMalicious
	}
	return PredictionBenign
}
