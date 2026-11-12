// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

// Protect runs operation while text is classified, instead of waiting for
// the verdict first. It accepts the same options as Classify.
//
// In Block mode, including the Block default when no mode is set, the result
// is withheld until the verdict arrives. A blocking decision returns
// FirewallBlockedError and cancels the context passed to operation, so an
// operation that honors its context stops early. Protect waits for operation
// to return before it reports the block. When ctx is done, Protect stops
// waiting for its turn in the queue and returns the context's error. In Shadow and Warn the result is
// returned as soon as operation finishes and the classification completes in
// the background; call Flush to wait for it.
//
// Use Protect only for an operation whose effect can be discarded. Classify
// the arguments of a tool that writes with Classify before running it.
func Protect[T any](
	ctx context.Context,
	f *Firewall,
	text string,
	operation func(context.Context) (T, error),
	opts ...ClassifyOption,
) (T, error) {
	return ProtectWithOutput(ctx, f, text, operation, nil, opts...)
}

// ProtectWithOutput is Protect with a second check: output extracts the text
// of a successful result, which is classified as HookLLMOutput before the
// result is returned. A nil output skips that check.
func ProtectWithOutput[T any](
	ctx context.Context,
	f *Firewall,
	text string,
	operation func(context.Context) (T, error),
	output func(T) string,
	opts ...ClassifyOption,
) (T, error) {
	var zero T
	input, err := snapshotClassifyConfig(newClassifyConfig(opts))
	if err != nil {
		return zero, err
	}
	mode, err := f.effectiveMode(input.mode, input.shadowMode)
	if err != nil {
		return zero, err
	}
	conversation := conversationID(input.metadata)
	generated := classifyConfig{
		hook:       HookLLMOutput,
		metadata:   input.metadata,
		mode:       input.mode,
		shadowMode: input.shadowMode,
		review:     input.review,
	}

	if mode == ModeShadow || mode == ModeWarn {
		background := withBackgroundRetries(context.WithoutCancel(ctx))
		f.pending.submit(background, conversation, true, func(ctx context.Context) (BlockResult, error) {
			return f.classifyConfigured(ctx, text, input)
		})
		result, err := operation(ctx)
		if err != nil {
			return zero, err
		}
		if output != nil {
			generatedText := output(result)
			f.pending.submit(background, conversation, true, func(ctx context.Context) (BlockResult, error) {
				return f.classifyConfigured(ctx, generatedText, generated)
			})
		}
		return result, nil
	}

	operationCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	pending := f.pending.submit(ctx, conversation, false, func(ctx context.Context) (BlockResult, error) {
		return f.classifyConfigured(ctx, text, input)
	})
	go func() {
		<-pending.done
		if pending.err != nil {
			cancel(pending.err)
		}
	}()
	result, operationErr := operation(operationCtx)
	<-pending.done
	if pending.err != nil {
		return zero, pending.err
	}
	if operationErr != nil {
		return zero, operationErr
	}
	if output != nil {
		generatedText := output(result)
		checked := f.pending.submit(ctx, conversation, false, func(ctx context.Context) (BlockResult, error) {
			return f.classifyConfigured(ctx, generatedText, generated)
		})
		<-checked.done
		if checked.err != nil {
			return zero, checked.err
		}
	}
	return result, nil
}

// snapshotClassifyConfig detaches a request from caller-owned metadata and
// governance values, so a classification that outlives Protect never reads
// data its caller may reuse.
func snapshotClassifyConfig(cfg classifyConfig) (classifyConfig, error) {
	if cfg.metadata != nil {
		encoded, err := json.Marshal(*cfg.metadata)
		if err != nil {
			return classifyConfig{}, fmt.Errorf("firewall: marshal metadata: %w", err)
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.UseNumber()
		var metadata ClassificationMetadata
		if err := decoder.Decode(&metadata); err != nil {
			return classifyConfig{}, fmt.Errorf("firewall: copy metadata: %w", err)
		}
		cfg.metadata = &metadata
	}
	if cfg.governance != nil {
		governance := *cfg.governance
		if governance.Resource != nil {
			resource := *governance.Resource
			governance.Resource = &resource
		}
		cfg.governance = &governance
	}
	return cfg, nil
}

// Flush waits for classifications that Protect left running in the
// background, or until ctx is done.
func (f *Firewall) Flush(ctx context.Context) error {
	return f.pending.drain(ctx)
}

func conversationID(metadata *ClassificationMetadata) string {
	if metadata == nil {
		return ""
	}
	id, _ := (*metadata)["conversationId"].(string)
	return id
}
