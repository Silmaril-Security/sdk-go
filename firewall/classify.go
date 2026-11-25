// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

type singleRequestPayload struct {
	Resource *GovernanceResource     `json:"resource,omitempty"`
	Text     string                  `json:"text"`
	Mode     FirewallMode            `json:"mode,omitempty"`
	Hook     HookLabel               `json:"hook,omitempty"`
	ToolName string                  `json:"tool_name,omitempty"`
	Metadata *ClassificationMetadata `json:"metadata,omitempty"`
	Review   *ReviewLevel            `json:"review,omitempty"`
}

type batchRequestPayload struct {
	Resources []*GovernanceResource     `json:"resources,omitempty"`
	Texts     []string                  `json:"texts"`
	Mode      FirewallMode              `json:"mode,omitempty"`
	Hooks     []HookLabel               `json:"hooks,omitempty"`
	ToolNames []*string                 `json:"tool_names,omitempty"`
	Metadata  []*ClassificationMetadata `json:"metadata,omitempty"`
	Review    *ReviewLevel              `json:"review,omitempty"`
}

type classifyResponse struct {
	current *decisionResponse
	legacy  legacyResponse
}

// UnmarshalJSON reads a body with a results key as version 2 and any other
// body as version 1, whichever path returned it.
func (r *classifyResponse) UnmarshalJSON(data []byte) error {
	var shape struct {
		Results json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(data, &shape); err != nil {
		return err
	}
	if shape.Results == nil {
		return json.Unmarshal(data, &r.legacy)
	}
	r.current = &decisionResponse{}
	return json.Unmarshal(data, r.current)
}

func (r classifyResponse) decisions(batch bool) (decisionResponse, error) {
	if r.current != nil {
		return *r.current, nil
	}
	return r.legacy.decisions(batch)
}

type decisionResponse struct {
	Results []decision `json:"results"`
	Review  any        `json:"review"`
}

type decision struct {
	Action     Action              `json:"action"`
	Source     string              `json:"source"`
	Confidence Confidence          `json:"confidence"`
	Severity   Severity            `json:"severity"`
	Outcome    HarmfulOutcome      `json:"outcome"`
	Governance *responseGovernance `json:"governance"`
	ModelID    string              `json:"model_id"`
	mode       FirewallMode
}

// responseGovernance decodes a returned governance decision and rejects
// evidence the public type cannot distinguish from absent: a blank
// identity_revision or reason, and an empty parent_id outside mcp_tool.
type responseGovernance GovernanceDecision

func (g *responseGovernance) UnmarshalJSON(data []byte) error {
	var evidence struct {
		IdentityRevision *string `json:"identity_revision"`
		Reason           *string `json:"reason"`
		Resource         *struct {
			Kind     GovernanceResourceKind `json:"kind"`
			ParentID *string                `json:"parent_id"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(data, &evidence); err != nil {
		return err
	}
	if evidence.IdentityRevision != nil && isPythonBlank(*evidence.IdentityRevision) {
		return errors.New("firewall: response governance identity_revision must be null, omitted, or a non-blank string")
	}
	if evidence.Reason != nil && isPythonBlank(*evidence.Reason) {
		return errors.New("firewall: response governance reason must be null, omitted, or a non-blank string")
	}
	if resource := evidence.Resource; resource != nil && resource.Kind != GovernanceMCPTool && resource.ParentID != nil && *resource.ParentID == "" {
		return errors.New("firewall: response governance resource parent_id must be null or omitted for non-mcp_tool")
	}
	return json.Unmarshal(data, (*GovernanceDecision)(g))
}

func isPythonBlank(value string) bool {
	return strings.TrimFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || r >= '\u001c' && r <= '\u001f'
	}) == ""
}

const (
	legacyBenign    = "BENIGN"
	legacyMalicious = "MALICIOUS"
)

type legacyResponse struct {
	legacyVerdict
	Predictions []legacyVerdict `json:"predictions"`
	Review      any             `json:"review"`
}

type legacyVerdict struct {
	Prediction      string                     `json:"prediction"`
	ModelPrediction string                     `json:"model_prediction"`
	Mode            FirewallMode               `json:"mode"`
	PrimaryOutcome  HarmfulOutcome             `json:"primary_outcome"`
	OutcomeScores   map[string]json.RawMessage `json:"outcome_scores"`
	Governance      *responseGovernance        `json:"governance"`
	ModelID         string                     `json:"model_id"`
}

func (r legacyResponse) decisions(batch bool) (decisionResponse, error) {
	verdicts := []legacyVerdict{r.legacyVerdict}
	if batch {
		verdicts = r.Predictions
	}
	adapted := decisionResponse{Results: make([]decision, len(verdicts)), Review: r.Review}
	for i, verdict := range verdicts {
		result, err := verdict.adapted()
		if err != nil {
			return decisionResponse{}, err
		}
		adapted.Results[i] = result
	}
	return adapted, nil
}

func (v legacyVerdict) adapted() (decision, error) {
	if v.Prediction != legacyBenign && v.Prediction != legacyMalicious {
		return decision{}, fmt.Errorf("firewall: invalid prediction %q", v.Prediction)
	}
	if validateMode(v.Mode) != nil {
		return decision{}, fmt.Errorf("firewall: invalid backend mode %q", v.Mode)
	}
	adapted := decision{Action: ActionAllow, Governance: v.Governance, ModelID: v.ModelID, mode: v.Mode}
	if v.Prediction != legacyMalicious && (v.Governance == nil || v.Governance.Action != GovernanceBlock) {
		return adapted, nil
	}
	adapted.Action, adapted.Source = ActionBlock, SourceGovernance
	modelLabel := v.ModelPrediction
	if modelLabel == "" {
		modelLabel = v.Prediction
	}
	if modelLabel == legacyMalicious {
		adapted.Source = SourceModel
		if len(v.OutcomeScores) > 0 {
			adapted.Outcome = v.PrimaryOutcome
		}
	}
	return adapted, nil
}

// Classify classifies one complete logical event in a single request.
func (f *Firewall) Classify(ctx context.Context, text string, opts ...ClassifyOption) (BlockResult, error) {
	return f.classifyConfigured(ctx, text, newClassifyConfig(opts))
}

func newClassifyConfig(opts []ClassifyOption) classifyConfig {
	var cfg classifyConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

func (f *Firewall) classifyConfigured(ctx context.Context, text string, cfg classifyConfig) (BlockResult, error) {
	if cfg.requestID == "" {
		cfg.requestID = newRequestID()
	}
	text = sanitizeText(text)
	mode, err := f.effectiveMode(cfg.mode, cfg.shadowMode)
	if err != nil {
		return BlockResult{}, err
	}
	cfg.mode = &mode
	review, err := f.effectiveReview(cfg.review)
	if err != nil {
		return BlockResult{}, err
	}
	cfg.review = review
	result, err := f.classifySingleRaw(ctx, text, cfg)
	if err != nil {
		return BlockResult{}, err
	}
	event := f.newClassifyEvent(text, cfg.hook, cfg.toolName, result)
	f.fireClassifyEvent(event)
	if event.Blocked && event.Mode == ModeBlock {
		return result, firewallBlockedErrorFromEvent(event)
	}
	return result, nil
}

func requestGovernanceResource(context *GovernanceContext) (*GovernanceResource, error) {
	if context == nil || context.Resource == nil {
		return nil, nil
	}
	resource := *context.Resource
	if err := validateGovernanceResource(resource); err != nil {
		return nil, fmt.Errorf("firewall: %w", err)
	}
	return &resource, nil
}

func validateGovernanceResource(resource GovernanceResource) error {
	switch resource.Kind {
	case GovernanceAgent, GovernanceTool, GovernanceMCPServer, GovernanceMCPTool, GovernancePlugin, GovernanceSkill, GovernanceExtension:
	default:
		return errors.New("invalid governance resource kind")
	}
	if strings.TrimSpace(resource.ID) == "" {
		return errors.New("governance resource id must be non-empty")
	}
	if resource.Kind == GovernanceMCPTool {
		if strings.TrimSpace(resource.ParentID) == "" {
			return errors.New("mcp_tool requires a non-empty parent_id")
		}
	} else if resource.ParentID != "" {
		return errors.New("parent_id is valid only for mcp_tool")
	}
	return nil
}

func (f *Firewall) classifySingleRaw(ctx context.Context, text string, cfg classifyConfig) (BlockResult, error) {
	metadata, err := sdkMetadata(cfg.metadata, cfg.requestID, nil)
	if err != nil {
		return BlockResult{}, err
	}
	resource, err := requestGovernanceResource(cfg.governance)
	if err != nil {
		return BlockResult{}, err
	}
	setGovernanceMetadata(metadata, cfg.governance)
	payload := singleRequestPayload{
		Resource: resource,
		Text:     text,
		Metadata: metadata,
	}
	if cfg.mode != nil {
		payload.Mode = *cfg.mode
	}
	if cfg.hook != "" {
		payload.Hook = cfg.hook
	}
	if cfg.toolName != "" {
		payload.ToolName = cfg.toolName
	}
	payload.Review = cfg.review
	results, err := f.decide(ctx, payload, false, 1, payload.Mode, cfg.review)
	if err != nil {
		return BlockResult{}, err
	}
	return results[0], nil
}

func blockResults(resp decisionResponse, inputs int, requestedMode FirewallMode, review *ReviewLevel) ([]BlockResult, error) {
	if err := verifyReviewAcknowledgement(review, resp.Review); err != nil {
		return nil, err
	}
	if len(resp.Results) != inputs {
		return nil, fmt.Errorf("firewall: results length %d does not match texts length %d", len(resp.Results), inputs)
	}
	results := make([]BlockResult, inputs)
	for i, item := range resp.Results {
		result, err := blockResultFromDecision(item, requestedMode)
		if err != nil {
			return nil, err
		}
		if review != nil {
			result.Review = *review
		}
		results[i] = result
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
	if cfg.requestID == "" {
		cfg.requestID = newRequestID()
	}
	texts = sanitizeTexts(texts)
	mode, err := f.effectiveMode(cfg.mode, cfg.shadowMode)
	if err != nil {
		return nil, err
	}
	cfg.mode = &mode
	review, err := f.effectiveReview(cfg.review)
	if err != nil {
		return nil, err
	}
	cfg.review = review
	results, err := f.classifyBatchRaw(ctx, texts, cfg)
	if err != nil {
		return nil, err
	}
	blocked := make([]BlockedBatchItem, 0)
	for i, result := range results {
		event := f.newClassifyEvent(texts[i], batchHookAt(cfg, i), batchToolNameAt(cfg, i), result)
		f.fireClassifyEvent(event)
		if event.Blocked && event.Mode == ModeBlock {
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
	if cfg.governance != nil && len(cfg.governance) != len(texts) {
		return nil, fmt.Errorf("firewall: governance length %d does not match texts length %d", len(cfg.governance), len(texts))
	}
	payload := batchRequestPayload{
		Texts: texts,
	}
	if cfg.mode != nil {
		payload.Mode = *cfg.mode
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
	payload.Review = cfg.review
	if cfg.governance != nil {
		payload.Resources = make([]*GovernanceResource, len(texts))
		for i, context := range cfg.governance {
			resource, err := requestGovernanceResource(context)
			if err != nil {
				return nil, err
			}
			payload.Resources[i] = resource
		}
	}
	return f.decide(ctx, payload, true, len(texts), payload.Mode, cfg.review)
}

func (f *Firewall) newClassifyEvent(text string, hook HookLabel, toolName string, result BlockResult) ClassifyEvent {
	if hook == "" {
		hook = HookUnknown
	}
	effectiveMode := result.Mode
	if effectiveMode == "" {
		// Preserve the pre-0.6 direct-SDK default without claiming that a
		// mode-less legacy response was a backend Block decision.
		effectiveMode = ModeBlock
	}
	return ClassifyEvent{
		Hook:       hook,
		ToolName:   toolName,
		Text:       text,
		Result:     result,
		Blocked:    result.Action != ActionAllow,
		Mode:       effectiveMode,
		ShadowMode: effectiveMode == ModeShadow,
	}
}

func validateMode(mode FirewallMode) error {
	switch mode {
	case "", ModeShadow, ModeWarn, ModeBlock:
		return nil
	default:
		return fmt.Errorf("firewall: mode must be shadow, warn, or block, got %q", mode)
	}
}

func validateReview(review ReviewLevel) error {
	switch review {
	case ReviewStandard, ReviewDeep:
		return nil
	default:
		return fmt.Errorf("firewall: review must be standard or deep, got %q", review)
	}
}

func (f *Firewall) effectiveReview(review *ReviewLevel) (*ReviewLevel, error) {
	if review != nil {
		if err := validateReview(*review); err != nil {
			return nil, err
		}
		selected := *review
		return &selected, nil
	}
	if f.review == "" {
		return nil, nil
	}
	selected := f.review
	return &selected, nil
}

func verifyReviewAcknowledgement(requested *ReviewLevel, acknowledged any) error {
	if requested == nil {
		return nil
	}
	got, ok := acknowledged.(string)
	if ok && ReviewLevel(got) == *requested {
		return nil
	}
	var echoed ReviewLevel
	if ok {
		echoed = ReviewLevel(got)
	}
	return &ReviewCompatibilityError{Requested: *requested, Acknowledged: echoed}
}

func legacyMode(shadowMode bool) FirewallMode {
	if shadowMode {
		return ModeShadow
	}
	return ModeBlock
}

func (f *Firewall) effectiveMode(mode *FirewallMode, shadowMode *bool) (FirewallMode, error) {
	if mode != nil {
		if err := validateMode(*mode); err != nil {
			return "", err
		}
		return *mode, nil
	}
	if shadowMode != nil {
		return legacyMode(*shadowMode), nil
	}
	return f.mode, nil
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
		if cfg.governance != nil {
			setGovernanceMetadata(metadata, cfg.governance[i])
		}
		out[i] = metadata
	}
	return out, nil
}

func blockResultFromDecision(item decision, requestedMode FirewallMode) (BlockResult, error) {
	if item.Action == "" {
		return BlockResult{}, errors.New("firewall: response action must be a non-empty string")
	}
	if item.Governance != nil {
		if item.Governance.Action != GovernanceAllow && item.Governance.Action != GovernanceBlock {
			return BlockResult{}, fmt.Errorf("firewall: response governance action must be allow or block")
		}
		if item.Governance.PolicyVersion == "" {
			return BlockResult{}, fmt.Errorf("firewall: response governance policy_version must be non-empty")
		}
		if item.Governance.Resource != nil {
			if err := validateGovernanceResource(*item.Governance.Resource); err != nil {
				return BlockResult{}, fmt.Errorf("firewall: response %w", err)
			}
		}
	}
	action := ActionBlock
	if item.Action == ActionAllow {
		action = ActionAllow
	}
	mode := item.mode
	if requestedMode != "" {
		// A supplied mode is the per-request override contract. Prefer it
		// during rolling upgrades so a missing or stale response field cannot
		// strengthen enforcement beyond what the caller requested.
		mode = requestedMode
	}
	return BlockResult{
		Action:     action,
		Source:     item.Source,
		Confidence: item.Confidence,
		Severity:   item.Severity,
		Outcome:    item.Outcome,
		Governance: (*GovernanceDecision)(item.Governance),
		ModelID:    item.ModelID,
		Mode:       mode,
	}, nil
}
