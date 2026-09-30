// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"net/http"
	"time"
)

// Prediction is the classifier's verdict for a single text.
type Prediction string

const (
	PredictionBenign    Prediction = "BENIGN"
	PredictionMalicious Prediction = "MALICIOUS"
)

// FirewallMode controls how a malicious decision affects the caller.
type FirewallMode string

const (
	ModeShadow FirewallMode = "shadow"
	ModeWarn   FirewallMode = "warn"
	ModeBlock  FirewallMode = "block"
)

type GovernanceAction string

const (
	GovernanceAllow GovernanceAction = "allow"
	GovernanceBlock GovernanceAction = "block"
)

type GovernanceResourceKind string

const (
	GovernanceAgent     GovernanceResourceKind = "agent"
	GovernanceTool      GovernanceResourceKind = "tool"
	GovernanceMCPServer GovernanceResourceKind = "mcp_server"
	GovernanceMCPTool   GovernanceResourceKind = "mcp_tool"
	GovernancePlugin    GovernanceResourceKind = "plugin"
	GovernanceSkill     GovernanceResourceKind = "skill"
	GovernanceExtension GovernanceResourceKind = "extension"
)

type GovernanceResource struct {
	Kind     GovernanceResourceKind `json:"kind"`
	ID       string                 `json:"id,omitempty"`
	ParentID string                 `json:"parent_id,omitempty"`
}

type GovernanceContext struct {
	Agent    string              `json:"agent,omitempty"`
	Resource *GovernanceResource `json:"resource,omitempty"`
}

type GovernanceDecision struct {
	Action        GovernanceAction `json:"action"`
	PolicyVersion string           `json:"policy_version"`
	RuleID        string           `json:"rule_id,omitempty"`
}

// BlockResult is the output of a single classification call.
type BlockResult struct {
	Prediction Prediction `json:"prediction"`
	Score      float64    `json:"score"`
	Threshold  float64    `json:"threshold"`
	// Mode is empty only when a legacy backend omitted mode and no override was requested.
	Mode           FirewallMode               `json:"mode,omitempty"`
	PrimaryOutcome PrimaryOutcome             `json:"primary_outcome,omitempty"`
	OutcomeScores  map[HarmfulOutcome]float64 `json:"outcome_scores,omitempty"`
	DetectorScores map[HarmfulOutcome]float64 `json:"detector_scores,omitempty"`
	DetectorCounts map[HarmfulOutcome]int     `json:"detector_counts,omitempty"`
	Governance     *GovernanceDecision        `json:"governance,omitempty"`
}

// ClassificationMetadata carries caller-provided request metadata alongside
// the classified text without embedding it in the text itself.
type ClassificationMetadata map[string]any

// Options configures a Firewall client. APIKey and APIURL are required.
// Timeout defaults to 10 seconds for the default HTTP client. When HTTPClient
// is set, Timeout is applied only when explicitly non-zero, by cloning the
// provided client. The SDK also installs a no-redirect policy on cloned clients
// whose CheckRedirect is nil; caller-provided redirect policies are preserved.
// A cloned client still shares the caller's Transport; that Transport must be
// safe for concurrent use if the Firewall is shared across goroutines.
type Options struct {
	APIKey     string
	APIURL     string
	Timeout    time.Duration
	HTTPClient *http.Client
	Mode       FirewallMode
	// Deprecated: use ModeShadow or ModeBlock. An explicit Mode takes precedence.
	ShadowMode bool
	// OnClassify is invoked after each classification decision. The callback
	// may run on overlapping Classify/ClassifyBatch calls; callers must
	// synchronize any shared state it touches.
	OnClassify func(ClassifyEvent)
}

type classifyConfig struct {
	hook       HookLabel
	toolName   string
	metadata   *ClassificationMetadata
	mode       *FirewallMode
	shadowMode *bool
	requestID  string
	governance *GovernanceContext
}

// ClassifyOption customizes a single Classify call.
type ClassifyOption func(*classifyConfig)

// WithHook sets the pipeline-stage label for the classified text.
func WithHook(hook HookLabel) ClassifyOption {
	return func(c *classifyConfig) { c.hook = hook }
}

// WithToolName sets the tool name for tool-name-aware classification.
func WithToolName(name string) ClassifyOption {
	return func(c *classifyConfig) { c.toolName = name }
}

// WithMetadata attaches caller-provided metadata to a single Classify request.
// Do not mutate the map while that Classify call is in flight.
func WithMetadata(metadata ClassificationMetadata) ClassifyOption {
	return func(c *classifyConfig) { c.metadata = &metadata }
}

// WithGovernance supplies the resource being evaluated. The server still owns
// principal authentication and policy decisions.
func WithGovernance(context GovernanceContext) ClassifyOption {
	return func(c *classifyConfig) { c.governance = &context }
}

// WithMode overrides the backend-controlled mode for a single Classify call.
func WithMode(mode FirewallMode) ClassifyOption {
	return func(c *classifyConfig) { c.mode = &mode }
}

// WithShadowMode overrides the client-level shadow-mode setting for a single
// Classify call.
func WithShadowMode(enabled bool) ClassifyOption {
	return func(c *classifyConfig) { c.shadowMode = &enabled }
}

// WithRequestID overrides the generated request id in metadata.silmaril.
func WithRequestID(id string) ClassifyOption {
	return func(c *classifyConfig) { c.requestID = id }
}

type batchClassifyConfig struct {
	hooks       []HookLabel
	toolNames   []string
	metadata    []ClassificationMetadata
	metadataSet bool
	mode        *FirewallMode
	shadowMode  *bool
	requestID   string
	governance  []*GovernanceContext
}

// BatchClassifyOption customizes a single ClassifyBatch call.
type BatchClassifyOption func(*batchClassifyConfig)

// WithBatchHooks sets one hook label per text. Length must match texts.
func WithBatchHooks(hooks []HookLabel) BatchClassifyOption {
	return func(c *batchClassifyConfig) { c.hooks = hooks }
}

// WithBatchToolNames sets one tool name per text. Length must match texts.
// An empty string at index i omits the tool_name for that text.
func WithBatchToolNames(names []string) BatchClassifyOption {
	return func(c *batchClassifyConfig) { c.toolNames = names }
}

// WithBatchMetadata sets one metadata object per text. Length must match texts.
// A nil metadata entry is serialized as null for that text. Do not mutate the
// slice or its maps while that ClassifyBatch call is in flight.
func WithBatchMetadata(metadata []ClassificationMetadata) BatchClassifyOption {
	return func(c *batchClassifyConfig) {
		c.metadata = metadata
		c.metadataSet = true
	}
}

// WithBatchGovernance supplies one optional governance context per input.
func WithBatchGovernance(contexts []*GovernanceContext) BatchClassifyOption {
	return func(c *batchClassifyConfig) { c.governance = contexts }
}

// WithBatchMode overrides the backend-controlled mode for one ClassifyBatch call.
func WithBatchMode(mode FirewallMode) BatchClassifyOption {
	return func(c *batchClassifyConfig) { c.mode = &mode }
}

// WithBatchShadowMode overrides the client-level shadow-mode setting for a
// single ClassifyBatch call.
func WithBatchShadowMode(enabled bool) BatchClassifyOption {
	return func(c *batchClassifyConfig) { c.shadowMode = &enabled }
}

// WithBatchRequestID overrides the generated request id in metadata.silmaril.
func WithBatchRequestID(id string) BatchClassifyOption {
	return func(c *batchClassifyConfig) { c.requestID = id }
}

// ClassifyEvent describes a classification decision. It is emitted for both
// enforced and shadow-mode calls.
type ClassifyEvent struct {
	Hook       HookLabel
	ToolName   string
	Text       string
	Result     BlockResult
	Blocked    bool
	Mode       FirewallMode
	ShadowMode bool
}
