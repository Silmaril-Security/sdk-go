// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"net/http"
	"time"
)

// Action is the enforcement decision for a single text. It is binary: the SDK
// reports every wire value other than "allow" as ActionBlock.
type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
)

// Confidence is how confident the Firewall's assessment of a blocked item is,
// on a closed scale ordered from ConfidenceVeryLow to ConfidenceVeryHigh.
type Confidence string

const (
	ConfidenceVeryLow  Confidence = "very_low"
	ConfidenceLow      Confidence = "low"
	ConfidenceMedium   Confidence = "medium"
	ConfidenceHigh     Confidence = "high"
	ConfidenceVeryHigh Confidence = "very_high"
)

// Severity is how severe the Firewall's assessment rates a blocked item, on a
// closed scale ordered from SeverityMinimal to SeverityCritical.
type Severity string

const (
	SeverityMinimal  Severity = "minimal"
	SeverityLow      Severity = "low"
	SeverityModerate Severity = "moderate"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Sources the Firewall reports for a block. BlockResult.Source is an open
// string, so later runtimes may report others.
const (
	SourceModel      = "model"
	SourceGovernance = "governance"
)

// FirewallMode controls how a blocking decision affects the caller.
type FirewallMode string

const (
	ModeShadow FirewallMode = "shadow"
	ModeWarn   FirewallMode = "warn"
	ModeBlock  FirewallMode = "block"
)

// ReviewLevel selects whether this request uses the optional large-judge stage.
// Exact values are "standard" and "deep". An omitted selection leaves the
// selected tenant/surface AppConfig threat_judge.enabled in control; the SDK
// never fills an implicit default.
type ReviewLevel string

const (
	ReviewStandard ReviewLevel = "standard"
	ReviewDeep     ReviewLevel = "deep"
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
	Action           GovernanceAction    `json:"action"`
	PolicyVersion    string              `json:"policy_version"`
	RuleID           string              `json:"rule_id,omitempty"`
	Resource         *GovernanceResource `json:"resource,omitempty"`
	IdentityRevision string              `json:"identity_revision,omitempty"`
	Reason           string              `json:"reason,omitempty"`
}

// BlockResult is the decision for a single classified text. Action is the only
// field the SDK enforces on; the others are evidence.
type BlockResult struct {
	Action Action `json:"action"`
	// Source names what decided a block. Empty on an allow.
	Source string `json:"source,omitempty"`
	// Confidence and Severity describe the Firewall's assessment of the item
	// and are set only when that assessment is the reason for the block. They
	// are empty on an allow, on a block that came from a governance policy, on
	// a block the Firewall reached without that assessment, and against a
	// runtime without /v2/classify.
	Confidence Confidence `json:"confidence,omitempty"`
	Severity   Severity   `json:"severity,omitempty"`
	// Outcome is the predicted harm on a model block that has one.
	Outcome    HarmfulOutcome      `json:"outcome,omitempty"`
	Governance *GovernanceDecision `json:"governance,omitempty"`
	// ModelID identifies the model release that classified the item, for
	// provenance. Empty when the runtime reports none.
	ModelID string `json:"model_id,omitempty"`
	// Review is the acknowledged explicit request setting after a successful
	// call, not evidence that the large-judge stage ran. Empty when review was
	// omitted on the request.
	Review ReviewLevel `json:"review,omitempty"`
	// Mode is empty when no client or per-call mode was set and the response
	// carries none.
	Mode FirewallMode `json:"mode,omitempty"`
}

// ClassificationMetadata carries caller-provided request metadata alongside
// the classified text without embedding it in the text itself.
type ClassificationMetadata map[string]any

// Options configures a Firewall client. APIKey and APIURL are required. APIURL
// may be the deployment base or its /classify or /v2/classify endpoint.
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
	// Review is an optional client default of "standard" or "deep". Empty
	// omits the wire field so the backend AppConfig remains authoritative.
	Review ReviewLevel
	// MaxConcurrent bounds classifications that Protect runs beside the
	// caller at one time. Zero selects the default of 32.
	MaxConcurrent int
	// MaxQueued bounds unjoined background classifications kept for one
	// conversation; further ones are dropped. Zero selects the default of 64.
	// Across all conversations, including calls with no conversation, the
	// client keeps at most MaxConcurrent times MaxQueued of them.
	MaxQueued int
}

type classifyConfig struct {
	hook       HookLabel
	toolName   string
	metadata   *ClassificationMetadata
	mode       *FirewallMode
	shadowMode *bool
	requestID  string
	governance *GovernanceContext
	review     *ReviewLevel
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
// principal authentication and policy decisions. Do not mutate the context or
// its resource while the Classify call is in flight.
func WithGovernance(context GovernanceContext) ClassifyOption {
	return func(c *classifyConfig) { c.governance = &context }
}

// WithMode sets the locally authoritative mode for a single Classify call.
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

// WithReview sets the review level for a single Classify call. An empty value
// is an error; it does not omit the field or restore server AppConfig control.
func WithReview(review ReviewLevel) ClassifyOption {
	return func(c *classifyConfig) { c.review = &review }
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
	review      *ReviewLevel
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
// A nil metadata entry contributes no caller fields; metadata.silmaril still
// contains SDK-owned provenance for that batch item. Do not mutate the slice
// or its maps while that ClassifyBatch call is in flight.
func WithBatchMetadata(metadata []ClassificationMetadata) BatchClassifyOption {
	return func(c *batchClassifyConfig) {
		c.metadata = metadata
		c.metadataSet = true
	}
}

// WithBatchGovernance supplies one optional governance context per input.
// Do not mutate the slice, its contexts, or their resources while the
// ClassifyBatch call is in flight.
func WithBatchGovernance(contexts []*GovernanceContext) BatchClassifyOption {
	return func(c *batchClassifyConfig) { c.governance = contexts }
}

// WithBatchMode sets the locally authoritative mode for one ClassifyBatch call.
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

// WithBatchReview sets the review level for one ClassifyBatch call. An empty
// value is an error; it does not omit the field or restore server AppConfig
// control.
func WithBatchReview(review ReviewLevel) BatchClassifyOption {
	return func(c *batchClassifyConfig) { c.review = &review }
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
