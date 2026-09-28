// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Prediction is the classifier's verdict for a single text.
type Prediction string

const (
	PredictionBenign    Prediction = "BENIGN"
	PredictionMalicious Prediction = "MALICIOUS"
)

// FirewallMode controls how a malicious prediction or governance Block
// decision affects the caller.
type FirewallMode string

const (
	ModeShadow FirewallMode = "shadow"
	ModeWarn   FirewallMode = "warn"
	ModeBlock  FirewallMode = "block"
)

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
	// Governance is the policy decision parsed from the classification response.
	// It is nil when the response omits governance.
	Governance *GovernanceDecision `json:"governance,omitempty"`
}

// ResourceKind is the canonical kind of a governance resource identity.
type ResourceKind string

const (
	ResourceKindAgent     ResourceKind = "agent"
	ResourceKindTool      ResourceKind = "tool"
	ResourceKindMCPServer ResourceKind = "mcp_server"
	ResourceKindMCPTool   ResourceKind = "mcp_tool"
	ResourceKindPlugin    ResourceKind = "plugin"
	ResourceKindSkill     ResourceKind = "skill"
	ResourceKindExtension ResourceKind = "extension"
)

// Resource is a caller-supplied canonical governance identity.
// ID is the exact configured or catalog identity. ParentID is required for
// mcp_tool and is otherwise absent. Tool names and metadata stay independent
// of this value.
type Resource struct {
	Kind     ResourceKind `json:"kind"`
	ID       string       `json:"id"`
	ParentID string       `json:"parent_id,omitempty"`
	// parentPresent records a JSON parent_id key so an empty string is distinct
	// from an omitted parent.
	parentPresent bool `json:"-"`
}

// Validate checks the concrete resource reference shape from governance contract 1.0.0.
func (r Resource) Validate() error {
	switch r.Kind {
	case ResourceKindAgent, ResourceKindTool, ResourceKindMCPServer, ResourceKindMCPTool,
		ResourceKindPlugin, ResourceKindSkill, ResourceKindExtension:
	default:
		return fmt.Errorf("firewall: resource kind %q is not supported", r.Kind)
	}
	if err := validateExactIdentity(r.ID, "resource id"); err != nil {
		return err
	}
	if r.Kind == ResourceKindMCPTool {
		if !r.parentPresent && r.ParentID == "" {
			return errors.New("firewall: resource parent_id is required for mcp_tool")
		}
		if err := validateExactIdentity(r.ParentID, "resource parent_id"); err != nil {
			return err
		}
		return nil
	}
	if r.parentPresent || r.ParentID != "" {
		return errors.New("firewall: resource parent_id is only valid for mcp_tool")
	}
	return nil
}

// UnmarshalJSON accepts a resource object with kind, id, and optional parent_id.
func (r *Resource) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return errors.New("firewall: resource must be an object")
	}
	for key := range raw {
		switch key {
		case "kind", "id", "parent_id":
		default:
			return fmt.Errorf("firewall: resource field %q is not supported", key)
		}
	}
	kind, err := requiredJSONString(raw, "kind")
	if err != nil {
		return err
	}
	id, err := requiredJSONString(raw, "id")
	if err != nil {
		return err
	}
	parentID, present, err := optionalJSONString(raw, "parent_id")
	if err != nil {
		return err
	}
	r.Kind = ResourceKind(kind)
	r.ID = id
	r.ParentID = parentID
	r.parentPresent = present
	return nil
}

// GovernanceAction is the policy action on a classification decision.
type GovernanceAction string

const (
	GovernanceActionAllow GovernanceAction = "allow"
	GovernanceActionBlock GovernanceAction = "block"
)

// GovernanceReasonIdentityUnresolved is the only governance reason for an identity failure.
const GovernanceReasonIdentityUnresolved = "identity_unresolved"

// GovernanceDecision is the governance object on a classification response.
// Action and PolicyVersion are required when the object is present.
type GovernanceDecision struct {
	Action           GovernanceAction `json:"action"`
	RuleID           string           `json:"rule_id,omitempty"`
	PolicyVersion    string           `json:"policy_version"`
	Resource         *Resource        `json:"resource,omitempty"`
	IdentityRevision string           `json:"identity_revision,omitempty"`
	Reason           string           `json:"reason,omitempty"`
}

// Validate checks a parsed governance decision.
func (d GovernanceDecision) Validate() error {
	switch d.Action {
	case GovernanceActionAllow, GovernanceActionBlock:
	default:
		return fmt.Errorf("firewall: governance action %q is invalid", d.Action)
	}
	if err := validateExactIdentity(d.PolicyVersion, "governance policy_version"); err != nil {
		return err
	}
	if d.RuleID != "" {
		if err := validateExactIdentity(d.RuleID, "governance rule_id"); err != nil {
			return err
		}
	}
	if d.Resource != nil {
		if err := d.Resource.Validate(); err != nil {
			return err
		}
	}
	if d.IdentityRevision != "" {
		if err := validateExactIdentity(d.IdentityRevision, "governance identity_revision"); err != nil {
			return err
		}
	}
	if d.Reason != "" && d.Reason != GovernanceReasonIdentityUnresolved {
		return fmt.Errorf("firewall: governance reason %q is invalid", d.Reason)
	}
	return nil
}

func validateExactIdentity(value, field string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("firewall: %s must be a nonempty exact identity", field)
	}
	return nil
}

func validateSuppliedIdentityRevision(revision string) error {
	if strings.TrimSpace(revision) == "" {
		return errors.New("firewall: identity_revision must be a nonempty resolver snapshot")
	}
	return nil
}

func validateOptionalIdentityRevision(revision string) error {
	if revision == "" {
		return nil
	}
	return validateSuppliedIdentityRevision(revision)
}

func requiredJSONString(raw map[string]json.RawMessage, key string) (string, error) {
	value, ok := raw[key]
	if !ok || isJSONNull(value) {
		return "", fmt.Errorf("firewall: resource %s is required", key)
	}
	parsed, err := jsonString(value, key)
	if err != nil {
		return "", err
	}
	return parsed, nil
}

func optionalJSONString(raw map[string]json.RawMessage, key string) (string, bool, error) {
	value, ok := raw[key]
	if !ok {
		return "", false, nil
	}
	if isJSONNull(value) {
		return "", true, fmt.Errorf("firewall: resource %s must be a string", key)
	}
	parsed, err := jsonString(value, key)
	if err != nil {
		return "", true, err
	}
	return parsed, true, nil
}

func jsonString(value json.RawMessage, key string) (string, error) {
	var parsed string
	if err := json.Unmarshal(value, &parsed); err != nil {
		return "", fmt.Errorf("firewall: resource %s must be a string", key)
	}
	return parsed, nil
}

func isJSONNull(value json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(value), []byte("null"))
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
	hook                HookLabel
	toolName            string
	metadata            *ClassificationMetadata
	mode                *FirewallMode
	shadowMode          *bool
	requestID           string
	resource            *Resource
	identityRevision    string
	identityRevisionSet bool
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

// WithResource attaches the caller-supplied canonical resource to one Classify request.
// The raw tool name remains the value passed to WithToolName.
func WithResource(resource Resource) ClassifyOption {
	return func(c *classifyConfig) {
		c.resource = cloneResource(&resource)
	}
}

// WithIdentityRevision attaches one resolver snapshot to a Classify request.
func WithIdentityRevision(revision string) ClassifyOption {
	return func(c *classifyConfig) {
		c.identityRevision = revision
		c.identityRevisionSet = true
	}
}

type batchClassifyConfig struct {
	hooks               []HookLabel
	toolNames           []string
	metadata            []ClassificationMetadata
	metadataSet         bool
	mode                *FirewallMode
	shadowMode          *bool
	requestID           string
	resources           []*Resource
	resourcesSet        bool
	identityRevision    string
	identityRevisionSet bool
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

// WithBatchResources attaches one resource reference per text, preserving order.
// A nil reference marks a text with no resource. The slice length must equal len(texts).
func WithBatchResources(resources []*Resource) BatchClassifyOption {
	return func(c *batchClassifyConfig) {
		c.resources = resources
		c.resourcesSet = true
	}
}

// WithBatchIdentityRevision attaches one resolver snapshot to a ClassifyBatch request.
func WithBatchIdentityRevision(revision string) BatchClassifyOption {
	return func(c *batchClassifyConfig) {
		c.identityRevision = revision
		c.identityRevisionSet = true
	}
}

// ClassifyEvent describes a classification decision. It is emitted for both
// enforced and shadow-mode calls.
type ClassifyEvent struct {
	Hook     HookLabel
	ToolName string
	Text     string
	Result   BlockResult
	// Blocked is true for a malicious prediction or governance Block action.
	Blocked    bool
	Mode       FirewallMode
	ShadowMode bool
}
