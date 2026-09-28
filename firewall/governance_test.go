// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResourceValidateAcceptsSevenKinds(t *testing.T) {
	kinds := []ResourceKind{
		ResourceKindAgent,
		ResourceKindTool,
		ResourceKindMCPServer,
		ResourceKindMCPTool,
		ResourceKindPlugin,
		ResourceKindSkill,
		ResourceKindExtension,
	}
	if len(kinds) != 7 {
		t.Fatalf("kind count = %d, want 7", len(kinds))
	}
	for _, kind := range kinds {
		resource := Resource{Kind: kind, ID: "Configured_ID"}
		if kind == ResourceKindMCPTool {
			resource.ParentID = "parent-server"
		}
		if err := resource.Validate(); err != nil {
			t.Errorf("%s: %v", kind, err)
		}
	}
}

func TestResourceValidateRejectsInvalidShape(t *testing.T) {
	cases := []struct {
		name     string
		resource Resource
	}{
		{name: "connector", resource: Resource{Kind: "connector", ID: "x"}},
		{name: "endpoint", resource: Resource{Kind: "endpoint", ID: "x"}},
		{name: "kind case", resource: Resource{Kind: "Tool", ID: "x"}},
		{name: "empty id", resource: Resource{Kind: ResourceKindTool, ID: ""}},
		{name: "blank id", resource: Resource{Kind: ResourceKindAgent, ID: " \t"}},
		{name: "tool parent", resource: Resource{Kind: ResourceKindTool, ID: "x", ParentID: "server"}},
		{name: "mcp tool parent missing", resource: Resource{Kind: ResourceKindMCPTool, ID: "search"}},
		{name: "mcp tool blank parent", resource: Resource{Kind: ResourceKindMCPTool, ID: "search", ParentID: " "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.resource.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestResourceJSONKeepsExactIdentity(t *testing.T) {
	resource := Resource{
		Kind:     ResourceKindMCPTool,
		ID:       "Search_Papers",
		ParentID: "Arxiv-MCP-Server",
	}
	encoded, err := json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["kind"] != "mcp_tool" || raw["id"] != "Search_Papers" || raw["parent_id"] != "Arxiv-MCP-Server" {
		t.Fatalf("wire = %#v", raw)
	}
	if _, ok := raw["parentPresent"]; ok {
		t.Fatalf("internal field leaked: %#v", raw)
	}
	var decoded Resource
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	if decoded.ID != resource.ID || decoded.ParentID != resource.ParentID || decoded.Kind != resource.Kind {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestResourceJSONRejectsUnknownField(t *testing.T) {
	var resource Resource
	err := json.Unmarshal([]byte(`{"kind":"tool","id":"shell","display_name":"Shell"}`), &resource)
	if err == nil || !strings.Contains(err.Error(), "display_name") {
		t.Fatalf("error = %v", err)
	}
	err = json.Unmarshal([]byte(`{"kind":"tool","id":"shell","parent_id":null}`), &resource)
	if err == nil || !strings.Contains(err.Error(), "parent_id must be a string") {
		t.Fatalf("error = %v", err)
	}
}

func TestClassifySerializesResourceAndIdentityRevision(t *testing.T) {
	var raw map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(singleResponse{
			Prediction: PredictionBenign,
			Score:      0.1,
			Threshold:  0.5,
			Mode:       ModeWarn,
		})
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	result, err := fw.Classify(context.Background(), "hello",
		WithMode(ModeWarn),
		WithToolName("mcp__arxiv__search_papers"),
		WithResource(Resource{
			Kind:     ResourceKindMCPTool,
			ID:       "search_papers",
			ParentID: "arxiv-mcp-server",
		}),
		WithIdentityRevision(" rev-1 "),
		WithMetadata(ClassificationMetadata{
			"resource":          map[string]any{"kind": "agent", "id": "from-metadata"},
			"identity_revision": "from-metadata",
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != ModeWarn || result.Governance != nil {
		t.Fatalf("result = %+v", result)
	}
	if raw["mode"] != "warn" {
		t.Fatalf("mode = %#v", raw["mode"])
	}
	if raw["tool_name"] != "mcp__arxiv__search_papers" {
		t.Fatalf("tool_name = %#v", raw["tool_name"])
	}
	if _, ok := raw["resources"]; ok {
		t.Fatalf("single request included resources: %#v", raw["resources"])
	}
	resource, ok := raw["resource"].(map[string]any)
	if !ok {
		t.Fatalf("resource = %#v", raw["resource"])
	}
	if resource["kind"] != "mcp_tool" || resource["id"] != "search_papers" || resource["parent_id"] != "arxiv-mcp-server" {
		t.Fatalf("resource = %#v", resource)
	}
	if raw["identity_revision"] != " rev-1 " {
		t.Fatalf("identity_revision = %#v", raw["identity_revision"])
	}
	metadata := raw["metadata"].(map[string]any)
	if metadata["identity_revision"] != "from-metadata" {
		t.Fatalf("metadata identity = %#v", metadata["identity_revision"])
	}
}

func TestClassifyOmitsIdentityWhenUnset(t *testing.T) {
	var raw map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(singleResponse{
			Prediction: PredictionBenign,
			Score:      0.1,
			Threshold:  0.5,
			Mode:       ModeBlock,
		})
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Classify(context.Background(), "hi", WithToolName("raw_tool")); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["resource"]; ok {
		t.Fatalf("resource = %#v", raw["resource"])
	}
	if _, ok := raw["identity_revision"]; ok {
		t.Fatalf("identity_revision = %#v", raw["identity_revision"])
	}
	if raw["tool_name"] != "raw_tool" {
		t.Fatalf("tool_name = %#v", raw["tool_name"])
	}
}

func TestClassifyRejectsInvalidIdentityBeforeSend(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	defer ts.Close()
	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fw.Classify(context.Background(), "hi", WithResource(Resource{Kind: ResourceKindTool, ID: " "}))
	if err == nil {
		t.Fatal("expected invalid resource error")
	}
	_, err = fw.Classify(context.Background(), "hi", WithIdentityRevision(" "))
	if err == nil || !strings.Contains(err.Error(), "identity_revision") {
		t.Fatalf("error = %v", err)
	}
	if called {
		t.Fatal("invalid identity reached the server")
	}
}

func TestClassifyBatchSerializesResourcesAndRevision(t *testing.T) {
	var raw map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		predictions := make([]singleResponse, 8)
		for i := range predictions {
			predictions[i] = singleResponse{
				Prediction: PredictionBenign,
				Score:      0.1,
				Threshold:  0.5,
				Mode:       ModeWarn,
			}
		}
		_ = json.NewEncoder(w).Encode(batchResponse{Predictions: predictions})
	}))
	defer ts.Close()

	kinds := []ResourceKind{
		ResourceKindAgent,
		ResourceKindTool,
		ResourceKindMCPServer,
		ResourceKindMCPTool,
		ResourceKindPlugin,
		ResourceKindSkill,
		ResourceKindExtension,
	}
	resources := make([]*Resource, len(kinds))
	toolNames := make([]string, len(kinds))
	texts := make([]string, len(kinds))
	for i, kind := range kinds {
		resource := &Resource{Kind: kind, ID: "id-" + string(kind)}
		if kind == ResourceKindMCPTool {
			resource.ParentID = "parent-server"
		}
		resources[i] = resource
		toolNames[i] = "raw-" + string(kind)
		texts[i] = "text"
	}
	resources = append(resources, nil)
	toolNames = append(toolNames, "raw-unscoped")
	texts = append(texts, "text")

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	results, err := fw.ClassifyBatch(context.Background(), texts,
		WithBatchMode(ModeWarn),
		WithBatchToolNames(toolNames),
		WithBatchResources(resources),
		WithBatchIdentityRevision("snap-7"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 8 {
		t.Fatalf("results = %d", len(results))
	}
	if raw["mode"] != "warn" || raw["identity_revision"] != "snap-7" {
		t.Fatalf("payload mode/revision = %#v %#v", raw["mode"], raw["identity_revision"])
	}
	if _, ok := raw["resource"]; ok {
		t.Fatalf("batch request included resource: %#v", raw["resource"])
	}
	gotResources, ok := raw["resources"].([]any)
	if !ok || len(gotResources) != 8 {
		t.Fatalf("resources = %#v", raw["resources"])
	}
	if gotResources[7] != nil {
		t.Fatalf("resources[7] = %#v, want null", gotResources[7])
	}
	for i, kind := range kinds {
		item, ok := gotResources[i].(map[string]any)
		if !ok {
			t.Fatalf("resources[%d] = %#v", i, gotResources[i])
		}
		if item["kind"] != string(kind) || item["id"] != "id-"+string(kind) {
			t.Fatalf("resources[%d] = %#v", i, item)
		}
		if kind == ResourceKindMCPTool && item["parent_id"] != "parent-server" {
			t.Fatalf("resources[%d] parent = %#v", i, item["parent_id"])
		}
		if kind != ResourceKindMCPTool {
			if _, ok := item["parent_id"]; ok {
				t.Fatalf("resources[%d] included parent_id: %#v", i, item)
			}
		}
	}
	gotTools, ok := raw["tool_names"].([]any)
	if !ok || len(gotTools) != 8 || gotTools[3] != "raw-mcp_tool" || gotTools[7] != "raw-unscoped" {
		t.Fatalf("tool_names = %#v", raw["tool_names"])
	}
}

func TestClassifyBatchRejectsResourceLengthBeforeSend(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	defer ts.Close()
	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fw.ClassifyBatch(context.Background(), []string{"a", "b"},
		WithBatchResources([]*Resource{{Kind: ResourceKindAgent, ID: "agent-1"}}),
	)
	if err == nil || !strings.Contains(err.Error(), "resources length 1 does not match texts length 2") {
		t.Fatalf("error = %v", err)
	}
	_, err = fw.ClassifyBatch(context.Background(), []string{"a"},
		WithBatchResources([]*Resource{{Kind: ResourceKindSkill, ID: " "}}),
	)
	if err == nil || !strings.Contains(err.Error(), "resource id") {
		t.Fatalf("error = %v", err)
	}
	if called {
		t.Fatal("invalid batch identity reached the server")
	}
}

func TestClassifyParsesGovernanceDecision(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"prediction": PredictionBenign,
			"score":      0.2,
			"threshold":  0.5,
			"mode":       ModeBlock,
			"governance": map[string]any{
				"action":            "block",
				"rule_id":           "rule-1",
				"policy_version":    "42",
				"identity_revision": "rev-9",
				"reason":            GovernanceReasonIdentityUnresolved,
				"resource": map[string]any{
					"kind":      "mcp_tool",
					"id":        "search_papers",
					"parent_id": "arxiv-mcp-server",
				},
			},
		})
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL, Mode: ModeShadow})
	if err != nil {
		t.Fatal(err)
	}
	result, err := fw.Classify(context.Background(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if result.Prediction != PredictionBenign || result.Mode != ModeShadow {
		t.Fatalf("result mode/prediction = %s %s", result.Prediction, result.Mode)
	}
	if result.Governance == nil {
		t.Fatal("governance missing")
	}
	decision := result.Governance
	if decision.Action != GovernanceActionBlock || decision.RuleID != "rule-1" || decision.PolicyVersion != "42" {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.IdentityRevision != "rev-9" || decision.Reason != GovernanceReasonIdentityUnresolved {
		t.Fatalf("decision revision/reason = %+v", decision)
	}
	if decision.Resource == nil || decision.Resource.Kind != ResourceKindMCPTool || decision.Resource.ID != "search_papers" || decision.Resource.ParentID != "arxiv-mcp-server" {
		t.Fatalf("resource = %+v", decision.Resource)
	}
}

func TestClassifyBatchParsesGovernancePerItem(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"predictions": []any{
				map[string]any{
					"prediction": PredictionBenign,
					"score":      0.1,
					"threshold":  0.5,
					"mode":       ModeWarn,
				},
				map[string]any{
					"prediction": PredictionBenign,
					"score":      0.2,
					"threshold":  0.5,
					"mode":       ModeBlock,
					"governance": map[string]any{
						"action":         "allow",
						"policy_version": "9",
						"resource":       map[string]any{"kind": "plugin", "id": "plugin-1"},
					},
				},
			},
		})
	}))
	defer ts.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL, Mode: ModeWarn})
	if err != nil {
		t.Fatal(err)
	}
	results, err := fw.ClassifyBatch(context.Background(), []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Governance != nil {
		t.Fatalf("first governance = %+v", results[0].Governance)
	}
	if results[1].Mode != ModeWarn || results[1].Governance == nil || results[1].Governance.Action != GovernanceActionAllow {
		t.Fatalf("second = %+v", results[1])
	}
	if results[1].Governance.Resource == nil || results[1].Governance.Resource.Kind != ResourceKindPlugin {
		t.Fatalf("second resource = %+v", results[1].Governance.Resource)
	}
}

func TestClassifyRejectsInvalidGovernance(t *testing.T) {
	cases := []map[string]any{
		{"action": "deny", "policy_version": "1"},
		{"action": "block"},
		{"action": "block", "policy_version": "1", "reason": "other"},
		{
			"action":         "block",
			"policy_version": "1",
			"resource":       map[string]any{"kind": "tool", "id": "shell", "parent_id": "nope"},
		},
	}
	for _, governance := range cases {
		governance := governance
		t.Run(governanceLabel(governance), func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"prediction": PredictionBenign,
					"score":      0.1,
					"threshold":  0.5,
					"mode":       ModeShadow,
					"governance": governance,
				})
			}))
			defer ts.Close()
			fw, err := New(Options{APIKey: "sk", APIURL: ts.URL, Mode: ModeShadow})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fw.Classify(context.Background(), "hi"); err == nil {
				t.Fatal("expected governance validation error")
			}
		})
	}
}

func governanceLabel(governance map[string]any) string {
	if reason, ok := governance["reason"]; ok {
		return "reason " + reason.(string)
	}
	if _, ok := governance["resource"]; ok {
		return "resource parent"
	}
	if _, ok := governance["policy_version"]; ok {
		return "action " + governance["action"].(string)
	}
	return "missing policy_version"
}

func TestPostJSONRejectsInvalidIdentityBeforeSend(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	defer ts.Close()
	fw, err := New(Options{APIKey: "sk", APIURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	err = fw.postJSON(context.Background(), singleRequestPayload{
		Text:     "hi",
		Resource: &Resource{Kind: ResourceKindExtension},
	}, &singleResponse{})
	if err == nil {
		t.Fatal("expected resource error")
	}
	err = fw.postJSON(context.Background(), batchRequestPayload{
		Texts:            []string{"a"},
		Resources:        []*Resource{nil, {Kind: ResourceKindAgent, ID: "a"}},
		IdentityRevision: "   ",
	}, &batchResponse{})
	if err == nil || !strings.Contains(err.Error(), "resources length") {
		t.Fatalf("error = %v", err)
	}
	if called {
		t.Fatal("postJSON sent an invalid identity payload")
	}
}

func TestClassifyEnforcesBenignGovernanceBlockByMode(t *testing.T) {
	for _, mode := range []FirewallMode{ModeBlock, ModeWarn, ModeShadow} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(singleResponse{
					Prediction: PredictionBenign,
					Score:      0.05,
					Threshold:  0.5,
					Mode:       ModeBlock,
					Governance: &GovernanceDecision{
						Action:        GovernanceActionBlock,
						RuleID:        "deny-shell",
						PolicyVersion: "policy-7",
					},
				})
			}))
			defer ts.Close()

			var event ClassifyEvent
			fw, err := New(Options{
				APIKey: "sk",
				APIURL: ts.URL,
				Mode:   mode,
				OnClassify: func(received ClassifyEvent) {
					event = received
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			result, classifyErr := fw.Classify(context.Background(), "benign tool call")
			if result.Prediction != PredictionBenign || !result.governanceBlocked() {
				t.Fatalf("result = %+v", result)
			}
			if !event.Blocked || event.Mode != mode || event.Result.Governance == nil {
				t.Fatalf("event = %+v", event)
			}
			var blocked *FirewallBlockedError
			if mode == ModeBlock {
				if !errors.As(classifyErr, &blocked) {
					t.Fatalf("error = %v, want FirewallBlockedError", classifyErr)
				}
				if blocked.Result.Governance == nil ||
					blocked.Result.Governance.RuleID != "deny-shell" {
					t.Fatalf("blocked result = %+v", blocked.Result)
				}
			} else if classifyErr != nil {
				t.Fatalf("%s must preserve the call: %v", mode, classifyErr)
			}
		})
	}
}

func TestClassifyGovernanceAllowDoesNotEraseMaliciousBlock(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(singleResponse{
			Prediction: PredictionMalicious,
			Score:      0.9,
			Threshold:  0.5,
			Mode:       ModeBlock,
			Governance: &GovernanceDecision{
				Action:        GovernanceActionAllow,
				PolicyVersion: "policy-7",
			},
		})
	}))
	defer ts.Close()

	var event ClassifyEvent
	fw, err := New(Options{
		APIKey:     "sk",
		APIURL:     ts.URL,
		Mode:       ModeBlock,
		OnClassify: func(received ClassifyEvent) { event = received },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, classifyErr := fw.Classify(context.Background(), "attack")
	var blocked *FirewallBlockedError
	if !errors.As(classifyErr, &blocked) {
		t.Fatalf("error = %v, want FirewallBlockedError", classifyErr)
	}
	if result.Prediction != PredictionMalicious || !event.Blocked {
		t.Fatalf("result/event = %+v %+v", result, event)
	}
}

func TestClassifyBatchEnforcesPredictionAndGovernanceBlocks(t *testing.T) {
	for _, mode := range []FirewallMode{ModeBlock, ModeWarn, ModeShadow} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(batchResponse{
					Predictions: []singleResponse{
						{
							Prediction: PredictionBenign,
							Score:      0.1,
							Threshold:  0.5,
							Mode:       ModeBlock,
							Governance: &GovernanceDecision{
								Action:        GovernanceActionBlock,
								RuleID:        "governance-block",
								PolicyVersion: "policy-1",
							},
						},
						{
							Prediction: PredictionMalicious,
							Score:      0.9,
							Threshold:  0.5,
							Mode:       ModeBlock,
							Governance: &GovernanceDecision{
								Action:        GovernanceActionAllow,
								PolicyVersion: "policy-1",
							},
						},
						{
							Prediction: PredictionBenign,
							Score:      0.1,
							Threshold:  0.5,
							Mode:       ModeBlock,
							Governance: &GovernanceDecision{
								Action:        GovernanceActionAllow,
								PolicyVersion: "policy-1",
							},
						},
					},
				})
			}))
			defer ts.Close()

			var events []ClassifyEvent
			fw, err := New(Options{
				APIKey: "sk",
				APIURL: ts.URL,
				Mode:   mode,
				OnClassify: func(event ClassifyEvent) {
					events = append(events, event)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			results, classifyErr := fw.ClassifyBatch(
				context.Background(),
				[]string{"governed", "malicious", "allowed"},
			)
			if len(results) != 3 || len(events) != 3 {
				t.Fatalf("results/events = %d/%d", len(results), len(events))
			}
			if !events[0].Blocked || !events[1].Blocked || events[2].Blocked {
				t.Fatalf("events = %+v", events)
			}
			for i := range events {
				if events[i].Mode != mode {
					t.Fatalf("events[%d].Mode = %q, want %q", i, events[i].Mode, mode)
				}
			}
			var blocked *BatchFirewallBlockedError
			if mode == ModeBlock {
				if !errors.As(classifyErr, &blocked) {
					t.Fatalf("error = %v, want BatchFirewallBlockedError", classifyErr)
				}
				if len(blocked.Blocked) != 2 ||
					blocked.Blocked[0].Index != 0 ||
					blocked.Blocked[1].Index != 1 {
					t.Fatalf("blocked = %+v", blocked.Blocked)
				}
			} else if classifyErr != nil {
				t.Fatalf("%s must preserve the batch: %v", mode, classifyErr)
			}
		})
	}
}
