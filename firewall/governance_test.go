package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGovernanceSingleAndLegacy(t *testing.T) {
	var sent []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		sent = append(sent, body)
		switch len(sent) {
		case 1:
			_, _ = w.Write([]byte(`{"prediction":"BENIGN","score":0.1,"threshold":0.5,"mode":"block","governance":{"action":"block","policy_version":"schema6","rule_id":"rule-1","resource":{"kind":"mcp_tool","id":"search","parent_id":"server-1"},"identity_revision":"identity-r7","reason":"identity_unresolved"}}`))
		case 2:
			_, _ = w.Write([]byte(`{"prediction":"BENIGN","score":0.1,"threshold":0.5,"mode":"block","governance":{"action":"allow","policy_version":"schema6","resource":null,"identity_revision":null,"reason":null}}`))
		default:
			_, _ = w.Write([]byte(`{"prediction":"BENIGN","score":0.1,"threshold":0.5,"mode":"block"}`))
		}
	}))
	defer server.Close()
	fw, err := New(Options{APIKey: "sk", APIURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	resource := GovernanceContext{Agent: "agent-1", Resource: &GovernanceResource{Kind: GovernanceMCPTool, ID: "search", ParentID: "server-1"}}
	result, err := fw.Classify(context.Background(), "search", WithGovernance(resource))
	var blocked *FirewallBlockedError
	if !errors.As(err, &blocked) || result.Governance == nil || result.Governance.RuleID != "rule-1" {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	decision := result.Governance
	if decision.PolicyVersion != "schema6" || decision.IdentityRevision != "identity-r7" || decision.Reason != "identity_unresolved" {
		t.Fatalf("governance evidence=%+v", decision)
	}
	if decision.Resource == nil || decision.Resource.Kind != GovernanceMCPTool || decision.Resource.ID != "search" || decision.Resource.ParentID != "server-1" {
		t.Fatalf("governance resource=%+v", decision.Resource)
	}
	canonical := sent[0]["resource"].(map[string]any)
	if canonical["kind"] != "mcp_tool" || canonical["id"] != "search" || canonical["parent_id"] != "server-1" {
		t.Fatalf("resource wire=%#v", canonical)
	}
	if _, ok := sent[0]["agent"]; ok {
		t.Fatal("caller agent must remain attribution only")
	}
	got := sent[0]["metadata"].(map[string]any)["silmaril"].(map[string]any)["governance"].(map[string]any)
	if got["agent"] != "agent-1" || got["resource"].(map[string]any)["parent_id"] != "server-1" {
		t.Fatalf("governance wire=%#v", got)
	}
	nullable, err := fw.Classify(context.Background(), "safe")
	if err != nil || nullable.Governance == nil || nullable.Governance.Resource != nil || nullable.Governance.IdentityRevision != "" || nullable.Governance.Reason != "" {
		t.Fatalf("nullable result=%+v error=%v", nullable, err)
	}
	legacy, err := fw.Classify(context.Background(), "legacy-safe")
	if err != nil || legacy.Governance != nil {
		t.Fatalf("legacy result=%+v error=%v", legacy, err)
	}
}

func TestGovernanceBatchWireAndLength(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		resources := body["resources"].([]any)
		if len(resources) != 2 || resources[0] != nil || resources[1] != nil {
			t.Errorf("resources=%#v", resources)
		}
		metadata := body["metadata"].([]any)
		first := metadata[0].(map[string]any)["silmaril"].(map[string]any)
		second := metadata[1].(map[string]any)["silmaril"].(map[string]any)
		if first["governance"] == nil || second["governance"] != nil {
			t.Errorf("metadata=%#v", metadata)
		}
		_, _ = w.Write([]byte(`{"predictions":[{"prediction":"BENIGN","score":0.1,"threshold":0.5,"mode":"warn","governance":{"action":"block","policy_version":"schema6","rule_id":"rule-future","resource":{"kind":"plugin","id":"plugin-future"},"identity_revision":"identity-r8","reason":"future_runtime_reason"}},{"prediction":"BENIGN","score":0.1,"threshold":0.5,"mode":"warn"}]}`))
	}))
	defer server.Close()
	fw, err := New(Options{APIKey: "sk", APIURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	contexts := []*GovernanceContext{{Agent: "a"}, nil}
	results, err := fw.ClassifyBatch(context.Background(), []string{"a", "b"}, WithBatchGovernance(contexts))
	if err != nil || len(results) != 2 || results[0].Governance == nil || results[1].Governance != nil {
		t.Fatalf("results=%+v error=%v", results, err)
	}
	decision := results[0].Governance
	if decision.Reason != "future_runtime_reason" || decision.IdentityRevision != "identity-r8" || decision.Resource == nil || decision.Resource.Kind != GovernancePlugin || decision.Resource.ID != "plugin-future" {
		t.Fatalf("governance evidence=%+v", decision)
	}
	if _, err := fw.ClassifyBatch(context.Background(), []string{"a", "b"}, WithBatchGovernance(contexts[:1])); err == nil {
		t.Fatal("expected governance length error")
	}
}

func TestGovernanceBatchBlockModeIncludesBenignPolicyDenial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"predictions":[{"prediction":"BENIGN","score":0.1,"threshold":0.5,"mode":"block","governance":{"action":"block","policy_version":"v2","rule_id":"policy-1"}},{"prediction":"BENIGN","score":0.1,"threshold":0.5,"mode":"block"}]}`))
	}))
	defer server.Close()

	fw, err := New(Options{APIKey: "sk", APIURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	results, err := fw.ClassifyBatch(context.Background(), []string{"governed", "allowed"}, WithBatchGovernance([]*GovernanceContext{{Agent: "a"}, nil}))
	var blocked *BatchFirewallBlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("expected BatchFirewallBlockedError, got %v", err)
	}
	if len(results) != 2 || len(blocked.Blocked) != 1 || blocked.Blocked[0].Index != 0 {
		t.Fatalf("results=%+v blocked=%+v", results, blocked.Blocked)
	}
	if decision := blocked.Blocked[0].Result.Governance; decision == nil || decision.Action != GovernanceBlock || decision.RuleID != "policy-1" {
		t.Fatalf("blocked decision=%+v", decision)
	}
}
