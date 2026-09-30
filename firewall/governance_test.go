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
		if len(sent) == 1 {
			_, _ = w.Write([]byte(`{"prediction":"BENIGN","score":0.1,"threshold":0.5,"mode":"block","governance":{"action":"block","policy_version":"v2","rule_id":"rule-1"}}`))
		} else {
			_, _ = w.Write([]byte(`{"prediction":"BENIGN","score":0.1,"threshold":0.5,"mode":"block"}`))
		}
	}))
	defer server.Close()
	fw, err := New(Options{APIKey: "sk", APIURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	resource := GovernanceContext{Agent: "agent-1", Resource: &GovernanceResource{Kind: GovernanceTool, ID: "search", ParentID: "server-1"}}
	result, err := fw.Classify(context.Background(), "search", WithGovernance(resource))
	var blocked *FirewallBlockedError
	if !errors.As(err, &blocked) || result.Governance == nil || result.Governance.RuleID != "rule-1" {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	got := sent[0]["metadata"].(map[string]any)["silmaril"].(map[string]any)["governance"].(map[string]any)
	if got["agent"] != "agent-1" || got["resource"].(map[string]any)["parent_id"] != "server-1" {
		t.Fatalf("governance wire=%#v", got)
	}
	legacy, err := fw.Classify(context.Background(), "safe")
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
		metadata := body["metadata"].([]any)
		first := metadata[0].(map[string]any)["silmaril"].(map[string]any)
		second := metadata[1].(map[string]any)["silmaril"].(map[string]any)
		if first["governance"] == nil || second["governance"] != nil {
			t.Errorf("metadata=%#v", metadata)
		}
		_, _ = w.Write([]byte(`{"predictions":[{"prediction":"BENIGN","score":0.1,"threshold":0.5,"mode":"warn","governance":{"action":"block","policy_version":"v2"}},{"prediction":"BENIGN","score":0.1,"threshold":0.5,"mode":"warn"}]}`))
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
