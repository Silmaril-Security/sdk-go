package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTypedResourcePolicyAndAttributionBoundary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if _, ok := body["agent"]; ok {
			t.Error("caller agent became request identity")
		}
		action := "allow"
		if resource, ok := body["resource"].(map[string]any); ok && resource["kind"] == "plugin" && resource["id"] == "blocked-plugin" {
			action = "block"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"prediction": "BENIGN", "score": 0.1, "threshold": 0.5, "governance": map[string]string{"action": action, "policy_version": "fixture"}})
	}))
	defer server.Close()
	fw, err := New(Options{APIKey: "sk-test", APIURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fw.Classify(context.Background(), "synthetic", WithGovernance(GovernanceContext{Agent: "attribution-only", Resource: &GovernanceResource{Kind: GovernancePlugin, ID: "blocked-plugin"}}))
	var blocked *FirewallBlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("expected resource deny, got %v", err)
	}
	metadata := ClassificationMetadata{"silmaril": map[string]any{"governance": map[string]any{"resource": map[string]string{"kind": "plugin", "id": "blocked-plugin"}}}}
	if _, err := fw.Classify(context.Background(), "synthetic", WithMetadata(metadata)); err != nil {
		t.Fatalf("metadata must not supply canonical identity: %v", err)
	}
}
func TestRequestResourceValidation(t *testing.T) {
	for _, resource := range []GovernanceResource{{Kind: GovernancePlugin}, {Kind: GovernancePlugin, ID: " "}, {Kind: GovernanceMCPTool, ID: "tool"}, {Kind: GovernanceTool, ID: "tool", ParentID: "server"}, {Kind: "unknown", ID: "tool"}} {
		if _, err := requestGovernanceResource(&GovernanceContext{Resource: &resource}); err == nil {
			t.Errorf("accepted invalid resource %+v", resource)
		}
	}
}
func TestNullableBatchResourceOrder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		resources := body["resources"].([]any)
		if len(resources) != 3 || resources[0] != nil || resources[2] != nil || resources[1].(map[string]any)["id"] != "blocked-plugin" {
			t.Errorf("wrong alignment: %#v", resources)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"predictions": []map[string]any{{"prediction": "BENIGN", "score": 0.1}, {"prediction": "BENIGN", "score": 0.1}, {"prediction": "BENIGN", "score": 0.1}}})
	}))
	defer server.Close()
	fw, err := New(Options{APIKey: "sk-test", APIURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fw.ClassifyBatch(context.Background(), []string{"a", "b", "c"}, WithBatchGovernance([]*GovernanceContext{nil, {Resource: &GovernanceResource{Kind: GovernancePlugin, ID: "blocked-plugin"}}, {Agent: "attribution-only"}}))
	if err != nil {
		t.Fatal(err)
	}
}
