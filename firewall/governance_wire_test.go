package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
func TestRequestResourceValidationBeforeTransport(t *testing.T) {
	for _, resource := range []GovernanceResource{{Kind: GovernancePlugin}, {Kind: GovernancePlugin, ID: " "}, {Kind: GovernanceMCPTool, ID: "tool"}, {Kind: GovernanceTool, ID: "tool", ParentID: "server"}, {Kind: "unknown", ID: "tool"}} {
		t.Run(string(resource.Kind)+resource.ID+resource.ParentID, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			fw, err := New(Options{APIKey: "sk-test", APIURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fw.Classify(context.Background(), "synthetic", WithGovernance(GovernanceContext{Resource: &resource})); err == nil {
				t.Error("single request accepted invalid canonical resource")
			}
			valid := &GovernanceContext{Resource: &GovernanceResource{Kind: GovernancePlugin, ID: "valid-plugin"}}
			invalid := &GovernanceContext{Resource: &resource}
			if _, err := fw.ClassifyBatch(context.Background(), []string{"valid", "invalid"}, WithBatchGovernance([]*GovernanceContext{valid, invalid})); err == nil {
				t.Error("batch request accepted invalid canonical resource")
			}
			if requests.Load() != 0 {
				t.Errorf("invalid resource reached HTTP transport %d times", requests.Load())
			}
		})
	}
}

func TestResponseResourceValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"prediction":"BENIGN","score":0.1,"threshold":0.5,"governance":{"action":"allow","policy_version":"schema6","resource":{"kind":"mcp_tool","id":"search"}}}`))
	}))
	defer server.Close()
	fw, err := New(Options{APIKey: "sk-test", APIURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Classify(context.Background(), "synthetic"); err == nil {
		t.Fatal("response accepted an invalid canonical governance resource")
	}
}

func TestGovernanceOptionalStringWireValidation(t *testing.T) {
	for _, tc := range []struct {
		name             string
		fields           string
		identityRevision string
		reason           string
		errorContains    string
	}{
		{name: "omitted"},
		{name: "null", fields: `,"identity_revision":null,"reason":null`},
		{
			name:             "preserves nonblank whitespace",
			fields:           `,"identity_revision":"  identity-r9\t","reason":"\tfuture reason  "`,
			identityRevision: "  identity-r9\t",
			reason:           "\tfuture reason  ",
		},
		{
			name:             "preserves Python nonblank byte order mark",
			fields:           `,"identity_revision":"\u00a0\ufeff\u0085","reason":"\u001cfuture reason\u3000"`,
			identityRevision: "\u00a0\ufeff\u0085",
			reason:           "\u001cfuture reason\u3000",
		},
		{name: "empty identity revision", fields: `,"identity_revision":""`, errorContains: "governance identity_revision must be null, omitted, or a non-blank string"},
		{name: "blank identity revision", fields: `,"identity_revision":" \t "`, errorContains: "governance identity_revision must be null, omitted, or a non-blank string"},
		{name: "Python-blank identity revision", fields: `,"identity_revision":"\u001c\u001d\u001e\u001f\u0085\u00a0\u1680\u2003\u2028\u2029\u202f\u205f\u3000"`, errorContains: "governance identity_revision must be null, omitted, or a non-blank string"},
		{name: "numeric identity revision", fields: `,"identity_revision":7`, errorContains: "cannot unmarshal number"},
		{name: "empty reason", fields: `,"reason":""`, errorContains: "governance reason must be null, omitted, or a non-blank string"},
		{name: "blank reason", fields: `,"reason":" \n "`, errorContains: "governance reason must be null, omitted, or a non-blank string"},
		{name: "Python-blank reason", fields: `,"reason":"\u001c\u0085\u00a0\u2007\u2029\u3000"`, errorContains: "governance reason must be null, omitted, or a non-blank string"},
		{name: "boolean reason", fields: `,"reason":true`, errorContains: "cannot unmarshal bool"},
	} {
		for _, batch := range []bool{false, true} {
			shape := "single"
			if batch {
				shape = "batch"
			}
			t.Run(tc.name+"/"+shape, func(t *testing.T) {
				decision := `{"action":"allow","policy_version":"schema6","rule_id":"rule-1"` + tc.fields + `}`
				body := `{"prediction":"BENIGN","score":0.1,"threshold":0.5,"governance":` + decision + `}`
				if batch {
					body = `{"predictions":[` + body + `]}`
				}
				fw, err := New(Options{
					APIKey: "sk-test",
					APIURL: "https://firewall.test/classify",
					HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
						return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
					})},
				})
				if err != nil {
					t.Fatal(err)
				}
				var got *GovernanceDecision
				if batch {
					results, classifyErr := fw.ClassifyBatch(context.Background(), []string{"synthetic"})
					err = classifyErr
					if err == nil {
						got = results[0].Governance
					}
				} else {
					result, classifyErr := fw.Classify(context.Background(), "synthetic")
					err = classifyErr
					if err == nil {
						got = result.Governance
					}
				}
				if tc.errorContains != "" {
					if err == nil || !strings.Contains(err.Error(), tc.errorContains) {
						t.Fatalf("classification error = %v, want substring %q", err, tc.errorContains)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if got == nil || got.Action != GovernanceAllow || got.PolicyVersion != "schema6" || got.RuleID != "rule-1" ||
					got.IdentityRevision != tc.identityRevision || got.Reason != tc.reason {
					t.Fatalf("governance decision = %+v", got)
				}
			})
		}
	}
}

func TestResponseNonMCPParentIDMustBeNullOrOmitted(t *testing.T) {
	for _, tc := range []struct {
		name     string
		parentID string
		valid    bool
		wantErr  string
	}{
		{name: "omitted", valid: true},
		{name: "null", parentID: `,"parent_id":null`, valid: true},
		{name: "empty string", parentID: `,"parent_id":""`, wantErr: "parent_id must be null or omitted for non-mcp_tool"},
		{name: "numeric", parentID: `,"parent_id":7`, wantErr: "cannot unmarshal number"},
	} {
		for _, batch := range []bool{false, true} {
			shape := "single"
			if batch {
				shape = "batch"
			}
			t.Run(tc.name+"/"+shape, func(t *testing.T) {
				body := `{"prediction":"BENIGN","score":0.1,"threshold":0.5,"governance":{"action":"allow","policy_version":"schema6","resource":{"kind":"plugin","id":"plugin-1"` + tc.parentID + `}}}`
				if batch {
					body = `{"predictions":[` + body + `]}`
				}
				fw, err := New(Options{
					APIKey: "sk-test",
					APIURL: "https://firewall.test/classify",
					HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
						return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
					})},
				})
				if err != nil {
					t.Fatal(err)
				}
				if batch {
					_, err = fw.ClassifyBatch(context.Background(), []string{"synthetic"})
				} else {
					_, err = fw.Classify(context.Background(), "synthetic")
				}
				if tc.valid && err != nil {
					t.Fatal(err)
				}
				if !tc.valid && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
					t.Fatalf("classification error = %v, want substring %q", err, tc.wantErr)
				}
			})
		}
	}
}

func TestRequestNonMCPEmptyParentIDRemainsOmitted(t *testing.T) {
	fw, err := New(Options{
		APIKey: "sk-test",
		APIURL: "https://firewall.test/classify",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			var body map[string]any
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				return nil, err
			}
			resource := body["resource"].(map[string]any)
			if _, exists := resource["parent_id"]; exists {
				t.Errorf("request resource contains parent_id: %#v", resource)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(
				`{"prediction":"BENIGN","score":0.1,"threshold":0.5}`,
			))}, nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fw.Classify(context.Background(), "synthetic", WithGovernance(GovernanceContext{
		Resource: &GovernanceResource{Kind: GovernancePlugin, ID: "plugin-1", ParentID: ""},
	}))
	if err != nil {
		t.Fatal(err)
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
		verdict := singleResponse{Prediction: PredictionBenign, Score: 0.1, Threshold: 0.5}
		_ = json.NewEncoder(w).Encode(batchResponse{Predictions: []singleResponse{verdict, verdict, verdict}})
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
