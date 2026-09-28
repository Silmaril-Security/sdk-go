// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var frozenGovernanceContractDigests = map[string]string{
	"README.md":            "b26ba42b2d8bf4caa7c65cb910d8f4fee3837ec3f7130e881e542a235b341615",
	"matching.json":        "7589f5d327a76878a8904b9543a0c5011218865842069a0cd70612f14fe34e91",
	"resource.schema.json": "b9ed2d0218aaca5ee741aa3bd544849fd61b4888bbf77ed4854684e64665ed84",
	"SHA256SUMS":           "e7618661bbd0b969833a1512ae19a3ee57835186c520b4874b7c65159cb2d7e2",
}

func TestFrozenGovernanceContractDigests(t *testing.T) {
	dir := governanceContractDir(t)
	manifestBytes, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256Hex(manifestBytes); got != frozenGovernanceContractDigests["SHA256SUMS"] {
		t.Fatalf("SHA256SUMS digest = %s, want frozen %s", got, frozenGovernanceContractDigests["SHA256SUMS"])
	}

	listed := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(manifestBytes)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			t.Fatalf("invalid SHA256SUMS line %q", scanner.Text())
		}
		listed[fields[1]] = fields[0]
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 3 {
		t.Fatalf("SHA256SUMS entries = %d, want 3", len(listed))
	}
	for name, want := range frozenGovernanceContractDigests {
		if name == "SHA256SUMS" {
			continue
		}
		if listed[name] != want {
			t.Fatalf("SHA256SUMS[%s] = %q, want %q", name, listed[name], want)
		}
		contents, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := sha256Hex(contents); got != want {
			t.Fatalf("%s digest = %s, want %s", name, got, want)
		}
	}
}

func TestGovernanceDispatchContractVectors(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join(governanceContractDir(t), "matching.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []governanceDispatchCase `json:"mcp_dispatch_cases"`
	}
	if err := json.Unmarshal(contents, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) != 19 {
		t.Fatalf("mcp_dispatch_cases = %d, want 19", len(vectors.Cases))
	}
	seen := map[string]struct{}{}
	for _, vector := range vectors.Cases {
		vector := vector
		if _, ok := seen[vector.Name]; ok {
			t.Fatalf("duplicate mcp_dispatch_cases name %q", vector.Name)
		}
		seen[vector.Name] = struct{}{}
		t.Run(vector.Name, func(t *testing.T) {
			resolver, err := resolverFromDispatchCatalog(vector.Catalog)
			if err != nil {
				t.Fatal(err)
			}
			if vector.Authoritative != nil {
				assertAuthoritativeDispatchResource(t, resolver, vector)
				return
			}
			assertDispatchResolution(t, resolver.Resolve(vector.RawName), vector)
		})
	}
}

type governanceDispatchCase struct {
	Name          string                    `json:"name"`
	RawName       string                    `json:"raw_name"`
	Authoritative *contractResource         `json:"authoritative_resource"`
	Catalog       governanceDispatchCatalog `json:"catalog"`
	Result        *contractResource         `json:"result"`
	Failure       *string                   `json:"failure"`
}

type governanceDispatchCatalog struct {
	Servers []struct {
		ID      string   `json:"id"`
		Aliases []string `json:"aliases"`
	} `json:"servers"`
	Tools []struct {
		ID       string `json:"id"`
		ParentID string `json:"parent_id"`
	} `json:"tools"`
}

func resolverFromDispatchCatalog(catalog governanceDispatchCatalog) (*MCPResolver, error) {
	aliases := make([]MCPServerAlias, 0)
	for _, server := range catalog.Servers {
		for _, alias := range server.Aliases {
			aliases = append(aliases, MCPServerAlias{ServerID: server.ID, Alias: alias})
		}
	}
	if len(catalog.Tools) > 0 {
		tools := make([]Resource, 0, len(catalog.Tools))
		for _, tool := range catalog.Tools {
			tools = append(tools, Resource{
				Kind:     ResourceKindMCPTool,
				ID:       tool.ID,
				ParentID: tool.ParentID,
			})
		}
		return NewMCPCatalogResolver(MCPCatalog{Tools: tools, Aliases: aliases})
	}
	servers := make([]Resource, 0, len(catalog.Servers))
	for _, server := range catalog.Servers {
		servers = append(servers, Resource{Kind: ResourceKindMCPServer, ID: server.ID})
	}
	return NewMCPCatalogResolver(MCPCatalog{Servers: servers, Aliases: aliases})
}

func assertDispatchResolution(t *testing.T, resolution MCPResolution, vector governanceDispatchCase) {
	t.Helper()
	switch {
	case vector.Failure == nil && vector.Result != nil:
		want := vector.Result.concrete()
		if resolution.Status != MCPResolutionResolved || resolution.Resource == nil {
			t.Fatalf("resolution = %+v, want %+v", resolution, want)
		}
		if resolution.Resource.Kind != want.Kind || resolution.Resource.ID != want.ID || resolution.Resource.ParentID != want.ParentID {
			t.Fatalf("resource = %+v, want %+v", resolution.Resource, want)
		}
		if err := resolution.Resource.Validate(); err != nil {
			t.Fatal(err)
		}
	case vector.Failure != nil && vector.Result == nil:
		var want MCPResolutionStatus
		switch *vector.Failure {
		case "ambiguous":
			want = MCPResolutionAmbiguous
		case "unresolved":
			want = MCPResolutionUnresolved
		default:
			t.Fatalf("unknown failure %q", *vector.Failure)
		}
		if resolution.Status != want || resolution.Resource != nil {
			t.Fatalf("resolution = %+v, want %s", resolution, want)
		}
	default:
		t.Fatalf("case %q must set exactly one of result or failure", vector.Name)
	}
}

func assertAuthoritativeDispatchResource(t *testing.T, resolver *MCPResolver, vector governanceDispatchCase) {
	t.Helper()
	if vector.Result == nil || vector.Failure != nil {
		t.Fatal("authoritative resource requires a resolved result")
	}
	want := vector.Authoritative.concrete()
	if got := vector.Result.concrete(); got.Kind != want.Kind || got.ID != want.ID || got.ParentID != want.ParentID {
		t.Fatalf("result = %+v, authoritative = %+v", got, want)
	}
	raw := resolver.Resolve(vector.RawName)
	if raw.Status != MCPResolutionAmbiguous || raw.Resource != nil {
		t.Fatalf("raw dispatch resolution = %+v, want ambiguous before the typed resource", raw)
	}

	var sent map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
			t.Error(err)
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
	if _, err := fw.Classify(context.Background(), "dispatch",
		WithMode(ModeWarn),
		WithToolName(vector.RawName),
		WithResource(want),
	); err != nil {
		t.Fatal(err)
	}
	if sent["tool_name"] != vector.RawName {
		t.Fatalf("tool_name = %#v, want %q", sent["tool_name"], vector.RawName)
	}
	resource, ok := sent["resource"].(map[string]any)
	if !ok {
		t.Fatalf("resource = %#v", sent["resource"])
	}
	if resource["kind"] != string(want.Kind) || resource["id"] != want.ID || resource["parent_id"] != want.ParentID {
		t.Fatalf("resource = %#v, want %+v", resource, want)
	}
}

func TestGovernanceMatchingContractVectors(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join(governanceContractDir(t), "matching.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		ContractVersion string                   `json:"contract_version"`
		Cases           []governanceMatchingCase `json:"cases"`
	}
	if err := json.Unmarshal(contents, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.ContractVersion != "1.0.0" {
		t.Fatalf("contract_version = %q", vectors.ContractVersion)
	}
	if len(vectors.Cases) != 35 {
		t.Fatalf("matching cases = %d, want 35", len(vectors.Cases))
	}
	for _, vector := range vectors.Cases {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			if vector.Actual != nil {
				actual := vector.Actual.concrete()
				if err := actual.Validate(); err != nil {
					t.Fatalf("actual resource violates SDK shape: %v", err)
				}
			}
			if got := contractResourceMatches(vector.Selector, vector.Actual); got != vector.Matches {
				t.Fatalf("match = %t, want %t; selector=%+v actual=%+v", got, vector.Matches, vector.Selector, vector.Actual)
			}
		})
	}
}

type governanceMatchingCase struct {
	Name     string            `json:"name"`
	Selector *contractResource `json:"selector"`
	Actual   *contractResource `json:"actual"`
	Matches  bool              `json:"matches"`
}

type contractResource struct {
	Kind     ResourceKind `json:"kind"`
	ID       string       `json:"id,omitempty"`
	ParentID string       `json:"parent_id,omitempty"`
}

func (r contractResource) concrete() Resource {
	return Resource{Kind: r.Kind, ID: r.ID, ParentID: r.ParentID}
}

func contractResourceMatches(selector, actual *contractResource) bool {
	if selector == nil {
		return true
	}
	if actual == nil {
		return false
	}
	if selector.Kind == actual.Kind {
		if selector.ID != "" && selector.ID != actual.ID {
			return false
		}
		return selector.ParentID == "" || selector.ParentID == actual.ParentID
	}
	if selector.Kind == ResourceKindMCPServer && actual.Kind == ResourceKindMCPTool {
		return selector.ID == "" || selector.ID == actual.ParentID
	}
	return false
}

func governanceContractDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	return filepath.Join(filepath.Dir(filename), "..", "contracts", "governance", "v1")
}

func sha256Hex(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}
