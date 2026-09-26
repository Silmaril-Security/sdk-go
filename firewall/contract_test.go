// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var frozenGovernanceContractDigests = map[string]string{
	"README.md":            "64ea16e79e334cbb9f53e2cbf586ed1d44aad5748532ff6b74333ae90df82649",
	"matching.json":        "973791d36f678ac024cd6bd912b36fd8728d3b563a6e8139f1b31fcc9ae3577e",
	"resource.schema.json": "b9ed2d0218aaca5ee741aa3bd544849fd61b4888bbf77ed4854684e64665ed84",
	"SHA256SUMS":           "d297f514a958236fcf1b0036888a63cd18a3be2c44be913c377b710efd481243",
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
