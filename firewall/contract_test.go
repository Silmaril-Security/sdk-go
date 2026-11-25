// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type contractCase struct {
	Name    string          `json:"name"`
	V1      json.RawMessage `json:"v1"`
	V2      json.RawMessage `json:"v2"`
	Adapted json.RawMessage `json:"adapted"`
}

func readContractFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func loadContractCases(t *testing.T) []contractCase {
	t.Helper()
	var cases []contractCase
	if err := json.Unmarshal(readContractFile(t, "cases.json"), &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("contract has no cases")
	}
	return cases
}

func contractDecisions(t *testing.T, body json.RawMessage) ([]BlockResult, *ReviewLevel) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var wire wireResponse
	if err := decoder.Decode(&wire); err != nil {
		t.Fatal(err)
	}
	var review *ReviewLevel
	if echoed, ok := wire.Review.(string); ok {
		review = ptr(ReviewLevel(echoed))
	}
	want := make([]BlockResult, len(wire.Results))
	for i, item := range wire.Results {
		want[i] = BlockResult{
			Action:     Action(item.Action),
			Source:     valueOf(item.Source),
			Confidence: Confidence(valueOf(item.Confidence)),
			Severity:   Severity(valueOf(item.Severity)),
			Outcome:    HarmfulOutcome(valueOf(item.Outcome)),
			Governance: item.Governance,
			ModelID:    valueOf(item.ModelID),
			Review:     valueOf(review),
		}
	}
	return want, review
}

func TestContractCasesMatchPinnedDigest(t *testing.T) {
	want := fmt.Sprintf("%x  cases.json", sha256.Sum256(readContractFile(t, "cases.json")))
	pinned := strings.Split(strings.TrimSpace(string(readContractFile(t, "SHA256SUMS"))), "\n")
	if !slices.Contains(pinned, want) {
		t.Fatalf("SHA256SUMS = %q, want an entry %q", pinned, want)
	}
}

func TestContractVersion2Decisions(t *testing.T) {
	fw, err := New(Options{APIKey: "sk", APIURL: "https://firewall.test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range loadContractCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			want, review := contractDecisions(t, tc.V2)
			var resp classifyResponse
			if err := json.Unmarshal(tc.V2, &resp); err != nil {
				t.Fatal(err)
			}
			if resp.current == nil {
				t.Fatal("version 2 body was not read as version 2")
			}
			got, err := blockResults(*resp.current, len(want), "", review)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("decisions = %+v, want %+v", got, want)
			}
			for i, result := range got {
				if blocked := fw.newClassifyEvent("", HookUnknown, "", result).Blocked; blocked != (want[i].Action != "allow") {
					t.Errorf("decision %d blocked = %t for action %q", i, blocked, want[i].Action)
				}
			}
		})
	}
}

func TestContractAdaptsVersion1(t *testing.T) {
	for _, tc := range loadContractCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			want, review := contractDecisions(t, tc.Adapted)
			var resp classifyResponse
			if err := json.Unmarshal(tc.V1, &resp); err != nil {
				t.Fatal(err)
			}
			if resp.current != nil {
				t.Fatal("version 1 body was read as version 2")
			}
			adapted, err := resp.decisions(resp.legacy.Predictions != nil)
			if err != nil {
				t.Fatal(err)
			}
			got, err := blockResults(adapted, len(want), "", review)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("adapted decisions = %+v, want %+v", got, want)
			}
		})
	}
}
