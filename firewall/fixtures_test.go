// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	modelRelease = "silmaril-cascade-1-6"

	allowItem = `{"action":"allow","source":null,"confidence":null,"severity":null,"outcome":null,"governance":null,"model_id":null}`
	blockItem = `{"action":"block","source":"model","confidence":null,"severity":null,"outcome":null,"governance":null,"model_id":null}`
	allowBody = `{"results":[` + allowItem + `]}`
)

// wireDecision is one /v2/classify result as the runtime sends it: every key
// present, null when empty.
type wireDecision struct {
	Action     string              `json:"action"`
	Source     *string             `json:"source"`
	Confidence *string             `json:"confidence"`
	Severity   *string             `json:"severity"`
	Outcome    *string             `json:"outcome"`
	Governance *GovernanceDecision `json:"governance"`
	ModelID    *string             `json:"model_id"`
}

type wireResponse struct {
	Results []wireDecision `json:"results"`
	Review  any            `json:"review,omitempty"`
}

var (
	allowDecision = wireDecision{Action: "allow"}
	blockDecision = wireDecision{Action: "block", Source: ptr(SourceModel)}
)

func ptr[T any](value T) *T {
	return &value
}

func valueOf[T any](pointer *T) T {
	if pointer == nil {
		var zero T
		return zero
	}
	return *pointer
}

func writeResults(w http.ResponseWriter, results ...wireDecision) {
	_ = json.NewEncoder(w).Encode(wireResponse{Results: results})
}

// newLegacyServer serves a runtime that predates /v2/classify: only /classify
// is routed, so every other path answers 404.
func newLegacyServer(t *testing.T, classify http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(legacyPath, classify)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}
