// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestSDKVersionMatchesVersionFile(t *testing.T) {
	data, err := os.ReadFile("../VERSION")
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	if version := strings.TrimSpace(string(data)); version != SDKVersion {
		t.Fatalf("VERSION = %q, SDKVersion = %q", version, SDKVersion)
	}
}

func TestClassifyPreservesTypedSilmarilMetadata(t *testing.T) {
	var request singleRequestPayload
	fw, err := New(Options{
		APIKey: "test", APIURL: "https://firewall.test/classify",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(allowBody))}, nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	namespace := map[string]string{"client_label": "test", "request_id": "caller"}
	_, err = fw.Classify(context.Background(), "hello",
		WithMetadata(ClassificationMetadata{"silmaril": namespace}), WithRequestID("req-single"))
	if err != nil {
		t.Fatal(err)
	}
	got := requireSilmarilMetadata(t, request.Metadata, "req-single", nil)
	if got["client_label"] != "test" || namespace["request_id"] != "caller" {
		t.Fatalf("wire namespace = %v, caller namespace = %v", got, namespace)
	}
}

func TestClassifyBatchPreservesNamedSilmarilMetadata(t *testing.T) {
	var request batchRequestPayload
	fw, err := New(Options{
		APIKey: "test", APIURL: "https://firewall.test/classify",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			decoder := json.NewDecoder(req.Body)
			decoder.UseNumber()
			if err := decoder.Decode(&request); err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(allowBody))}, nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	type counters map[string]uint64
	const count = 9007199254740993
	namespace := counters{"count": count, "input_index": 72}
	_, err = fw.ClassifyBatch(context.Background(), []string{"hello"},
		WithBatchMetadata([]ClassificationMetadata{{"silmaril": namespace}}), WithBatchRequestID("req-batch"))
	if err != nil {
		t.Fatal(err)
	}
	if len(request.Metadata) != 1 || request.Metadata[0] == nil {
		t.Fatalf("wire metadata = %v, want one object", request.Metadata)
	}
	got, ok := (*request.Metadata[0])["silmaril"].(map[string]any)
	if !ok {
		t.Fatalf("metadata.silmaril = %#v, want object", (*request.Metadata[0])["silmaril"])
	}
	if got["count"] != json.Number("9007199254740993") || got["input_index"] != json.Number("0") ||
		got["request_id"] != "req-batch" || namespace["input_index"] != 72 {
		t.Fatalf("wire namespace = %v, caller namespace = %v", got, namespace)
	}
}

func TestSDKMetadataRejectsNonObjectNamespace(t *testing.T) {
	for _, raw := range []any{"scalar", []string{"array"}, json.RawMessage("null")} {
		metadata := ClassificationMetadata{"silmaril": raw}
		_, err := sdkMetadata(&metadata, "req-invalid", nil)
		if err == nil || !strings.Contains(err.Error(), "metadata.silmaril must be an object") {
			t.Errorf("sdkMetadata(%#v) error = %v", raw, err)
		}
	}
}
