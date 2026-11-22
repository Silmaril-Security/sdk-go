// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"maps"
	"time"
)

// SDKVersion is the semantic version reported in metadata.silmaril.
const SDKVersion = "0.8.2"

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%x-%x-%x-%x-%x",
		b[0:4],
		b[4:6],
		b[6:8],
		b[8:10],
		b[10:16],
	)
}

func sdkMetadata(
	metadata *ClassificationMetadata,
	requestID string,
	inputIndex *int,
) (*ClassificationMetadata, error) {
	out := ClassificationMetadata{}
	if metadata != nil {
		for key, value := range *metadata {
			out[key] = value
		}
	}
	namespace, err := copyMetadataNamespace(out["silmaril"])
	if err != nil {
		return nil, err
	}
	namespace["sdk_language"] = "go"
	namespace["sdk_version"] = SDKVersion
	namespace["request_id"] = requestID
	if inputIndex != nil {
		namespace["input_index"] = *inputIndex
	}
	out["silmaril"] = namespace
	return &out, nil
}

// copyMetadataNamespace normalizes JSON objects without modifying caller values.
func copyMetadataNamespace(raw any) (map[string]any, error) {
	namespace := map[string]any{}
	switch object := raw.(type) {
	case nil:
	case map[string]any:
		maps.Copy(namespace, object)
	case ClassificationMetadata:
		maps.Copy(namespace, object)
	default:
		encoded, err := json.Marshal(object)
		if err != nil {
			return nil, fmt.Errorf("firewall: metadata.silmaril must be an object when provided: %w", err)
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.UseNumber()
		if err := decoder.Decode(&namespace); err != nil || namespace == nil {
			return nil, fmt.Errorf("firewall: metadata.silmaril must be an object when provided")
		}
	}
	return namespace, nil
}

func setGovernanceMetadata(metadata *ClassificationMetadata, context *GovernanceContext) {
	if context == nil {
		return
	}
	namespace := (*metadata)["silmaril"].(map[string]any)
	namespace["governance"] = context
}
