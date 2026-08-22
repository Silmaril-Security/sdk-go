// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"crypto/rand"
	"fmt"
	"time"
)

// SDKVersion is the semantic version reported in metadata.silmaril.
const SDKVersion = "0.6.0"

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
	namespace := map[string]any{}
	if raw, ok := out["silmaril"]; ok && raw != nil {
		existing, ok := raw.(map[string]any)
		if !ok {
			if typed, typedOK := raw.(ClassificationMetadata); typedOK {
				existing = map[string]any(typed)
				ok = true
			}
		}
		if !ok {
			return nil, fmt.Errorf("firewall: metadata.silmaril must be an object when provided")
		}
		for key, value := range existing {
			namespace[key] = value
		}
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
