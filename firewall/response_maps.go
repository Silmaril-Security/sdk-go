// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type outcomeScoreMap map[string]float64
type detectorScoreMap map[string]float64
type detectorCountMap map[string]int

func (m *outcomeScoreMap) UnmarshalJSON(data []byte) error {
	values, err := decodeNonNullMap[float64](data, "outcome_scores")
	if err != nil {
		return err
	}
	*m = values
	return nil
}

func (m *detectorScoreMap) UnmarshalJSON(data []byte) error {
	values, err := decodeNonNullMap[float64](data, "detector_scores")
	if err != nil {
		return err
	}
	*m = values
	return nil
}

func (m *detectorCountMap) UnmarshalJSON(data []byte) error {
	values, err := decodeNonNullMap[int](data, "detector_counts")
	if err != nil {
		return err
	}
	*m = values
	return nil
}

func decodeNonNullMap[T float64 | int](data []byte, fieldName string) (map[string]T, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	values := make(map[string]T, len(raw))
	for key, encoded := range raw {
		if bytes.Equal(bytes.TrimSpace(encoded), []byte("null")) {
			return nil, fmt.Errorf("firewall: %s value for %q must not be null", fieldName, key)
		}
		var value T
		if err := json.Unmarshal(encoded, &value); err != nil {
			return nil, fmt.Errorf("firewall: invalid %s value for %q: %w", fieldName, key, err)
		}
		values[key] = value
	}
	return values, nil
}
