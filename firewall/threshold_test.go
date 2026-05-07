// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"math"
	"testing"
)

func TestAdaptiveThresholdSchedule(t *testing.T) {
	cases := []struct {
		count int
		want  float64
	}{
		{count: 1, want: 0.5},
		{count: 2, want: 0.6661087830919008},
		{count: 5, want: 0.8327747955407889},
		{count: 10, want: 0.9},
		{count: 100, want: 0.9},
	}
	for _, tc := range cases {
		got := adaptiveThreshold(tc.count)
		if math.Abs(got-tc.want) > 1e-12 {
			t.Errorf("adaptiveThreshold(%d) = %.16f, want %.16f", tc.count, got, tc.want)
		}
	}
}

func TestAdaptiveThresholdRejectsInvalidCount(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = adaptiveThreshold(0)
}
