// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import "math"

const (
	baseThreshold        = 0.5
	targetSequenceFPR    = 0.01
	maxAdaptiveThreshold = 0.9
)

func adaptiveThreshold(scoringOpportunityCount int) float64 {
	if scoringOpportunityCount < 1 {
		panic("firewall: scoringOpportunityCount must be >= 1")
	}
	if scoringOpportunityCount == 1 {
		return baseThreshold
	}
	targetChunkFPR := 1 - math.Pow(1-targetSequenceFPR, 1/float64(scoringOpportunityCount))
	oddsRatio := targetSequenceFPR / targetChunkFPR
	rawThreshold := oddsRatio / (1 + oddsRatio)
	return math.Min(rawThreshold, maxAdaptiveThreshold)
}
