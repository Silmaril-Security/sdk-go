// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import "fmt"

// Chunking constants mirror the Python and TypeScript SDKs so the three
// clients split long inputs identically.
const (
	CharsPerToken     = 4
	MaxInputTokens    = 10_240
	ChunkWindow       = 400
	ChunkOverlap      = 64
	MaxInputChars     = MaxInputTokens * CharsPerToken
	ChunkWindowChars  = ChunkWindow * CharsPerToken
	ChunkOverlapChars = ChunkOverlap * CharsPerToken
	chunkStrideChars  = ChunkWindowChars - ChunkOverlapChars
)

// ChunkText splits text into overlapping rune windows for server
// classification. Returns a single-element slice when text fits one
// window. Returns an error when text exceeds MaxInputChars.
func ChunkText(text string) ([]string, error) {
	runes := []rune(text)
	n := len(runes)
	if n > MaxInputChars {
		return nil, fmt.Errorf(
			"firewall: input has ~%d tokens (%d chars); max is %d tokens (%d chars)",
			n/CharsPerToken, n, MaxInputTokens, MaxInputChars,
		)
	}
	if n <= ChunkWindowChars {
		return []string{text}, nil
	}
	chunks := make([]string, 0)
	for start := 0; start < n; start += chunkStrideChars {
		end := start + ChunkWindowChars
		if end > n {
			end = n
		}
		chunks = append(chunks, string(runes[start:end]))
		if end >= n {
			break
		}
	}
	return chunks, nil
}
