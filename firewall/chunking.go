// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Chunking constants mirror the Python and TypeScript SDKs so the three
// clients split long inputs identically.
const (
	CharsPerToken     = 4
	MaxInputTokens    = 81_920
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
	text = sanitizeText(text)
	if len(text) <= ChunkWindowChars {
		return []string{text}, nil
	}
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
	capacity := (n - ChunkOverlapChars + chunkStrideChars - 1) / chunkStrideChars
	chunks := make([]string, 0, capacity)
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

func sanitizeText(text string) string {
	if utf8.ValidString(text) {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	for len(text) > 0 {
		r, size := utf8.DecodeRuneInString(text)
		if r == utf8.RuneError && size == 1 {
			text = text[1:]
			continue
		}
		b.WriteString(text[:size])
		text = text[size:]
	}
	return b.String()
}

func sanitizeTexts(texts []string) []string {
	out := make([]string, len(texts))
	for i, text := range texts {
		out[i] = sanitizeText(text)
	}
	return out
}
