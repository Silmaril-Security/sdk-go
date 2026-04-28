// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL

package firewall

import (
	"math"
	"strings"
	"testing"
)

func TestChunkingConstantsMatchTypeScriptSDK(t *testing.T) {
	if MaxInputTokens != 10_240 {
		t.Errorf("MaxInputTokens = %d, want 10240", MaxInputTokens)
	}
	if ChunkWindow != 400 {
		t.Errorf("ChunkWindow = %d, want 400", ChunkWindow)
	}
	if ChunkOverlap != 64 {
		t.Errorf("ChunkOverlap = %d, want 64", ChunkOverlap)
	}
	if MaxInputChars != MaxInputTokens*CharsPerToken {
		t.Errorf("MaxInputChars = %d, want %d", MaxInputChars, MaxInputTokens*CharsPerToken)
	}
	if ChunkWindowChars != ChunkWindow*CharsPerToken {
		t.Errorf("ChunkWindowChars = %d, want %d", ChunkWindowChars, ChunkWindow*CharsPerToken)
	}
	if ChunkOverlapChars != ChunkOverlap*CharsPerToken {
		t.Errorf("ChunkOverlapChars = %d, want %d", ChunkOverlapChars, ChunkOverlap*CharsPerToken)
	}
}

func TestChunkTextShort(t *testing.T) {
	chunks, err := ChunkText("hello")
	if err != nil {
		t.Fatalf("ChunkText: %v", err)
	}
	if len(chunks) != 1 || chunks[0] != "hello" {
		t.Errorf("short text: got %v", chunks)
	}
}

func TestChunkTextEmpty(t *testing.T) {
	chunks, err := ChunkText("")
	if err != nil {
		t.Fatalf("ChunkText: %v", err)
	}
	if len(chunks) != 1 || chunks[0] != "" {
		t.Errorf("empty: got %v", chunks)
	}
}

func TestChunkTextExactWindow(t *testing.T) {
	text := strings.Repeat("a", ChunkWindowChars)
	chunks, err := ChunkText(text)
	if err != nil {
		t.Fatalf("ChunkText: %v", err)
	}
	if len(chunks) != 1 {
		t.Errorf("exact window: got %d chunks, want 1", len(chunks))
	}
}

func TestChunkTextJustOverWindowMatchesTypeScriptSDK(t *testing.T) {
	text := strings.Repeat("a", ChunkWindowChars+1)
	chunks, err := ChunkText(text)
	if err != nil {
		t.Fatalf("ChunkText: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("got %d chunks, want 2", len(chunks))
	}
	if len(chunks[0]) != ChunkWindowChars {
		t.Errorf("first chunk length = %d, want %d", len(chunks[0]), ChunkWindowChars)
	}
	wantSecond := ChunkWindowChars + 1 - (ChunkWindowChars - ChunkOverlapChars)
	if len(chunks[1]) != wantSecond {
		t.Errorf("second chunk length = %d, want %d", len(chunks[1]), wantSecond)
	}
}

func TestChunkTextMultipleWindows(t *testing.T) {
	text := strings.Repeat("a", ChunkWindowChars*3)
	chunks, err := ChunkText(text)
	if err != nil {
		t.Fatalf("ChunkText: %v", err)
	}
	if len(chunks) < 2 {
		t.Errorf("multi-window: got %d chunks, want >= 2", len(chunks))
	}
	for i, c := range chunks {
		if len([]rune(c)) > ChunkWindowChars {
			t.Errorf("chunk %d too large: %d > %d", i, len([]rune(c)), ChunkWindowChars)
		}
	}
}

func TestChunkTextAdjacentChunksShareExactOverlap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < ChunkWindowChars*2; i++ {
		b.WriteByte(byte('a' + (i % 26)))
	}
	chunks, err := ChunkText(b.String())
	if err != nil {
		t.Fatalf("ChunkText: %v", err)
	}
	if len(chunks) < 2 {
		t.Fatalf("expected at least 2 chunks, got %d", len(chunks))
	}
	for i := 1; i < len(chunks); i++ {
		prevTail := chunks[i-1][len(chunks[i-1])-ChunkOverlapChars:]
		currHead := chunks[i][:ChunkOverlapChars]
		if currHead != prevTail {
			t.Fatalf("chunk %d overlap mismatch", i)
		}
	}
}

func TestChunkTextCountFollowsTypeScriptStrideFormula(t *testing.T) {
	length := ChunkWindowChars * 4
	stride := ChunkWindowChars - ChunkOverlapChars
	want := int(math.Ceil(float64(length-ChunkOverlapChars) / float64(stride)))
	chunks, err := ChunkText(strings.Repeat("q", length))
	if err != nil {
		t.Fatalf("ChunkText: %v", err)
	}
	if len(chunks) != want {
		t.Fatalf("got %d chunks, want %d", len(chunks), want)
	}
}

func TestChunkTextOverlapStride(t *testing.T) {
	text := strings.Repeat("a", ChunkWindowChars+ChunkOverlapChars+10)
	chunks, err := ChunkText(text)
	if err != nil {
		t.Fatalf("ChunkText: %v", err)
	}
	if len(chunks) < 2 {
		t.Fatalf("expected at least 2 chunks, got %d", len(chunks))
	}
}

func TestChunkTextOverflow(t *testing.T) {
	text := strings.Repeat("a", MaxInputChars+1)
	_, err := ChunkText(text)
	if err == nil {
		t.Fatal("expected error for overflow, got nil")
	}
}

func TestChunkTextAtLimit(t *testing.T) {
	text := strings.Repeat("a", MaxInputChars)
	_, err := ChunkText(text)
	if err != nil {
		t.Errorf("expected no error at limit, got %v", err)
	}
}

func TestChunkTextMultibyteRunes(t *testing.T) {
	text := strings.Repeat("é", 10)
	chunks, err := ChunkText(text)
	if err != nil {
		t.Fatalf("ChunkText: %v", err)
	}
	if len(chunks) != 1 || chunks[0] != text {
		t.Errorf("multibyte: got %v", chunks)
	}
}
