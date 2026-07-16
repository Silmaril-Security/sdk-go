// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"strings"
	"unicode/utf8"
)

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
