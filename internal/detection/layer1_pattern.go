// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

// Package detection implements the multi-layer detection engine.
package detection

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/panavinsingh/MCP-Lattice/internal/templates"
)

// PatternEngine implements Layer 1 pattern detection (<1ms).
// It uses regex matching, Unicode analysis, zero-width character detection,
// and base64 payload detection.
type PatternEngine struct {
	compiledCache map[string]*regexp.Regexp
}

// NewPatternEngine creates a new L1 pattern detection engine.
func NewPatternEngine() *PatternEngine {
	return &PatternEngine{
		compiledCache: make(map[string]*regexp.Regexp),
	}
}

// MatchPatterns checks text against a set of patterns and returns
// (matched, evidence, confidence).
func (e *PatternEngine) MatchPatterns(text string, patterns []templates.Pattern) (bool, string, float64) {
	for _, p := range patterns {
		if p.Regex != "" {
			matched, evidence, conf := e.matchRegex(text, p.Regex)
			if matched {
				return true, evidence, conf
			}
		}

		if p.UnicodeTags {
			matched, evidence, conf := e.detectUnicodeTags(text)
			if matched {
				return true, evidence, conf
			}
		}

		if p.ZeroWidth {
			matched, evidence, conf := e.detectZeroWidth(text)
			if matched {
				return true, evidence, conf
			}
		}

		if p.Base64Check {
			matched, evidence, conf := e.detectBase64Payloads(text)
			if matched {
				return true, evidence, conf
			}
		}

		if p.Homoglyphs {
			matched, evidence, conf := e.detectHomoglyphs(text)
			if matched {
				return true, evidence, conf
			}
		}
	}

	return false, "", 0
}

// matchRegex compiles and matches a regex pattern against text.
func (e *PatternEngine) matchRegex(text, pattern string) (bool, string, float64) {
	re, ok := e.compiledCache[pattern]
	if !ok {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			return false, "", 0
		}
		e.compiledCache[pattern] = re
	}

	match := re.FindString(text)
	if match != "" {
		// Truncate evidence to reasonable length
		evidence := match
		if len(evidence) > 200 {
			evidence = evidence[:200] + "..."
		}
		return true, fmt.Sprintf("pattern match: %q", evidence), 0.85
	}

	return false, "", 0
}

// detectUnicodeTags finds Unicode tag characters (U+E0001-U+E007F)
// used to embed invisible instructions.
func (e *PatternEngine) detectUnicodeTags(text string) (bool, string, float64) {
	var found []string

	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if r >= 0xE0001 && r <= 0xE007F {
			found = append(found, fmt.Sprintf("U+%04X", r))
		}
		i += size
	}

	if len(found) > 0 {
		return true, fmt.Sprintf("Unicode tag characters detected: %s", strings.Join(found[:min(5, len(found))], ", ")), 0.95
	}

	return false, "", 0
}

// detectZeroWidth finds zero-width characters that can hide text.
func (e *PatternEngine) detectZeroWidth(text string) (bool, string, float64) {
	zeroWidthChars := map[rune]string{
		'\u200B': "ZERO WIDTH SPACE",
		'\u200C': "ZERO WIDTH NON-JOINER",
		'\u200D': "ZERO WIDTH JOINER",
		'\uFEFF': "ZERO WIDTH NO-BREAK SPACE",
		'\u00AD': "SOFT HYPHEN",
		'\u200E': "LEFT-TO-RIGHT MARK",
		'\u200F': "RIGHT-TO-LEFT MARK",
		'\u2060': "WORD JOINER",
		'\u2061': "FUNCTION APPLICATION",
		'\u2062': "INVISIBLE TIMES",
		'\u2063': "INVISIBLE SEPARATOR",
		'\u2064': "INVISIBLE PLUS",
	}

	var found []string
	count := 0

	for _, r := range text {
		if name, ok := zeroWidthChars[r]; ok {
			count++
			if count <= 3 {
				found = append(found, name)
			}
		}
	}

	// A few zero-width chars might be legitimate, but many indicate obfuscation
	if count >= 2 {
		return true, fmt.Sprintf("%d zero-width characters detected: %s", count, strings.Join(found, ", ")), 0.9
	}

	return false, "", 0
}

// detectBase64Payloads finds base64-encoded content that may contain
// hidden instructions when decoded.
func (e *PatternEngine) detectBase64Payloads(text string) (bool, string, float64) {
	// Look for base64-like strings (at least 20 chars of base64)
	re := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	matches := re.FindAllString(text, -1)

	suspiciousKeywords := []string{
		"ignore", "system", "execute", "eval", "exec",
		"curl", "wget", "http", "fetch", "bash", "powershell",
		"rm ", "del ", "format", "password", "token", "secret",
		"override", "bypass", "admin", "root",
	}

	for _, match := range matches {
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err != nil {
			// Try URL-safe base64
			decoded, err = base64.URLEncoding.DecodeString(match)
			if err != nil {
				continue
			}
		}

		decodedStr := strings.ToLower(string(decoded))

		// Check if decoded content contains suspicious keywords
		for _, keyword := range suspiciousKeywords {
			if strings.Contains(decodedStr, keyword) {
				truncated := string(decoded)
				if len(truncated) > 100 {
					truncated = truncated[:100] + "..."
				}
				return true, fmt.Sprintf("base64-encoded suspicious content: %q", truncated), 0.8
			}
		}

		// Check if decoded content looks like a command or URL
		if strings.HasPrefix(decodedStr, "http") || strings.Contains(decodedStr, "://") {
			return true, fmt.Sprintf("base64-encoded URL detected: %q", string(decoded)[:min(100, len(decoded))]), 0.75
		}
	}

	return false, "", 0
}

// detectHomoglyphs finds characters from different scripts that look like
// ASCII characters (e.g., Cyrillic 'а' vs Latin 'a').
func (e *PatternEngine) detectHomoglyphs(text string) (bool, string, float64) {
	// Map of homoglyph characters to their ASCII equivalents
	homoglyphs := map[rune]rune{
		'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', // Cyrillic
		'х': 'x', 'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M',
		'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
		'ɑ': 'a', 'ɡ': 'g', 'ɪ': 'I', 'ɴ': 'N', // IPA
		'ℓ': 'l', 'ℰ': 'E', 'ℱ': 'F', 'ℋ': 'H', // Math symbols
	}

	var found []string
	mixedScripts := false
	hasASCII := false
	hasNonASCII := false

	for _, r := range text {
		if r < 128 && unicode.IsLetter(r) {
			hasASCII = true
		}
		if _, isHomoglyph := homoglyphs[r]; isHomoglyph {
			hasNonASCII = true
			found = append(found, fmt.Sprintf("U+%04X", r))
		}
	}

	if hasASCII && hasNonASCII {
		mixedScripts = true
	}

	if mixedScripts && len(found) > 0 {
		return true, fmt.Sprintf("homoglyph characters detected (mixed scripts): %s", strings.Join(found[:min(5, len(found))], ", ")), 0.9
	}

	return false, "", 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
