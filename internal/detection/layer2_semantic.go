// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package detection

import (
	"math"
	"strings"
)

// SemanticEngine implements Layer 2 semantic detection (~20ms).
// It uses pre-computed embeddings and cosine similarity to detect
// tool descriptions that are semantically similar to known malicious intents.
//
// For v0.1, this uses a bag-of-words + TF-IDF approach as a pure-Go fallback.
// Future versions will integrate ONNX Runtime for full transformer inference.
type SemanticEngine struct {
	intentVectors map[string][]float64
	vocabulary    map[string]int
	idf           map[string]float64
}

// NewSemanticEngine creates a new L2 semantic detection engine.
func NewSemanticEngine() *SemanticEngine {
	e := &SemanticEngine{
		intentVectors: make(map[string][]float64),
		vocabulary:    make(map[string]int),
		idf:           make(map[string]float64),
	}
	e.buildVocabulary()
	return e
}

// CheckIntents compares text against known malicious intents.
// Returns (matched, evidence, confidence).
func (e *SemanticEngine) CheckIntents(text string, intents []string, threshold float64) (bool, string, float64) {
	if len(intents) == 0 {
		return false, "", 0
	}

	textVec := e.vectorize(text)

	var bestScore float64
	var bestIntent string

	for _, intent := range intents {
		intentVec := e.vectorize(intent)
		score := cosineSimilarity(textVec, intentVec)

		if score > bestScore {
			bestScore = score
			bestIntent = intent
		}
	}

	if bestScore >= threshold {
		return true, bestIntent, bestScore
	}

	// Also check for keyword-based semantic matching
	matched, evidence, conf := e.keywordSemanticMatch(text, intents)
	if matched && conf >= threshold {
		return true, evidence, conf
	}

	return false, "", bestScore
}

// buildVocabulary creates the vocabulary and IDF weights from known
// security-relevant terms in MCP tool descriptions.
func (e *SemanticEngine) buildVocabulary() {
	// Security-critical terms with higher IDF weights
	terms := map[string]float64{
		// Data exfiltration indicators
		"exfiltrate": 5.0, "steal": 4.5, "extract": 2.0, "leak": 3.5,
		"send": 1.5, "transmit": 3.0, "upload": 2.0, "post": 1.5,
		"forward": 2.0, "relay": 2.5, "export": 1.5, "transfer": 1.8,

		// Override/bypass indicators
		"override": 3.5, "bypass": 4.0, "ignore": 3.0, "skip": 2.5,
		"disable": 3.0, "circumvent": 4.5, "evade": 4.5, "avoid": 2.0,

		// Permission/access indicators
		"permission": 2.0, "access": 1.5, "credential": 3.0, "token": 2.5,
		"secret": 3.5, "password": 3.5, "key": 2.0, "auth": 2.5,
		"privilege": 3.0, "admin": 2.5, "root": 3.0, "sudo": 4.0,

		// External communication
		"external": 2.5, "endpoint": 1.5, "server": 1.0, "api": 1.0,
		"http": 1.5, "https": 1.0, "url": 1.5, "webhook": 2.5,
		"callback": 2.0, "remote": 2.5, "third-party": 2.5,

		// Filesystem operations
		"file": 1.5, "read": 1.0, "write": 1.5, "delete": 2.5,
		"directory": 1.5, "path": 1.0, "filesystem": 2.0, "disk": 2.0,

		// Code execution
		"execute": 3.0, "eval": 4.0, "exec": 3.5, "run": 1.5,
		"command": 2.0, "shell": 3.5, "bash": 3.0, "powershell": 3.0,
		"system": 2.0, "process": 1.5, "spawn": 3.0,

		// Network
		"network": 1.5, "connect": 1.0, "socket": 2.5, "port": 1.5,
		"dns": 2.5, "request": 1.0, "fetch": 1.5, "download": 2.0,

		// Manipulation
		"inject": 4.0, "poison": 4.5, "manipulate": 3.5, "tamper": 4.0,
		"modify": 1.5, "alter": 2.0, "replace": 1.5, "overwrite": 2.5,
		"hijack": 4.5, "intercept": 3.5, "redirect": 2.5,

		// Scope violations
		"outside": 2.5, "beyond": 2.0, "scope": 2.0, "boundary": 2.5,
		"restricted": 2.5, "unauthorized": 4.0, "forbidden": 3.5,
		"private": 2.5, "sensitive": 2.5, "confidential": 3.0,

		// MCP-specific
		"tool": 1.0, "description": 0.5, "schema": 1.5, "input": 0.5,
		"output": 0.5, "parameter": 1.0, "resource": 1.0, "prompt": 1.5,
		"instruction": 2.5, "context": 1.5, "window": 1.0,
	}

	idx := 0
	for term, idfWeight := range terms {
		e.vocabulary[term] = idx
		e.idf[term] = idfWeight
		idx++
	}
}

// vectorize converts text to a TF-IDF weighted vector.
func (e *SemanticEngine) vectorize(text string) []float64 {
	vec := make([]float64, len(e.vocabulary))
	words := tokenize(text)
	wordCount := make(map[string]int)

	for _, w := range words {
		wordCount[w]++
	}

	totalWords := len(words)
	if totalWords == 0 {
		return vec
	}

	for word, count := range wordCount {
		if idx, ok := e.vocabulary[word]; ok {
			tf := float64(count) / float64(totalWords)
			idf := e.idf[word]
			vec[idx] = tf * idf
		}
	}

	return vec
}

// keywordSemanticMatch does enhanced keyword-based matching with context.
func (e *SemanticEngine) keywordSemanticMatch(text string, intents []string) (bool, string, float64) {
	textLower := strings.ToLower(text)

	for _, intent := range intents {
		intentWords := tokenize(intent)
		matchedWords := 0
		totalWeight := 0.0
		matchedWeight := 0.0

		for _, word := range intentWords {
			weight := 1.0
			if w, ok := e.idf[word]; ok {
				weight = w
			}
			totalWeight += weight

			if strings.Contains(textLower, word) {
				matchedWords++
				matchedWeight += weight
			}
		}

		if totalWeight > 0 {
			score := matchedWeight / totalWeight
			if score >= 0.5 && matchedWords >= 2 {
				return true, intent, score * 0.85 // Scale down since this is keyword-based
			}
		}
	}

	return false, "", 0
}

// tokenize splits text into lowercase words.
func tokenize(text string) []string {
	text = strings.ToLower(text)
	// Replace common separators with spaces
	for _, sep := range []string{"-", "_", "/", ".", ",", ";", ":", "(", ")", "[", "]", "{", "}", "'", "\""} {
		text = strings.ReplaceAll(text, sep, " ")
	}
	words := strings.Fields(text)

	// Filter out very short words
	var result []string
	for _, w := range words {
		if len(w) >= 2 {
			result = append(result, w)
		}
	}
	return result
}

// cosineSimilarity computes the cosine similarity between two vectors.
func cosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}

	var dotProduct, normA, normB float64
	for i := range a {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}
