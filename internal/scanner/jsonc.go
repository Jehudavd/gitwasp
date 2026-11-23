package scanner

import "strings"

// StripJSONC removes single-line (//) comments, block (/* */) comments, and
// trailing commas before '}' or ']' while preserving string literals and
// newline characters (so line numbers stay aligned with the original input).
func StripJSONC(input []byte) []byte {
	// Strip UTF-8 BOM if present.
	if len(input) >= 3 && input[0] == 0xEF && input[1] == 0xBB && input[2] == 0xBF {
		input = input[3:]
	}

	// Pass 1: strip // and /* */ comments outside string literals.
	noComments := make([]byte, 0, len(input))
	inString := false
	escaped := false
	inLineComment := false
	inBlockComment := false

	for i := 0; i < len(input); i++ {
		b := input[i]

		if inLineComment {
			if b == '\n' {
				inLineComment = false
				noComments = append(noComments, '\n')
			}
			continue
		}

		if inBlockComment {
			if b == '\n' {
				noComments = append(noComments, '\n')
				continue
			}
			if b == '*' && i+1 < len(input) && input[i+1] == '/' {
				inBlockComment = false
				i++
			}
			continue
		}

		if inString {
			noComments = append(noComments, b)
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				escaped = true
				continue
			}
			if b == '"' {
				inString = false
			}
			continue
		}

		// Outside string and comments.
		if b == '"' {
			inString = true
			noComments = append(noComments, b)
			continue
		}
		if b == '/' && i+1 < len(input) {
			next := input[i+1]
			if next == '/' {
				inLineComment = true
				i++
				continue
			}
			if next == '*' {
				inBlockComment = true
				i++
				continue
			}
		}

		noComments = append(noComments, b)
	}

	// Pass 2: remove trailing commas before '}' or ']' outside string literals.
	out := make([]byte, 0, len(noComments))
	inString = false
	escaped = false

	for i := 0; i < len(noComments); i++ {
		b := noComments[i]

		if inString {
			out = append(out, b)
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				escaped = true
				continue
			}
			if b == '"' {
				inString = false
			}
			continue
		}

		if b == '"' {
			inString = true
			out = append(out, b)
			continue
		}

		if b == ',' {
			j := i + 1
			for j < len(noComments) && isJSONWhitespace(noComments[j]) {
				j++
			}
			if j < len(noComments) && (noComments[j] == '}' || noComments[j] == ']') {
				// Skip trailing comma.
				continue
			}
		}

		out = append(out, b)
	}

	return out
}

func isJSONWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

// FindLine returns the 1-based line number of the first occurrence of needle in content.
// If needle is empty or not found, it returns 1.
func FindLine(content []byte, needle string) int {
	if needle == "" || len(content) == 0 {
		return 1
	}
	text := string(content)
	idx := strings.Index(text, needle)
	if idx < 0 {
		return 1
	}
	return 1 + strings.Count(text[:idx], "\n")
}

// FindLineAny returns the 1-based line number of the first matched needle, or 1.
func FindLineAny(content []byte, needles ...string) int {
	best := -1
	text := string(content)
	for _, n := range needles {
		if n == "" {
			continue
		}
		if idx := strings.Index(text, n); idx >= 0 && (best < 0 || idx < best) {
			best = idx
		}
	}
	if best < 0 {
		return 1
	}
	return 1 + strings.Count(text[:best], "\n")
}
