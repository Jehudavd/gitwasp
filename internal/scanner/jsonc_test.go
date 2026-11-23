package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStripJSONC(t *testing.T) {
	input := "\xEF\xBB\xBF" + `{
  // single-line comment with fake "quote" and URL https://ignore.example.invalid
  "url": "https://example.invalid/path?a=1//keep",
  "escaped": "hello \"//not-a-comment\" /*also-keep*/",
  /* multi-line
     block comment */
  "items": [
    "one",
    "two",
  ],
}`

	stripped := StripJSONC([]byte(input))

	var parsed map[string]any
	if err := json.Unmarshal(stripped, &parsed); err != nil {
		t.Fatalf("StripJSONC output is not valid JSON: %v\nOutput:\n%s", err, string(stripped))
	}

	if parsed["url"] != "https://example.invalid/path?a=1//keep" {
		t.Fatalf("URL inside string was corrupted: %v", parsed["url"])
	}
	if parsed["escaped"] != `hello "//not-a-comment" /*also-keep*/` {
		t.Fatalf("escaped string was corrupted: %v", parsed["escaped"])
	}

	// Verify line count is preserved so line numbers remain aligned.
	inLines := strings.Count(strings.TrimPrefix(input, "\xEF\xBB\xBF"), "\n")
	outLines := strings.Count(string(stripped), "\n")
	if inLines != outLines {
		t.Fatalf("line count drifted: got %d, want %d", outLines, inLines)
	}
}

func TestFindLine(t *testing.T) {
	content := []byte("line one\nline two\n\"folderOpen\"\nline four\n")
	if got := FindLine(content, "folderOpen"); got != 3 {
		t.Fatalf("FindLine got %d, want 3", got)
	}
	if got := FindLine(content, "missing"); got != 1 {
		t.Fatalf("FindLine missing needle got %d, want 1", got)
	}
}
