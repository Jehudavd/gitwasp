package scanner

import (
	"bytes"
	"fmt"
	"path"
	"strings"

	"github.com/Jehudavd/gitwasp/internal/model"
)

var scriptExtensions = map[string]bool{
	".sh":  true,
	".ps1": true,
	".bat": true,
	".cmd": true,
	".js":  true,
	".mjs": true,
	".cjs": true,
}

func checkObf(f model.FileEntry) []model.Finding {
	var findings []model.Finding

	if f0 := checkHiddenUnicode(f); f0 != nil {
		findings = append(findings, *f0)
	}
	findings = append(findings, checkHorizontalPadding(f)...)

	ext := strings.ToLower(path.Ext(f.Path))
	if scriptExtensions[ext] {
		findings = append(findings, checkScriptObfuscation(f)...)
	}

	return findings
}

func checkHiddenUnicode(f model.FileEntry) *model.Finding {
	content := f.Content
	// Allow a single leading UTF-8 BOM at byte 0.
	content = bytes.TrimPrefix(content, []byte{0xEF, 0xBB, 0xBF})

	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")

	total := 0
	firstLine := 0
	firstCol := 0
	firstLineText := ""
	hasBiDi := false
	hasTag := false
	onlyBOM := true

	for i, line := range lines {
		col := 0
		for _, r := range line {
			col++
			cat := ClassifyHiddenRune(r)
			if cat == HiddenNone {
				continue
			}
			total++
			if r != 0xFEFF {
				onlyBOM = false
			}
			if firstLine == 0 {
				firstLine = i + 1
				firstCol = col
				firstLineText = line
			}
			switch cat {
			case HiddenBiDi:
				hasBiDi = true
			case HiddenTag:
				hasTag = true
			}
		}
	}

	if total == 0 {
		return nil
	}

	sev := model.SeverityHigh
	kind := "zero-width invisible"
	if hasBiDi || hasTag {
		sev = model.SeverityCritical
		if hasBiDi && hasTag {
			kind = "BiDi override & Unicode tag"
		} else if hasBiDi {
			kind = "BiDi override (Trojan Source)"
		} else {
			kind = "Unicode tag"
		}
	}

	detail := fmt.Sprintf("Detected %d hidden %s character(s); first at line %d col %d", total, kind, firstLine, firstCol)
	if !hasBiDi && !hasTag && onlyBOM && isTestFilePath(f.Path) {
		sev = model.SeverityLow
		detail = fmt.Sprintf("Detected %d UTF-8 BOM (U+FEFF) character(s) in test file (likely BOM-handling fixture); first at line %d col %d", total, firstLine, firstCol)
	}

	return &model.Finding{
		RuleID:    "OBF-001",
		Title:     "Hidden Unicode / Trojan Source Characters",
		Severity:  sev,
		File:      f.Path,
		Line:      firstLine,
		Column:    firstCol,
		Detail:    detail,
		Snippet:   SanitizeSnippet(firstLineText, 140),
		Reference: "CVE-2021-42574 (Trojan Source) / GlassWorm",
	}
}

func isTestFilePath(p string) bool {
	lower := strings.ToLower(strings.ReplaceAll(p, `\`, `/`))
	base := path.Base(lower)
	if strings.Contains(base, "_test.") || strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") {
		return true
	}
	for _, seg := range []string{"/tests/", "/test/", "/__tests__/"} {
		if strings.Contains(lower, seg) {
			return true
		}
	}
	for _, prefix := range []string{"tests/", "test/", "__tests__/"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func checkHorizontalPadding(f model.FileEntry) []model.Finding {
	lines := splitLines(f.Content)
	isMarkdown := strings.EqualFold(path.Ext(f.Path), ".md")
	var findings []model.Finding

	for i, line := range lines {
		runStart, runLen, tail := findLargeWhitespaceGap(line)
		if runLen == 0 {
			continue
		}
		if isMarkdown && isBenignMarkdownTablePadding(line, tail) {
			continue
		}
		findings = append(findings, model.Finding{
			RuleID:   "OBF-002",
			Title:    "Horizontal Whitespace Scroll-Hiding",
			Severity: model.SeverityHigh,
			File:     f.Path,
			Line:     i + 1,
			Column:   runStart,
			Detail:   fmt.Sprintf("Line hides code past %d consecutive whitespace characters", runLen),
			Snippet:  SanitizeSnippet(tail, 140),
		})
	}
	return findings
}

func isBenignMarkdownTablePadding(line, tail string) bool {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "|") || !strings.HasSuffix(trimmed, "|") {
		return false
	}
	if suspicious, _ := SuspiciousCommandMatch(tail); suspicious {
		return false
	}
	if reStrongInjection.MatchString(tail) || reWeakStealth.MatchString(tail) {
		return false
	}
	return true
}

func findLargeWhitespaceGap(line string) (startCol int, gapLen int, tail string) {
	spaceRun := 0
	tabRun := 0
	runStartCol := 0
	col := 0

	for idx, r := range line {
		col++
		switch r {
		case ' ':
			if spaceRun == 0 {
				runStartCol = col
			}
			spaceRun++
			tabRun = 0
		case '\t':
			if tabRun == 0 {
				runStartCol = col
			}
			tabRun++
			spaceRun = 0
		default:
			if spaceRun >= 200 || tabRun >= 40 {
				gl := spaceRun
				if tabRun > gl {
					gl = tabRun
				}
				return runStartCol, gl, strings.TrimSpace(line[idx:])
			}
			spaceRun = 0
			tabRun = 0
		}
	}
	return 0, 0, ""
}

func checkScriptObfuscation(f model.FileEntry) []model.Finding {
	lines := splitLines(f.Content)
	var findings []model.Finding

	for i, line := range lines {
		lineNum := i + 1
		var reason string
		switch {
		case reDisguisedAsset.MatchString(line):
			reason = "executes disguised non-code asset file"
		case reBufferB64.MatchString(line) && (reEvalCall.MatchString(line) || reNewFunc.MatchString(line)):
			reason = "evaluates Base64-decoded payload dynamically"
		case rePipeToShell.MatchString(line) || rePSPipeIEX.MatchString(line):
			reason = "downloads remote script and pipes directly to shell"
		}
		if reason != "" {
			findings = append(findings, model.Finding{
				RuleID:   "OBF-003",
				Title:    "High-Risk Obfuscated or Disguised Script Payload",
				Severity: model.SeverityCritical,
				File:     f.Path,
				Line:     lineNum,
				Detail:   "Script " + reason,
				Snippet:  SanitizeSnippet(line, 140),
			})
		}
	}
	return findings
}
