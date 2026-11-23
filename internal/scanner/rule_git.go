package scanner

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/Jehudavd/gitwasp/internal/model"
)

var reHookNetOrShell = regexp.MustCompile(`(?i)\b(?:curl|wget|nc|ncat|powershell(?:\.exe)?|pwsh|eval)\b|\bnode\s+-e\b|\bpython[23]?\s+-c\b`)

func checkGit(f model.FileEntry) []model.Finding {
	lower := strings.ToLower(f.Path)
	switch {
	case isGitHookFile(lower):
		return checkGitHook(f)
	case lower == ".gitmodules" || strings.HasSuffix(lower, "/.gitmodules"):
		return checkGitmodules(f)
	case lower == ".git/config" || strings.HasSuffix(lower, "/.git/config"):
		return checkGitConfig(f)
	default:
		return nil
	}
}

func isGitHookFile(lower string) bool {
	base := path.Base(lower)
	if strings.HasSuffix(base, ".sample") {
		return false
	}
	if isUnderDir(lower, ".githooks") || isUnderDir(lower, ".git/hooks") {
		return true
	}
	if isUnderDir(lower, ".husky") {
		if strings.Contains(lower, ".husky/_/") || base == "_" {
			return false
		}
		return true
	}
	return false
}

func checkGitHook(f model.FileEntry) []model.Finding {
	lines := splitLines(f.Content)
	var findings []model.Finding

	decoyRun := 0
	decoyFlagged := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		lineNum := i + 1

		if suspicious, reason := SuspiciousCommandMatch(line); suspicious {
			findings = append(findings, model.Finding{
				RuleID:   "GIT-001",
				Title:    "Malicious Payload in Git Hook",
				Severity: model.SeverityCritical,
				File:     f.Path,
				Line:     lineNum,
				Detail:   "Git hook " + reason,
				Snippet:  SanitizeSnippet(trimmed, 140),
			})
		} else if !strings.HasPrefix(trimmed, "#") && reHookNetOrShell.MatchString(trimmed) {
			findings = append(findings, model.Finding{
				RuleID:   "GIT-001",
				Title:    "Network or Inline Interpreter in Git Hook",
				Severity: model.SeverityMedium,
				File:     f.Path,
				Line:     lineNum,
				Detail:   "Git hook invokes network transfer or inline script execution",
				Snippet:  SanitizeSnippet(trimmed, 140),
			})
		}

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			decoyRun++
			continue
		}
		if decoyRun >= 40 && !decoyFlagged {
			decoyFlagged = true
			findings = append(findings, model.Finding{
				RuleID:   "GIT-001",
				Title:    "Hidden Payload Behind Decoy Lines in Git Hook",
				Severity: model.SeverityCritical,
				File:     f.Path,
				Line:     lineNum,
				Detail:   fmt.Sprintf("Executable statement appears after %d consecutive blank/comment lines", decoyRun),
				Snippet:  SanitizeSnippet(trimmed, 140),
			})
		}
		decoyRun = 0
	}

	return findings
}

func checkGitmodules(f model.FileEntry) []model.Finding {
	lines := splitLines(f.Content)
	var findings []model.Finding

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(trimmed[:eq]))
		if key != "url" {
			continue
		}
		val := strings.TrimSpace(trimmed[eq+1:])
		lowerVal := strings.ToLower(val)

		rawIP, ip := HasRawPublicIPURL(val)
		var reason string
		switch {
		case strings.HasPrefix(lowerVal, "ext::"):
			reason = "uses dangerous ext:: remote helper transport"
		case strings.HasPrefix(lowerVal, "file://"):
			reason = "uses local file:// submodule URL"
		case strings.Contains(val, "../") || strings.Contains(val, `..\`):
			reason = "uses relative path traversal (../) in submodule URL"
		case rawIP:
			reason = "points submodule URL to raw IP (" + ip + ")"
		}
		if reason != "" {
			findings = append(findings, model.Finding{
				RuleID:   "GIT-002",
				Title:    "Suspicious Submodule URL in .gitmodules",
				Severity: model.SeverityHigh,
				File:     f.Path,
				Line:     i + 1,
				Detail:   "Submodule " + reason,
				Snippet:  SanitizeSnippet(trimmed, 140),
			})
		}
	}

	return findings
}

func checkGitConfig(f model.FileEntry) []model.Finding {
	lines := splitLines(f.Content)
	var findings []model.Finding
	inCore := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section := strings.ToLower(strings.TrimSpace(trimmed[1 : len(trimmed)-1]))
			inCore = section == "core"
			continue
		}
		if !inCore {
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(trimmed[:eq]))
		val := strings.TrimSpace(trimmed[eq+1:])

		switch key {
		case "fsmonitor":
			findings = append(findings, model.Finding{
				RuleID:   "GIT-003",
				Title:    "Arbitrary Command Execution via core.fsmonitor",
				Severity: model.SeverityCritical,
				File:     f.Path,
				Line:     i + 1,
				Detail:   fmt.Sprintf(".git/config sets core.fsmonitor = %q (runs automatically on git status)", val),
				Snippet:  SanitizeSnippet(trimmed, 140),
			})
		case "sshcommand":
			findings = append(findings, model.Finding{
				RuleID:   "GIT-003",
				Title:    "SSH Command Override via core.sshCommand",
				Severity: model.SeverityCritical,
				File:     f.Path,
				Line:     i + 1,
				Detail:   fmt.Sprintf(".git/config sets core.sshCommand = %q", val),
				Snippet:  SanitizeSnippet(trimmed, 140),
			})
		case "hookspath":
			findings = append(findings, model.Finding{
				RuleID:   "GIT-003",
				Title:    "Custom Hooks Directory via core.hooksPath",
				Severity: model.SeverityHigh,
				File:     f.Path,
				Line:     i + 1,
				Detail:   fmt.Sprintf(".git/config redirects hooks to %q", val),
				Snippet:  SanitizeSnippet(trimmed, 140),
			})
		}
	}

	return findings
}
