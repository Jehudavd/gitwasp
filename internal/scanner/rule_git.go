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
	lower := strings.ToLower(strings.ReplaceAll(f.Path, `\`, `/`))
	switch {
	case isGitHookFile(lower):
		return checkGitHook(f)
	case lower == ".gitmodules" || strings.HasSuffix(lower, "/.gitmodules"):
		return checkGitmodules(f)
	case lower == ".git/config" || strings.HasSuffix(lower, "/.git/config"):
		return checkGitConfig(f)
	case path.Base(lower) == ".gitattributes" || lower == ".git/info/attributes" || strings.HasSuffix(lower, "/.git/info/attributes"):
		return checkGitAttributes(f)
	case isUnexpectedGitRootFile(lower):
		return checkUnexpectedGitFile(f)
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

var standardGitRootFileNames = map[string]bool{
	"config":              true,
	"head":                true,
	"fetch_head":          true,
	"orig_head":           true,
	"commit_editmsg":      true,
	"merge_head":          true,
	"merge_msg":           true,
	"merge_mode":          true,
	"merge_rr":            true,
	"cherry_pick_head":    true,
	"revert_head":         true,
	"auto_merge":          true,
	"index":               true,
	"index.lock":          true,
	"packed-refs":         true,
	"description":         true,
	"shallow":             true,
	"gc.log":              true,
	"config.worktree":     true,
	"bisect_expected_rev": true,
	"bisect_log":          true,
	"bisect_names":        true,
	"bisect_run":          true,
	"bisect_start":        true,
	"bisect_terms":        true,
	"editmsg":             true,
	"squash_msg":          true,
	"tag_editmsg":         true,
}

var standardCredentialHelpers = map[string]bool{
	"manager":       true,
	"manager-core":  true,
	"osxkeychain":   true,
	"cache":         true,
	"store":         true,
	"libsecret":     true,
	"wincred":       true,
	"gnome-keyring": true,
	"netrc":         true,
	"gcm":           true,
}

var builtinGitDiffDrivers = map[string]bool{
	"ada":         true,
	"astextplain": true,
	"bash":        true,
	"bibtex":      true,
	"cpp":         true,
	"csharp":      true,
	"css":         true,
	"dts":         true,
	"elixir":      true,
	"fortran":     true,
	"fountain":    true,
	"golang":      true,
	"html":        true,
	"java":        true,
	"kotlin":      true,
	"lfs":         true,
	"matlab":      true,
	"objc":        true,
	"pascal":      true,
	"perl":        true,
	"php":         true,
	"python":      true,
	"ruby":        true,
	"rust":        true,
	"scheme":      true,
	"tex":         true,
}

func isUnexpectedGitRootFile(lowerSlash string) bool {
	norm := path.Clean(lowerSlash)
	dir := path.Dir(norm)
	if dir != ".git" && !strings.HasSuffix(dir, "/.git") {
		return false
	}
	return !standardGitRootFileNames[path.Base(norm)]
}

func parseGitConfigSection(trimmed string) (section, subsection string, ok bool) {
	if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
		return "", "", false
	}
	inner := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	if inner == "" {
		return "", "", false
	}
	idx := strings.IndexAny(inner, " \t")
	if idx < 0 {
		return strings.ToLower(inner), "", true
	}
	sec := strings.ToLower(strings.TrimSpace(inner[:idx]))
	sub := strings.Trim(strings.TrimSpace(inner[idx+1:]), `"`)
	return sec, sub, true
}

func isGitExecPath(val string) bool {
	if isRepoRelativePath(val) {
		return true
	}
	trimmed := strings.TrimSpace(val)
	lower := strings.ToLower(strings.ReplaceAll(trimmed, `\`, `/`))
	return strings.HasPrefix(lower, ".git/") || strings.Contains(lower, " .git/") || strings.HasPrefix(trimmed, `"`) && strings.Contains(lower, ".git/")
}

func isStandardCredentialHelper(val string) bool {
	norm := strings.ToLower(strings.TrimSpace(val))
	if norm == "" {
		return true
	}
	fields := strings.Fields(norm)
	if len(fields) == 0 {
		return true
	}
	first := strings.Trim(fields[0], `"'`)
	if standardCredentialHelpers[first] {
		return true
	}
	if !strings.HasPrefix(norm, "!.") && strings.Contains(norm, "gh auth git-credential") {
		return true
	}
	return false
}

func checkGitConfig(f model.FileEntry) []model.Finding {
	lines := splitLines(f.Content)
	var findings []model.Finding
	section := ""
	subsection := ""

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if sec, sub, ok := parseGitConfigSection(trimmed); ok {
			section = sec
			subsection = sub
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(trimmed[:eq]))
		val := strings.TrimSpace(trimmed[eq+1:])
		lineNum := i + 1
		snippet := SanitizeSnippet(trimmed, 140)

		switch section {
		case "core":
			switch key {
			case "fsmonitor":
				findings = append(findings, model.Finding{
					RuleID:   "GIT-003",
					Title:    "Arbitrary Command Execution via core.fsmonitor",
					Severity: model.SeverityCritical,
					File:     f.Path,
					Line:     lineNum,
					Detail:   fmt.Sprintf(".git/config sets core.fsmonitor = %q (runs automatically on git status)", val),
					Snippet:  snippet,
				})
			case "sshcommand":
				findings = append(findings, model.Finding{
					RuleID:   "GIT-003",
					Title:    "SSH Command Override via core.sshCommand",
					Severity: model.SeverityCritical,
					File:     f.Path,
					Line:     lineNum,
					Detail:   fmt.Sprintf(".git/config sets core.sshCommand = %q", val),
					Snippet:  snippet,
				})
			case "hookspath":
				findings = append(findings, model.Finding{
					RuleID:   "GIT-003",
					Title:    "Custom Hooks Directory via core.hooksPath",
					Severity: model.SeverityHigh,
					File:     f.Path,
					Line:     lineNum,
					Detail:   fmt.Sprintf(".git/config redirects hooks to %q", val),
					Snippet:  snippet,
				})
			case "askpass":
				findings = append(findings, model.Finding{
					RuleID:   "GIT-003",
					Title:    "AskPass Program Override via core.askPass",
					Severity: model.SeverityCritical,
					File:     f.Path,
					Line:     lineNum,
					Detail:   fmt.Sprintf(".git/config overrides core.askPass = %q (can intercept credentials or execute code)", val),
					Snippet:  snippet,
				})
			case "pager", "editor", "sequenceeditor":
				sev := model.SeverityHigh
				if suspicious, _ := SuspiciousCommandMatch(val); suspicious || isGitExecPath(val) {
					sev = model.SeverityCritical
				}
				findings = append(findings, model.Finding{
					RuleID:   "GIT-003",
					Title:    fmt.Sprintf("Executable Override via core.%s", key),
					Severity: sev,
					File:     f.Path,
					Line:     lineNum,
					Detail:   fmt.Sprintf(".git/config sets core.%s = %q (executes automatically during Git operations)", key, val),
					Snippet:  snippet,
				})
			}

		case "filter":
			if key == "clean" || key == "smudge" || key == "process" {
				label := key
				if subsection != "" {
					label = fmt.Sprintf("filter.%s.%s", subsection, key)
				}
				findings = append(findings, model.Finding{
					RuleID:    "GIT-003",
					Title:     fmt.Sprintf("Git Filter Auto-Execution (%s)", label),
					Severity:  model.SeverityCritical,
					File:      f.Path,
					Line:      lineNum,
					Detail:    fmt.Sprintf(".git/config configures %s = %q (executes automatically on git status/checkout)", label, val),
					Snippet:   snippet,
					Reference: "Git clean/smudge filter auto-execution (Contagious Interview)",
				})
			}

		case "diff":
			if key == "external" || key == "textconv" || key == "command" {
				findings = append(findings, model.Finding{
					RuleID:   "GIT-003",
					Title:    fmt.Sprintf("Git Diff Driver Command Execution (diff.%s)", key),
					Severity: model.SeverityCritical,
					File:     f.Path,
					Line:     lineNum,
					Detail:   fmt.Sprintf(".git/config sets diff.%s = %q (executes automatically on git diff/status)", key, val),
					Snippet:  snippet,
				})
			}

		case "merge":
			if key == "driver" {
				sev := model.SeverityHigh
				if suspicious, _ := SuspiciousCommandMatch(val); suspicious {
					sev = model.SeverityCritical
				}
				findings = append(findings, model.Finding{
					RuleID:   "GIT-003",
					Title:    "Git Merge Driver Execution (merge.driver)",
					Severity: sev,
					File:     f.Path,
					Line:     lineNum,
					Detail:   fmt.Sprintf(".git/config defines merge.driver = %q", val),
					Snippet:  snippet,
				})
			}

		case "credential":
			if key == "helper" && !isStandardCredentialHelper(val) {
				suspicious, _ := SuspiciousCommandMatch(val)
				isBang := strings.HasPrefix(strings.TrimSpace(val), "!")
				if suspicious || isBang || isGitExecPath(val) {
					sev := model.SeverityHigh
					if suspicious {
						sev = model.SeverityCritical
					}
					findings = append(findings, model.Finding{
						RuleID:   "GIT-003",
						Title:    "Custom Credential Helper Execution in .git/config",
						Severity: sev,
						File:     f.Path,
						Line:     lineNum,
						Detail:   fmt.Sprintf(".git/config overrides credential.helper = %q", val),
						Snippet:  snippet,
					})
				}
			}

		case "alias":
			if strings.HasPrefix(strings.TrimSpace(val), "!") {
				sev := model.SeverityHigh
				if suspicious, _ := SuspiciousCommandMatch(val); suspicious {
					sev = model.SeverityCritical
				}
				findings = append(findings, model.Finding{
					RuleID:   "GIT-003",
					Title:    "Shell Alias Defined in .git/config",
					Severity: sev,
					File:     f.Path,
					Line:     lineNum,
					Detail:   fmt.Sprintf(".git/config defines shell-executing alias %q = %q", key, val),
					Snippet:  snippet,
				})
			}

		case "include", "includeif":
			if key == "path" && val != "" {
				findings = append(findings, model.Finding{
					RuleID:   "GIT-003",
					Title:    "External Config Include in .git/config",
					Severity: model.SeverityHigh,
					File:     f.Path,
					Line:     lineNum,
					Detail:   fmt.Sprintf(".git/config includes external/hidden config path %q", val),
					Snippet:  snippet,
				})
			}
		}
	}

	return findings
}

func checkGitAttributes(f model.FileEntry) []model.Finding {
	lines := splitLines(f.Content)
	lowerPath := strings.ToLower(strings.ReplaceAll(f.Path, `\`, `/`))
	isHiddenInfoAttrs := lowerPath == ".git/info/attributes" || strings.HasSuffix(lowerPath, "/.git/info/attributes")

	var findings []model.Finding
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		lineNum := i + 1
		snippet := SanitizeSnippet(trimmed, 140)

		for _, tok := range fields[1:] {
			tl := strings.ToLower(tok)
			if strings.HasPrefix(tl, "filter=") {
				drv := strings.TrimPrefix(tl, "filter=")
				if drv == "" || drv == "lfs" {
					continue
				}
				sev := model.SeverityHigh
				title := "Custom Git Filter Attribute in .gitattributes"
				detail := fmt.Sprintf(".gitattributes maps %q to custom filter %q (executes clean/smudge driver if configured)", fields[0], tok[len("filter="):])
				if isHiddenInfoAttrs {
					sev = model.SeverityCritical
					title = "Custom Git Filter in .git/info/attributes"
					detail = fmt.Sprintf("Hidden .git/info/attributes maps %q to filter %q (triggers .git/config filter automatically on git status/checkout)", fields[0], tok[len("filter="):])
				}
				findings = append(findings, model.Finding{
					RuleID:    "GIT-004",
					Title:     title,
					Severity:  sev,
					File:      f.Path,
					Line:      lineNum,
					Detail:    detail,
					Snippet:   snippet,
					Reference: "Git clean/smudge filter auto-execution (Contagious Interview)",
				})
				break
			}
			if strings.HasPrefix(tl, "diff=") {
				drv := strings.TrimPrefix(tl, "diff=")
				if drv == "" || builtinGitDiffDrivers[drv] {
					continue
				}
				findings = append(findings, model.Finding{
					RuleID:   "GIT-004",
					Title:    "Custom Git Diff Driver Attribute",
					Severity: model.SeverityMedium,
					File:     f.Path,
					Line:     lineNum,
					Detail:   fmt.Sprintf("Git attributes map %q to custom diff driver %q", fields[0], tok[len("diff="):]),
					Snippet:  snippet,
				})
			}
		}
	}

	return findings
}

func checkUnexpectedGitFile(f model.FileEntry) []model.Finding {
	contentStr := string(f.Content)
	trimmed := strings.TrimSpace(contentStr)
	suspicious, reason := SuspiciousCommandMatch(contentStr)
	isExec := strings.HasPrefix(trimmed, "#!") || suspicious || reHookNetOrShell.MatchString(contentStr)

	sev := model.SeverityHigh
	title := "Unexpected File Inside .git Directory"
	detail := fmt.Sprintf("Non-standard file %q found inside .git/ directory (can be invoked by hidden .git/config filters or hooks)", f.Path)
	if isExec {
		sev = model.SeverityCritical
		title = "Unexpected Executable Script Inside .git Directory"
		if suspicious {
			detail = fmt.Sprintf("Non-standard script inside .git/ (%s)", reason)
		} else {
			detail = fmt.Sprintf("Non-standard executable script %q placed directly inside .git/ directory", f.Path)
		}
	}

	firstLine := ""
	for _, l := range splitLines(f.Content) {
		if strings.TrimSpace(l) != "" {
			firstLine = l
			break
		}
	}

	return []model.Finding{{
		RuleID:    "GIT-004",
		Title:     title,
		Severity:  sev,
		File:      f.Path,
		Line:      1,
		Detail:    detail,
		Snippet:   SanitizeSnippet(firstLine, 140),
		Reference: "Trojanized .git archive vector (Contagious Interview)",
	}}
}
