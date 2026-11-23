package scanner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/Jehudavd/gitwasp/internal/model"
)

var benignPackageScripts = map[string]bool{
	"husky":           true,
	"husky install":   true,
	"prisma generate": true,
	"patch-package":   true,
	"svelte-kit sync": true,
	"nuxt prepare":    true,
}

var (
	reEnvrcExec    = regexp.MustCompile(`(?i)(?:\b(?:curl|wget|eval|source|bash|sh|zsh|python[23]?|node|exec)\b|\$\(|` + "`" + `)`)
	reSetupExec    = regexp.MustCompile(`(?i)\b(?:os\.system|subprocess\.(?:run|Popen|call|check_output|check_call)|Popen)\b`)
	reSetupNetObf  = regexp.MustCompile(`(?i)\b(?:urllib|requests|http\.client|socket|curl|wget|base64|b64decode|eval|exec)\b`)
	reSetupObfHigh = regexp.MustCompile(`(?i)\b(?:base64|b64decode|eval|exec)\b`)
)

func checkPkg(f model.FileEntry) []model.Finding {
	base := strings.ToLower(path.Base(f.Path))
	switch base {
	case "package.json":
		return checkPackageJSON(f)
	case ".npmrc":
		return checkNPMRC(f)
	case ".envrc":
		return checkEnvrc(f)
	case "setup.py":
		return checkSetupPy(f)
	default:
		return nil
	}
}

func checkPackageJSON(f model.FileEntry) []model.Finding {
	var doc struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(f.Content, &doc); err != nil {
		return nil
	}

	installHooks := map[string]bool{
		"preinstall":  true,
		"install":     true,
		"postinstall": true,
	}
	otherLifecycleHooks := map[string]bool{
		"prepare":        true,
		"preprepare":     true,
		"postprepare":    true,
		"prepublish":     true,
		"prepublishonly": true,
	}

	var findings []model.Finding
	for scriptName, cmd := range doc.Scripts {
		keyLower := strings.ToLower(scriptName)
		if !installHooks[keyLower] && !otherLifecycleHooks[keyLower] {
			continue
		}

		normCmd := strings.ToLower(strings.TrimSpace(cmd))
		if normCmd == "" || benignPackageScripts[normCmd] {
			continue
		}

		line := FindLineAny(f.Content, fmt.Sprintf("%q", scriptName), cmd)
		if suspicious, reason := SuspiciousCommandMatch(cmd); suspicious {
			findings = append(findings, model.Finding{
				RuleID:   "PKG-001",
				Title:    "Suspicious Package Lifecycle Script",
				Severity: model.SeverityCritical,
				File:     f.Path,
				Line:     line,
				Detail:   fmt.Sprintf("Script %q %s", scriptName, reason),
				Snippet:  SanitizeSnippet(fmt.Sprintf("%s: %s", scriptName, cmd), 140),
			})
			continue
		}

		if installHooks[keyLower] {
			findings = append(findings, model.Finding{
				RuleID:   "PKG-001",
				Title:    "Non-Allowlisted Install Lifecycle Script",
				Severity: model.SeverityMedium,
				File:     f.Path,
				Line:     line,
				Detail:   fmt.Sprintf("Script %q runs automatically on npm/pnpm/yarn install", scriptName),
				Snippet:  SanitizeSnippet(fmt.Sprintf("%s: %s", scriptName, cmd), 140),
			})
		}
	}

	return findings
}

var allowedNPMHosts = map[string]bool{
	"registry.npmjs.org":   true,
	"registry.yarnpkg.com": true,
	"npm.pkg.github.com":   true,
}

func checkNPMRC(f model.FileEntry) []model.Finding {
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
		val := strings.Trim(strings.TrimSpace(trimmed[eq+1:]), `"'`)

		if key == "registry" || strings.HasSuffix(key, ":registry") {
			u, err := url.Parse(val)
			host := ""
			if err == nil {
				host = strings.ToLower(u.Hostname())
			}
			if !allowedNPMHosts[host] {
				findings = append(findings, model.Finding{
					RuleID:   "PKG-002",
					Title:    "Custom Package Registry Override in .npmrc",
					Severity: model.SeverityHigh,
					File:     f.Path,
					Line:     i + 1,
					Detail:   fmt.Sprintf("%s points to non-standard registry %q (potential dependency confusion/malware host)", key, val),
					Snippet:  SanitizeSnippet(trimmed, 140),
				})
			}
		}

		if key == "onload-script" || key == "script-shell" {
			findings = append(findings, model.Finding{
				RuleID:   "PKG-002",
				Title:    "Package Manager Execution Hook in .npmrc",
				Severity: model.SeverityHigh,
				File:     f.Path,
				Line:     i + 1,
				Detail:   fmt.Sprintf(".npmrc overrides %q to %q", key, val),
				Snippet:  SanitizeSnippet(trimmed, 140),
			})
		}
	}

	return findings
}

func checkEnvrc(f model.FileEntry) []model.Finding {
	lines := splitLines(f.Content)
	var findings []model.Finding

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if suspicious, reason := SuspiciousCommandMatch(trimmed); suspicious {
			findings = append(findings, model.Finding{
				RuleID:   "PKG-003",
				Title:    "Suspicious Command in .envrc (direnv)",
				Severity: model.SeverityCritical,
				File:     f.Path,
				Line:     i + 1,
				Detail:   "direnv .envrc " + reason,
				Snippet:  SanitizeSnippet(trimmed, 140),
			})
			continue
		}
		if reEnvrcExec.MatchString(trimmed) {
			findings = append(findings, model.Finding{
				RuleID:   "PKG-003",
				Title:    "Executable Command in .envrc (direnv)",
				Severity: model.SeverityMedium,
				File:     f.Path,
				Line:     i + 1,
				Detail:   "direnv executes shell commands automatically when allowed in this directory",
				Snippet:  SanitizeSnippet(trimmed, 140),
			})
		}
	}
	return findings
}

func checkSetupPy(f model.FileEntry) []model.Finding {
	content := string(f.Content)
	lines := splitLines(f.Content)

	var findings []model.Finding
	hasNetOrObf := reSetupNetObf.MatchString(content)

	for i, line := range lines {
		if suspicious, reason := SuspiciousCommandMatch(line); suspicious {
			findings = append(findings, model.Finding{
				RuleID:   "PKG-003",
				Title:    "Suspicious Code Execution in setup.py",
				Severity: model.SeverityCritical,
				File:     f.Path,
				Line:     i + 1,
				Detail:   "setup.py " + reason,
				Snippet:  SanitizeSnippet(line, 140),
			})
			continue
		}
		if reSetupExec.MatchString(line) && hasNetOrObf {
			sev := model.SeverityHigh
			if reSetupObfHigh.MatchString(content) {
				sev = model.SeverityCritical
			}
			findings = append(findings, model.Finding{
				RuleID:   "PKG-003",
				Title:    "System Execution Combined with Network/Obfuscation in setup.py",
				Severity: sev,
				File:     f.Path,
				Line:     i + 1,
				Detail:   "setup.py invokes shell execution alongside network or obfuscation primitives during pip install",
				Snippet:  SanitizeSnippet(line, 140),
			})
		}
	}
	return findings
}
