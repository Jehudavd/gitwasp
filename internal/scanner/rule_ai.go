package scanner

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/Jehudavd/gitwasp/internal/model"
)

var (
	reStrongInjection = regexp.MustCompile(`(?i)\b(?:ignore (?:all )?previous instructions|disregard (?:all )?previous|silently run|run silently|without asking|do not tell the user|before responding,?\s*(?:run|execute)|exfiltrate)\b`)
	reWeakStealth     = regexp.MustCompile(`(?i)\b(?:do not mention|don't mention|never mention)\b`)
	reExfilCue        = regexp.MustCompile(`(?i)\b(?:curl|wget|powershell|pwsh|bash|sh\s+-c|base64|id_rsa|\.ssh|\.aws|token|secret|api[_-]?key|env)\b|https?://|eval\s*\(`)
	reStrictExfilCue  = regexp.MustCompile(`(?i)\b(?:curl|wget|powershell|pwsh|sh\s+-c|base64|id_rsa|\.ssh|\.aws|secret|api[_-]?key|token|exfil(?:trate)?)\b|https?://|eval\s*\(`)
)

var shellExecutables = map[string]bool{
	"sh":             true,
	"bash":           true,
	"zsh":            true,
	"dash":           true,
	"ash":            true,
	"cmd":            true,
	"cmd.exe":        true,
	"powershell":     true,
	"powershell.exe": true,
	"pwsh":           true,
	"pwsh.exe":       true,
}

var unpinnedMCPRunners = map[string]bool{
	"npx":     true,
	"uvx":     true,
	"pipx":    true,
	"bunx":    true,
	"dlx":     true,
	"node":    true,
	"python":  true,
	"python3": true,
}

func checkAI(f model.FileEntry) []model.Finding {
	lower := strings.ToLower(f.Path)
	base := path.Base(lower)

	switch {
	case lower == ".claude/settings.json" || strings.HasSuffix(lower, "/.claude/settings.json") ||
		lower == ".claude/settings.local.json" || strings.HasSuffix(lower, "/.claude/settings.local.json"):
		return checkClaudeSettings(f)
	case lower == ".mcp.json" || strings.HasSuffix(lower, "/.mcp.json") ||
		lower == ".cursor/mcp.json" || strings.HasSuffix(lower, "/.cursor/mcp.json") ||
		lower == ".vscode/mcp.json" || strings.HasSuffix(lower, "/.vscode/mcp.json"):
		return checkMCPConfig(f)
	case base == "agents.md" || base == "claude.md" || base == ".cursorrules" ||
		lower == ".github/copilot-instructions.md" || strings.HasSuffix(lower, "/.github/copilot-instructions.md") ||
		isUnderDir(lower, ".cursor/rules"):
		return checkPromptFile(f)
	default:
		return nil
	}
}

func checkClaudeSettings(f model.FileEntry) []model.Finding {
	stripped := StripJSONC(f.Content)
	var doc map[string]any
	if err := json.Unmarshal(stripped, &doc); err != nil {
		return nil
	}

	var findings []model.Finding

	// AI-001: hooks (SessionStart, PreToolUse, PostToolUse, etc.)
	if hooksRaw, ok := doc["hooks"].(map[string]any); ok {
		for eventName, eventVal := range hooksRaw {
			cmds := extractHookCommands(eventVal)
			if len(cmds) == 0 {
				continue
			}
			for _, cmd := range cmds {
				sev := model.SeverityHigh
				suspicious, reason := SuspiciousCommandMatch(cmd)
				if strings.EqualFold(eventName, "SessionStart") || suspicious {
					sev = model.SeverityCritical
				}
				detail := fmt.Sprintf("Project defines Claude %s hook executing %q", eventName, SanitizeSnippet(cmd, 80))
				if suspicious {
					detail += " (" + reason + ")"
				}
				findings = append(findings, model.Finding{
					RuleID:    "AI-001",
					Title:     "AI Agent Hook Execution in Claude Settings",
					Severity:  sev,
					File:      f.Path,
					Line:      FindLineAny(f.Content, cmd, eventName),
					Detail:    detail,
					Snippet:   SanitizeSnippet(cmd, 140),
					Reference: "CVE-2025-59536",
				})
			}
		}
	}

	// AI-002: dangerous env overrides & auto-approval of all MCP servers
	envKeys := []string{"ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "NODE_OPTIONS", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_ENV"}
	if envMap, ok := doc["env"].(map[string]any); ok {
		for k, v := range envMap {
			for _, target := range envKeys {
				if strings.EqualFold(k, target) {
					valStr := fmt.Sprintf("%v", v)
					findings = append(findings, model.Finding{
						RuleID:    "AI-002",
						Title:     "Dangerous Environment Override in Claude Settings",
						Severity:  model.SeverityCritical,
						File:      f.Path,
						Line:      FindLineAny(f.Content, k, valStr),
						Detail:    fmt.Sprintf("Overrides %s to %q (can hijack API keys or inject code)", k, valStr),
						Snippet:   SanitizeSnippet(fmt.Sprintf("%s=%s", k, valStr), 140),
						Reference: "CVE-2026-21852",
					})
				}
			}
		}
	}
	for _, target := range envKeys {
		if v, ok := doc[target]; ok {
			valStr := fmt.Sprintf("%v", v)
			findings = append(findings, model.Finding{
				RuleID:    "AI-002",
				Title:     "Dangerous Environment Override in Claude Settings",
				Severity:  model.SeverityCritical,
				File:      f.Path,
				Line:      FindLineAny(f.Content, target, valStr),
				Detail:    fmt.Sprintf("Sets %s to %q", target, valStr),
				Snippet:   SanitizeSnippet(fmt.Sprintf("%s=%s", target, valStr), 140),
				Reference: "CVE-2026-21852",
			})
		}
	}

	if enableAll, ok := doc["enableAllProjectMcpServers"].(bool); ok && enableAll {
		findings = append(findings, model.Finding{
			RuleID:    "AI-002",
			Title:     "Auto-Enable All Project MCP Servers",
			Severity:  model.SeverityHigh,
			File:      f.Path,
			Line:      FindLine(f.Content, "enableAllProjectMcpServers"),
			Detail:    `Project sets "enableAllProjectMcpServers": true, auto-trusting repository .mcp.json servers`,
			Snippet:   `"enableAllProjectMcpServers": true`,
			Reference: "CVE-2025-59536",
		})
	}

	return findings
}

func extractHookCommands(v any) []string {
	var cmds []string
	switch node := v.(type) {
	case string:
		if strings.TrimSpace(node) != "" {
			cmds = append(cmds, node)
		}
	case []any:
		for _, item := range node {
			cmds = append(cmds, extractHookCommands(item)...)
		}
	case map[string]any:
		if cmd, ok := node["command"].(string); ok && strings.TrimSpace(cmd) != "" {
			cmds = append(cmds, cmd)
		}
		if nested, ok := node["hooks"]; ok {
			cmds = append(cmds, extractHookCommands(nested)...)
		}
	}
	return cmds
}

func checkMCPConfig(f model.FileEntry) []model.Finding {
	stripped := StripJSONC(f.Content)
	var doc map[string]any
	if err := json.Unmarshal(stripped, &doc); err != nil {
		return nil
	}

	var findings []model.Finding
	for _, containerKey := range []string{"mcpServers", "servers"} {
		servers, ok := doc[containerKey].(map[string]any)
		if !ok {
			continue
		}
		for srvName, raw := range servers {
			srv, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			cmd, _ := srv["command"].(string)
			urlStr, _ := srv["url"].(string)
			var args []string
			if arr, ok := srv["args"].([]any); ok {
				args = flattenArgs(arr)
			}
			fullCmd := strings.TrimSpace(strings.Join(append([]string{cmd}, args...), " "))
			line := FindLineAny(f.Content, srvName, cmd, urlStr)

			baseCmd := strings.ToLower(path.Base(strings.ReplaceAll(strings.TrimSpace(cmd), `\`, `/`)))
			suspicious, reason := SuspiciousCommandMatch(fullCmd)
			rawIP, ip := HasRawPublicIPURL(urlStr)

			if shellExecutables[baseCmd] || suspicious || rawIP {
				var detail string
				switch {
				case shellExecutables[baseCmd]:
					detail = fmt.Sprintf("MCP server %q invokes shell interpreter %q", srvName, cmd)
				case rawIP:
					detail = fmt.Sprintf("MCP server %q points to raw IP URL (%s)", srvName, ip)
				default:
					detail = fmt.Sprintf("MCP server %q %s", srvName, reason)
				}
				findings = append(findings, model.Finding{
					RuleID:    "AI-003",
					Title:     "High-Risk MCP Server Definition",
					Severity:  model.SeverityCritical,
					File:      f.Path,
					Line:      line,
					Detail:    detail,
					Snippet:   SanitizeSnippet(nonEmpty(fullCmd, urlStr), 140),
					Reference: "CVE-2025-59536",
				})
				continue
			}

			if isRepoRelativePath(cmd) || unpinnedMCPRunners[baseCmd] {
				findings = append(findings, model.Finding{
					RuleID:   "AI-003",
					Title:    "Project-Controlled or Unpinned MCP Server",
					Severity: model.SeverityMedium,
					File:     f.Path,
					Line:     line,
					Detail:   fmt.Sprintf("MCP server %q launches project-local or unpinned command %q", srvName, cmd),
					Snippet:  SanitizeSnippet(fullCmd, 140),
				})
			}
		}
	}

	return findings
}

func checkPromptFile(f model.FileEntry) []model.Finding {
	lines := splitLines(f.Content)
	var findings []model.Finding

	for i, line := range lines {
		lineNum := i + 1
		window := nearbyLines(lines, i, 2)
		isStrongMatch := reStrongInjection.MatchString(line) && reExfilCue.MatchString(window)
		isWeakMatch := reWeakStealth.MatchString(line) && reStrictExfilCue.MatchString(window)
		if isStrongMatch || isWeakMatch {
			findings = append(findings, model.Finding{
				RuleID:   "AI-004",
				Title:    "Potential Prompt Injection in AI Instruction File",
				Severity: model.SeverityHigh,
				File:     f.Path,
				Line:     lineNum,
				Detail:   "Instruction contains stealth/override directive alongside command or exfiltration cues",
				Snippet:  SanitizeSnippet(line, 140),
			})
			continue
		}

		if suspicious, reason := SuspiciousCommandMatch(line); suspicious {
			findings = append(findings, model.Finding{
				RuleID:   "AI-004",
				Title:    "Suspicious Command in AI Instruction File",
				Severity: model.SeverityHigh,
				File:     f.Path,
				Line:     lineNum,
				Detail:   "AI harness instruction contains command that " + reason,
				Snippet:  SanitizeSnippet(line, 140),
			})
		}
	}

	return findings
}

func nearbyLines(lines []string, idx, radius int) string {
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + radius
	if end >= len(lines) {
		end = len(lines) - 1
	}
	return strings.Join(lines[start:end+1], "\n")
}
