package scanner

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/Jehudavd/gitwasp/internal/model"
)

func checkIDE(f model.FileEntry) []model.Finding {
	lower := strings.ToLower(f.Path)
	switch {
	case lower == ".vscode/tasks.json" || strings.HasSuffix(lower, "/.vscode/tasks.json"):
		return checkVSCodeTasks(f)
	case lower == ".vscode/launch.json" || strings.HasSuffix(lower, "/.vscode/launch.json"):
		return checkVSCodeLaunch(f)
	case lower == ".vscode/settings.json" || strings.HasSuffix(lower, "/.vscode/settings.json"):
		return checkVSCodeSettings(f)
	default:
		return nil
	}
}

type vscodeTasksDoc struct {
	Tasks []vscodeTask `json:"tasks"`
}

type vscodeTask struct {
	Label        string          `json:"label"`
	Type         string          `json:"type"`
	Command      string          `json:"command"`
	Args         []any           `json:"args"`
	Presentation *vscodePresent  `json:"presentation"`
	RunOptions   *vscodeRunOpts  `json:"runOptions"`
	Windows      *vscodeOSTarget `json:"windows"`
	Linux        *vscodeOSTarget `json:"linux"`
	OSX          *vscodeOSTarget `json:"osx"`
}

type vscodeOSTarget struct {
	Command      string         `json:"command"`
	Args         []any          `json:"args"`
	Presentation *vscodePresent `json:"presentation"`
	RunOptions   *vscodeRunOpts `json:"runOptions"`
}

type vscodePresent struct {
	Reveal string `json:"reveal"`
}

type vscodeRunOpts struct {
	RunOn string `json:"runOn"`
}

func checkVSCodeTasks(f model.FileEntry) []model.Finding {
	stripped := StripJSONC(f.Content)
	var doc vscodeTasksDoc
	if err := json.Unmarshal(stripped, &doc); err != nil {
		return nil
	}

	var findings []model.Finding
	for _, task := range doc.Tasks {
		variants := []struct {
			osName  string
			cmd     string
			args    []any
			present *vscodePresent
			runOpts *vscodeRunOpts
		}{
			{"", task.Command, task.Args, task.Presentation, task.RunOptions},
		}
		if task.Windows != nil {
			variants = append(variants, struct {
				osName  string
				cmd     string
				args    []any
				present *vscodePresent
				runOpts *vscodeRunOpts
			}{"windows", task.Windows.Command, task.Windows.Args, task.Windows.Presentation, task.Windows.RunOptions})
		}
		if task.Linux != nil {
			variants = append(variants, struct {
				osName  string
				cmd     string
				args    []any
				present *vscodePresent
				runOpts *vscodeRunOpts
			}{"linux", task.Linux.Command, task.Linux.Args, task.Linux.Presentation, task.Linux.RunOptions})
		}
		if task.OSX != nil {
			variants = append(variants, struct {
				osName  string
				cmd     string
				args    []any
				present *vscodePresent
				runOpts *vscodeRunOpts
			}{"osx", task.OSX.Command, task.OSX.Args, task.OSX.Presentation, task.OSX.RunOptions})
		}

		for _, v := range variants {
			fullCmd := strings.TrimSpace(strings.Join(append([]string{v.cmd}, flattenArgs(v.args)...), " "))
			if fullCmd == "" && v.osName != "" {
				fullCmd = strings.TrimSpace(strings.Join(append([]string{task.Command}, flattenArgs(task.Args)...), " "))
			}

			runOn := ""
			if v.runOpts != nil {
				runOn = v.runOpts.RunOn
			} else if v.osName != "" && task.RunOptions != nil {
				runOn = task.RunOptions.RunOn
			}

			reveal := ""
			if v.present != nil {
				reveal = v.present.Reveal
			} else if task.Presentation != nil {
				reveal = task.Presentation.Reveal
			}

			line := FindLineAny(f.Content, v.cmd, task.Label, "folderOpen")

			if strings.EqualFold(runOn, "folderOpen") {
				suspicious, reason := SuspiciousCommandMatch(fullCmd)
				hidden := strings.EqualFold(reveal, "never")
				sev := model.SeverityHigh
				if hidden || suspicious || ContainsShellOrNetwork(fullCmd) {
					sev = model.SeverityCritical
				}
				detail := fmt.Sprintf("Task %q auto-executes on folderOpen", nonEmpty(task.Label, "unnamed"))
				if hidden {
					detail += ` with hidden terminal (reveal="never")`
				}
				if suspicious {
					detail += "; " + reason
				}
				findings = append(findings, model.Finding{
					RuleID:    "IDE-001",
					Title:     "VS Code Auto-Execution Task (folderOpen)",
					Severity:  sev,
					File:      f.Path,
					Line:      line,
					Detail:    detail,
					Snippet:   SanitizeSnippet(fullCmd, 140),
					Reference: "Contagious Interview / VS Code tasks.json vector",
				})
				break
			}

			if suspicious, reason := SuspiciousCommandMatch(fullCmd); suspicious {
				findings = append(findings, model.Finding{
					RuleID:   "IDE-002",
					Title:    "Suspicious Command in VS Code Task",
					Severity: model.SeverityCritical,
					File:     f.Path,
					Line:     line,
					Detail:   fmt.Sprintf("Task %q %s", nonEmpty(task.Label, "unnamed"), reason),
					Snippet:  SanitizeSnippet(fullCmd, 140),
				})
				break
			}
		}
	}

	return findings
}

func checkVSCodeLaunch(f model.FileEntry) []model.Finding {
	stripped := StripJSONC(f.Content)
	var doc struct {
		Configurations []map[string]any `json:"configurations"`
	}
	if err := json.Unmarshal(stripped, &doc); err != nil {
		return nil
	}

	var findings []model.Finding
	for _, cfg := range doc.Configurations {
		name, _ := cfg["name"].(string)
		parts := make([]string, 0)
		for _, key := range []string{"runtimeExecutable", "program", "miDebuggerPath", "preLaunchTask"} {
			if val, ok := cfg[key].(string); ok && val != "" {
				parts = append(parts, val)
			}
		}
		for _, key := range []string{"args", "runtimeArgs"} {
			if arr, ok := cfg[key].([]any); ok {
				parts = append(parts, flattenArgs(arr)...)
			}
		}
		combined := strings.Join(parts, " ")
		if suspicious, reason := SuspiciousCommandMatch(combined); suspicious {
			line := FindLineAny(f.Content, parts...)
			findings = append(findings, model.Finding{
				RuleID:   "IDE-002",
				Title:    "Suspicious Command in VS Code Launch Config",
				Severity: model.SeverityCritical,
				File:     f.Path,
				Line:     line,
				Detail:   fmt.Sprintf("Launch configuration %q %s", nonEmpty(name, "unnamed"), reason),
				Snippet:  SanitizeSnippet(combined, 140),
			})
		}
	}
	return findings
}

var dangerousVSCodePathKeys = map[string]bool{
	"python.defaultinterpreterpath":     true,
	"python.pythonpath":                 true,
	"php.validate.executablepath":       true,
	"eslint.nodepath":                   true,
	"typescript.tsdk":                   true,
	"git.path":                          true,
	"terminal.integrated.shell.windows": true,
	"terminal.integrated.shell.linux":   true,
	"terminal.integrated.shell.osx":     true,
}

var dangerousEnvVars = map[string]bool{
	"LD_PRELOAD":            true,
	"DYLD_INSERT_LIBRARIES": true,
	"NODE_OPTIONS":          true,
	"BASH_ENV":              true,
}

func checkVSCodeSettings(f model.FileEntry) []model.Finding {
	stripped := StripJSONC(f.Content)
	var settings map[string]any
	if err := json.Unmarshal(stripped, &settings); err != nil {
		return nil
	}

	var findings []model.Finding
	for k, v := range settings {
		kl := strings.ToLower(k)

		if dangerousVSCodePathKeys[kl] {
			if s, ok := v.(string); ok && isRepoRelativePath(s) {
				findings = append(findings, model.Finding{
					RuleID:   "IDE-003",
					Title:    "Workspace-Relative Executable Override in VS Code Settings",
					Severity: model.SeverityHigh,
					File:     f.Path,
					Line:     FindLineAny(f.Content, k, s),
					Detail:   fmt.Sprintf("Setting %q points executable to repository-local path %q", k, s),
					Snippet:  SanitizeSnippet(fmt.Sprintf("%q: %q", k, s), 140),
				})
			}
		}

		if strings.HasPrefix(kl, "terminal.integrated.profiles.") {
			if profiles, ok := v.(map[string]any); ok {
				for profName, profVal := range profiles {
					profMap, ok := profVal.(map[string]any)
					if !ok {
						continue
					}
					if p, ok := profMap["path"].(string); ok && isRepoRelativePath(p) {
						findings = append(findings, model.Finding{
							RuleID:   "IDE-003",
							Title:    "Workspace-Relative Terminal Profile in VS Code Settings",
							Severity: model.SeverityHigh,
							File:     f.Path,
							Line:     FindLineAny(f.Content, profName, p),
							Detail:   fmt.Sprintf("Terminal profile %q executes repository-local path %q", profName, p),
							Snippet:  SanitizeSnippet(fmt.Sprintf("%s.path: %q", profName, p), 140),
						})
					}
				}
			}
		}

		if strings.HasPrefix(kl, "terminal.integrated.env.") {
			if envMap, ok := v.(map[string]any); ok {
				for envKey, envVal := range envMap {
					if dangerousEnvVars[strings.ToUpper(envKey)] {
						valStr := fmt.Sprintf("%v", envVal)
						findings = append(findings, model.Finding{
							RuleID:   "IDE-003",
							Title:    "Dangerous Terminal Environment Injection in VS Code Settings",
							Severity: model.SeverityCritical,
							File:     f.Path,
							Line:     FindLineAny(f.Content, envKey, k),
							Detail:   fmt.Sprintf("Setting %q injects %s into integrated terminals", k, envKey),
							Snippet:  SanitizeSnippet(fmt.Sprintf("%s=%s", envKey, valStr), 140),
						})
					}
				}
			}
		}

		if kl == "task.allowautomatictasks" {
			if s, ok := v.(string); ok && strings.EqualFold(strings.TrimSpace(s), "on") {
				findings = append(findings, model.Finding{
					RuleID:   "IDE-003",
					Title:    "VS Code Automatic Tasks Enabled in Workspace Settings",
					Severity: model.SeverityHigh,
					File:     f.Path,
					Line:     FindLine(f.Content, k),
					Detail:   `Workspace enables "task.allowAutomaticTasks": "on"`,
					Snippet:  SanitizeSnippet(fmt.Sprintf("%q: %q", k, s), 140),
				})
			}
		}

		if kl == "security.workspace.trust.enabled" {
			if b, ok := v.(bool); ok && !b {
				findings = append(findings, model.Finding{
					RuleID:   "IDE-003",
					Title:    "Workspace Trust Disabled in VS Code Settings",
					Severity: model.SeverityHigh,
					File:     f.Path,
					Line:     FindLine(f.Content, k),
					Detail:   `Workspace sets "security.workspace.trust.enabled": false`,
					Snippet:  SanitizeSnippet(fmt.Sprintf("%q: false", k), 140),
				})
			}
		}
	}

	return findings
}

func isRepoRelativePath(p string) bool {
	trimmed := strings.TrimSpace(p)
	lower := strings.ToLower(trimmed)
	return strings.HasPrefix(trimmed, "./") ||
		strings.HasPrefix(trimmed, "../") ||
		strings.HasPrefix(trimmed, `.\`) ||
		strings.HasPrefix(trimmed, `..\`) ||
		strings.Contains(lower, "${workspacefolder}") ||
		strings.Contains(lower, "${workspaceroot}")
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func isUnderDir(filePath, dir string) bool {
	lower := strings.ToLower(filePath)
	prefix := strings.ToLower(dir) + "/"
	return strings.HasPrefix(lower, prefix) || strings.Contains(lower, "/"+prefix)
}

func baseLower(filePath string) string {
	return strings.ToLower(path.Base(filePath))
}
