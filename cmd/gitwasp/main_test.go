package main

import (
	"bytes"
	"encoding/json"
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

func TestRunVersionHelpAndRemoteStub(t *testing.T) {
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
	if code := run([]string{"scan", "https://github.com/example/repo"}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "Stage 2") {
		t.Fatalf("remote stub failed: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
}
