# Contributing to gitwasp

Thanks for helping make developer environments safer!

## Design Rules

1. **Zero external dependencies:** `gitwasp` uses the Go standard library only (`go.mod` must remain free of `require` blocks).
2. **Zero execution:** Never execute, source, or `eval` any content from inspected repositories.
3. **ReDoS-safe patterns:** Rely on Go stdlib `regexp` (Thompson NFA) and avoid unbounded allocations on untrusted inputs.
4. **Safe test fixtures only:** All malicious test fixtures in `testdata/` or `*_test.go` must use RFC 2606 `.invalid` domains (such as `payload.example.invalid`) and harmless dummy payloads (never real malware, real C2 domains, or live exploits).

## Local Development

Requirements: **Go 1.26+** and **Git 2.45.1+** (recommended `2.50.1+`).

```bash
git clone https://github.com/Jehudavd/gitwasp.git
cd gitwasp
go vet ./...
go test -v ./...
```

## Adding a New Detection Rule

1. Add the rule check to the appropriate file in `internal/scanner/` (`rule_ide.go`, `rule_ai.go`, `rule_pkg.go`, `rule_git.go`, or `rule_obf.go`).
2. Assign a clear rule ID (e.g., `IDE-004`, `AI-005`), accurate `Severity`, line number, and sanitized snippet via `SanitizeSnippet`.
3. If inspecting a new file path or extension, register it in `IsTargetFile` and `RemotePriority` inside `internal/source/local.go`.
4. Add both positive detection tests and false-positive regression tests in `internal/scanner/scanner_test.go`.
5. Update the detection rules table in `README.md`.

## Pull Request Checklist

- `go fmt ./...` produces no changes
- `go vet ./...` passes
- `go test -v ./...` passes
- `go.mod` has zero external dependencies
