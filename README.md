# gitwasp

**Pre-clone & pre-open security inspector for untrusted Git repositories.**

`gitwasp` statically inspects remote GitHub repositories and local project folders **without executing a single line of code** — catching IDE auto-execution traps, AI coding-agent hooks, malicious package lifecycle scripts, Git hook payloads, and hidden Unicode obfuscation before you clone or click *"Trust Workspace"*.

Built with **Go standard library only (zero external dependencies)** so the security tool itself has minimal supply-chain surface and is immune to ReDoS.

---

## Why `gitwasp`?

Developer-targeted attacks (such as fake take-home coding interviews and supply-chain lures) hide code execution inside workspace config files that editors, package managers, and AI coding agents process automatically:

- **`.vscode/tasks.json`** with `"runOn": "folderOpen"` and hidden terminals
- **`.claude/settings.json`** `SessionStart` hooks and `ANTHROPIC_BASE_URL` overrides (`CVE-2025-59536`, `CVE-2026-21852`)
- **`.mcp.json` / `.cursor/mcp.json`** shell-invoking MCP servers and **`AGENTS.md` / `CLAUDE.md` / `.cursorrules`** indirect prompt injections
- **`package.json`** `postinstall` / `preinstall` obfuscated scripts and rogue **`.npmrc`** registries
- **`.githooks/*`**, **`.gitmodules`**, and **`.git/config`** (`core.fsmonitor`, `core.sshCommand`, `core.hooksPath`)
- **Trojan Source** BiDi overrides, zero-width Unicode, horizontal whitespace scroll-hiding, and disguised asset execution

---

## Quick Start

### Build

```bash
go build -o gitwasp ./cmd/gitwasp
```

### 1. Remote Pre-Clone Scan *(Zero Local Write)*

Inspect a GitHub repository via the GitHub REST API before cloning a single byte to disk:

```bash
gitwasp scan https://github.com/owner/repo
gitwasp scan owner/repo --ref main
gitwasp scan --json https://github.com/owner/repo
```

For private repositories or higher API rate limits, set `GITHUB_TOKEN` (or `GH_TOKEN`) or pass `--token`.

### 2. Safe Clone Wrapper

Drop-in wrapper around `git clone` that inspects the repository first, checks your local Git version for known clone RCEs, blocks automatically on `DANGER`, prompts on `WARN`, and clones with `git clone --no-local -- <url>` (without `--recurse-submodules`) when safe:

```bash
gitwasp clone https://github.com/owner/repo
gitwasp clone owner/repo ./target-dir
gitwasp clone --yes https://github.com/owner/repo
```

### 3. Local Pre-Open Scan

Inspect an already-downloaded folder or extracted archive before opening it in VS Code / Cursor / Claude Code:

```bash
gitwasp scan ./path/to/untrusted-repo
gitwasp scan --json ./path/to/untrusted-repo
```

### Flags

| Flag | Commands | Description |
| :--- | :--- | :--- |
| `--json` | `scan` | Output machine-readable JSON |
| `--no-color` | `scan`, `clone` | Disable ANSI terminal colors (also respects `NO_COLOR`) |
| `--ref <ref>` | `scan`, `clone` | Branch, tag, or commit SHA for remote GitHub inspection |
| `--token <token>` | `scan`, `clone` | GitHub API token (defaults to `GITHUB_TOKEN` / `GH_TOKEN`) |
| `--yes` | `clone` | Proceed automatically on `WARN` without prompting |
| `--force` | `clone` | Override `DANGER` block and clone anyway (unsafe) |

### Exit Codes

| Code | Verdict | Meaning |
| :--- | :--- | :--- |
| `0` | `SAFE` | No findings detected |
| `1` | `WARN` | Medium/Low findings detected, aborted clone, or CLI/input error |
| `2` | `DANGER` | Critical/High traps detected — clone blocked, do not trust or open |

---

## Detection Rules

| Rule ID | Target | What It Detects |
| :--- | :--- | :--- |
| `IDE-001` | `.vscode/tasks.json` | Auto-execution via `runOptions.runOn: "folderOpen"`, especially with `reveal: "never"` or shell/network payloads |
| `IDE-002` | `.vscode/tasks.json`, `launch.json` | Obfuscated, Base64, encoded PowerShell, pipe-to-shell, or disguised asset execution |
| `IDE-003` | `.vscode/settings.json` | Repo-relative executable overrides, `LD_PRELOAD`/`NODE_OPTIONS` terminal env injection, workspace trust disabled |
| `AI-001` | `.claude/settings*.json` | Project hooks (`SessionStart`, `PreToolUse`, etc.) executing commands |
| `AI-002` | `.claude/settings*.json` | `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` / `NODE_OPTIONS` overrides, `enableAllProjectMcpServers: true` |
| `AI-003` | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` | Shell-spawning MCP servers, raw-IP URLs, or unpinned/local commands |
| `AI-004` | `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, Copilot instructions | Stealth prompt injection directives paired with command/exfiltration cues |
| `PKG-001` | `package.json` | Suspicious or non-allowlisted `preinstall` / `install` / `postinstall` / `prepare` scripts |
| `PKG-002` | `.npmrc` | Non-standard package registries, `onload-script`, or `script-shell` overrides |
| `PKG-003` | `.envrc`, `setup.py` | Automatic direnv execution or `setup.py` system commands combined with network/obfuscation |
| `GIT-001` | `.githooks/*`, `.husky/*`, `.git/hooks/*` | Malicious payloads, network calls, or payloads hidden behind >=40 decoy comment/blank lines |
| `GIT-002` | `.gitmodules` | Dangerous `ext::`, `file://`, raw-IP, or `../` path-traversal submodule URLs |
| `GIT-003` | `.git/config` | `core.fsmonitor`, `core.sshCommand`, or `core.hooksPath` overrides |
| `OBF-001` | All scanned target files | Trojan Source BiDi overrides, Unicode Tag characters, and hidden zero-width runes |
| `OBF-002` | All scanned target files | Horizontal whitespace scroll-hiding (>=200 spaces or >=40 tabs before trailing code) |
| `OBF-003` | `.sh`, `.ps1`, `.bat`, `.cmd`, `.js`, `.mjs`, `.cjs` | Disguised asset execution, `eval(Buffer.from(...,'base64'))`, or pipe-to-shell downloaders |

---

## Development & Tests

```bash
go vet ./...
go test -v ./...
```

---

## Roadmap (Stage 3 — Public Release Readiness)

- Open-source `LICENSE` and `CONTRIBUTING.md`
- GitHub Actions CI (`go vet`, `go test`)
- Cross-platform static binaries via GoReleaser (`v0.1.0`)
