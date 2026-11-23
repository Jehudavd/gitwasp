# gitwasp

**Pre-clone & pre-open security inspector for untrusted Git repositories.**

`gitwasp` statically inspects repositories and downloaded project folders **without executing a single line of code** — catching IDE auto-execution traps, AI coding-agent hooks, malicious package lifecycle scripts, Git hook payloads, and hidden Unicode obfuscation before you click *"Trust Workspace"* or run `npm install`.

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

## Quick Start (v0.1 — Local Pre-Open Audit)

### Build & Run

```bash
go build -o gitwasp ./cmd/gitwasp
./gitwasp scan ./path/to/untrusted-repo
```

JSON output for automation / CI:

```bash
./gitwasp scan --json ./path/to/untrusted-repo
```

### Exit Codes

| Code | Verdict | Meaning |
| :--- | :--- | :--- |
| `0` | `SAFE` | No findings detected |
| `1` | `WARN` | Medium/Low findings detected (or CLI/input error) |
| `2` | `DANGER` | Critical/High traps detected — do not trust or open |

---

## Detection Rules (v0.1)

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

## Roadmap (Stage 2)

- **Remote Pre-Clone Inspection (`gitwasp scan https://github.com/owner/repo`)**: Inspect target files via GitHub REST API without writing a single byte to disk (supports private repos via `GITHUB_TOKEN`).
- **Safe Clone Wrapper (`gitwasp clone <url>`)**: Runs pre-clone inspection first and halts automatically before invoking `git clone --no-local -- <url>` if `DANGER` findings are present.
- **Release Automation**: Cross-platform static binaries via GoReleaser and GitHub Actions CI.
