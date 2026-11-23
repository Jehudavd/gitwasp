# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.1.x` | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in `gitwasp` (for example: a bypass in static detection rules, a path traversal or symlink-handling flaw, terminal escape injection, or a `git clone` argument injection issue), **please do not open a public GitHub issue**.

Instead, report it privately via GitHub Security Advisories:

- https://github.com/Jehudavd/gitwasp/security/advisories/new

Please include:
1. A concise description of the issue and affected component (`internal/scanner`, `internal/source`, `internal/gitclone`, or `cmd/gitwasp`).
2. A minimal, harmless reproduction fixture using RFC 2606 `.invalid` domains (for example `example.invalid`).
3. The `gitwasp version` and OS you tested on.

We aim to acknowledge reports within 72 hours and coordinate a fix before public disclosure.

## Defensive Scope

`gitwasp` is strictly a **defensive, static inspection tool**. It never executes target code, never sends telemetry, and maintains zero external Go module dependencies to minimize its own supply-chain attack surface.
