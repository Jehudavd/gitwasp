package source

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Jehudavd/gitwasp/internal/model"
)

const (
	// MaxFileSize caps the number of bytes read per file (512 KiB).
	MaxFileSize = 512 * 1024
	// MaxFiles caps the total number of target files collected in a scan.
	MaxFiles = 2000
)

var skipDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	".next":        true,
	"__pycache__":  true,
	".venv":        true,
	"venv":         true,
	"target":       true,
}

var scriptExts = map[string]bool{
	".sh":  true,
	".ps1": true,
	".bat": true,
	".cmd": true,
	".js":  true,
	".mjs": true,
	".cjs": true,
}

var vscodeTargets = map[string]bool{
	"tasks.json":    true,
	"settings.json": true,
	"launch.json":   true,
	"mcp.json":      true,
}

var standardGitRootFiles = map[string]bool{
	"config":              true,
	"head":                true,
	"fetch_head":          true,
	"orig_head":           true,
	"commit_editmsg":      true,
	"merge_head":          true,
	"merge_msg":           true,
	"merge_mode":          true,
	"merge_rr":            true,
	"cherry_pick_head":    true,
	"revert_head":         true,
	"auto_merge":          true,
	"index":               true,
	"index.lock":          true,
	"packed-refs":         true,
	"description":         true,
	"shallow":             true,
	"gc.log":              true,
	"config.worktree":     true,
	"bisect_expected_rev": true,
	"bisect_log":          true,
	"bisect_names":        true,
	"bisect_run":          true,
	"bisect_start":        true,
	"bisect_terms":        true,
	"editmsg":             true,
	"squash_msg":          true,
	"tag_editmsg":         true,
}

// IsUnexpectedGitRootFile reports whether relPath is a non-standard file located
// directly inside a .git/ directory (for example, a disguised .git/ltr script).
func IsUnexpectedGitRootFile(relPath string) bool {
	norm := path.Clean(filepath.ToSlash(relPath))
	if norm == "." || norm == "" {
		return false
	}
	lower := strings.ToLower(norm)
	dir := path.Dir(lower)
	if dir != ".git" && !strings.HasSuffix(dir, "/.git") {
		return false
	}
	base := path.Base(lower)
	return !standardGitRootFiles[base]
}

func isBuildConfigTS(base string) bool {
	return strings.HasSuffix(base, ".config.ts") ||
		strings.HasSuffix(base, ".config.mts") ||
		strings.HasSuffix(base, ".config.cts")
}

func isSkippedGitSubdir(relLower string) bool {
	segs := strings.Split(relLower, "/")
	for i := 0; i < len(segs)-1; i++ {
		if segs[i] == ".git" {
			next := segs[i+1]
			return next != "hooks" && next != "info"
		}
	}
	return false
}

// IsSkippedPath reports whether relPath falls inside a directory that should
// always be skipped (such as node_modules, vendor, build outputs, or .husky/_).
func IsSkippedPath(relPath string) bool {
	norm := path.Clean(filepath.ToSlash(relPath))
	if norm == "." || norm == "" {
		return false
	}
	lower := strings.ToLower(norm)
	if lower == ".husky/_" || strings.HasSuffix(lower, "/.husky/_") || strings.Contains(lower, ".husky/_/") {
		return true
	}
	for _, seg := range strings.Split(lower, "/") {
		if skipDirs[seg] {
			return true
		}
	}
	return false
}

// RemotePriority returns a fetch priority for remote pre-clone scanning (1 = highest,
// 3 = lowest, 0 = do not fetch remotely). Keeping remote JS fetches limited to root or
// scripts/hooks/bin directories avoids exhausting unauthenticated GitHub API rate limits.
func RemotePriority(relPath string) int {
	norm := path.Clean(filepath.ToSlash(relPath))
	if norm == "." || norm == "" {
		return 0
	}
	lower := strings.ToLower(norm)
	base := path.Base(lower)
	dir := path.Dir(lower)
	ext := path.Ext(lower)

	// Priority 1: IDE, AI harness, package config, and Git hook/submodule traps.
	if (dir == ".vscode" || strings.HasSuffix(dir, "/.vscode")) && vscodeTargets[base] {
		return 1
	}
	if (dir == ".claude" || strings.HasSuffix(dir, "/.claude")) &&
		(base == "settings.json" || base == "settings.local.json") {
		return 1
	}
	if base == ".mcp.json" {
		return 1
	}
	if (dir == ".cursor" || strings.HasSuffix(dir, "/.cursor")) && base == "mcp.json" {
		return 1
	}
	if base == "agents.md" || base == "claude.md" || base == ".cursorrules" {
		return 1
	}
	if lower == ".github/copilot-instructions.md" || strings.HasSuffix(lower, "/.github/copilot-instructions.md") {
		return 1
	}
	if strings.HasPrefix(lower, ".cursor/rules/") || strings.Contains(lower, "/.cursor/rules/") {
		return 1
	}
	if base == "package.json" || base == ".npmrc" || base == ".envrc" || base == "setup.py" {
		return 1
	}
	if base == ".gitmodules" || base == ".gitattributes" {
		return 1
	}
	if strings.HasPrefix(lower, ".githooks/") || strings.Contains(lower, "/.githooks/") {
		return 1
	}
	if strings.HasPrefix(lower, ".husky/") || strings.Contains(lower, "/.husky/") {
		if strings.Contains(lower, ".husky/_/") || base == "_" {
			return 0
		}
		return 1
	}

	// Priority 2: Shell and batch scripts.
	switch ext {
	case ".sh", ".ps1", ".bat", ".cmd":
		return 2
	case ".js", ".mjs", ".cjs":
		if dir == "." {
			return 3
		}
		for _, seg := range strings.Split(dir, "/") {
			switch seg {
			case "scripts", "hooks", "bin", ".vscode", ".claude", ".githooks", ".husky":
				return 3
			}
		}
		return 0
	default:
		if isBuildConfigTS(base) && dir == "." {
			return 3
		}
		return 0
	}
}

// IsRemoteTargetFile reports whether relPath should be fetched during remote pre-clone scans.
func IsRemoteTargetFile(relPath string) bool {
	return !IsSkippedPath(relPath) && RemotePriority(relPath) > 0
}

// IsTargetFile reports whether relPath (slash-separated or OS-separated) should
// be collected and inspected by the static security rules.
func IsTargetFile(relPath string) bool {
	norm := path.Clean(filepath.ToSlash(relPath))
	if norm == "." || norm == "" {
		return false
	}
	lower := strings.ToLower(norm)
	base := path.Base(lower)
	dir := path.Dir(lower)

	// VS Code configuration files
	if (dir == ".vscode" || strings.HasSuffix(dir, "/.vscode")) && vscodeTargets[base] {
		return true
	}

	// Claude & MCP configuration files
	if (dir == ".claude" || strings.HasSuffix(dir, "/.claude")) &&
		(base == "settings.json" || base == "settings.local.json") {
		return true
	}
	if base == ".mcp.json" {
		return true
	}
	if (dir == ".cursor" || strings.HasSuffix(dir, "/.cursor")) && base == "mcp.json" {
		return true
	}

	// AI instruction / harness prompt files
	if base == "agents.md" || base == "claude.md" || base == ".cursorrules" {
		return true
	}
	if lower == ".github/copilot-instructions.md" || strings.HasSuffix(lower, "/.github/copilot-instructions.md") {
		return true
	}
	if strings.HasPrefix(lower, ".cursor/rules/") || strings.Contains(lower, "/.cursor/rules/") {
		return true
	}

	// Package manager / environment setup files
	if base == "package.json" || base == ".npmrc" || base == ".envrc" || base == "setup.py" {
		return true
	}

	// Git configuration & hook files
	if base == ".gitmodules" || base == ".gitattributes" ||
		lower == ".git/config" || strings.HasSuffix(lower, "/.git/config") ||
		lower == ".git/info/attributes" || strings.HasSuffix(lower, "/.git/info/attributes") {
		return true
	}
	if IsUnexpectedGitRootFile(relPath) {
		return true
	}
	if strings.HasPrefix(lower, ".git/hooks/") || strings.Contains(lower, "/.git/hooks/") {
		return !strings.HasSuffix(base, ".sample")
	}
	if strings.HasPrefix(lower, ".githooks/") || strings.Contains(lower, "/.githooks/") {
		return true
	}
	if strings.HasPrefix(lower, ".husky/") || strings.Contains(lower, "/.husky/") {
		if strings.Contains(lower, ".husky/_/") || base == "_" {
			return false
		}
		return true
	}

	// Standalone script files & TypeScript build configs
	if scriptExts[path.Ext(lower)] || isBuildConfigTS(base) {
		return true
	}

	return false
}

// CollectLocal walks root safely without executing code or following symlinks,
// returning target files up to MaxFiles and MaxFileSize.
func CollectLocal(root string) ([]model.FileEntry, int, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, 0, fmt.Errorf("cannot access %q: %w", root, err)
	}
	if !info.IsDir() {
		return nil, 0, fmt.Errorf("%q is not a directory", root)
	}

	files := make([]model.FileEntry, 0)
	skipped := 0

	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			skipped++
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		rel, err := filepath.Rel(root, p)
		if err != nil {
			skipped++
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		if relSlash == "." {
			return nil
		}
		relLower := strings.ToLower(relSlash)

		// Never follow symlinks.
		isSymlink := d.Type()&os.ModeSymlink != 0
		if !isSymlink && d.Type() == 0 {
			if linfo, lerr := os.Lstat(p); lerr == nil {
				isSymlink = linfo.Mode()&os.ModeSymlink != 0
			}
		}
		if isSymlink {
			skipped++
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			base := strings.ToLower(d.Name())
			if skipDirs[base] {
				return filepath.SkipDir
			}
			if relLower == ".husky/_" || strings.HasSuffix(relLower, "/.husky/_") {
				return filepath.SkipDir
			}
			if isSkippedGitSubdir(relLower) {
				return filepath.SkipDir
			}
			return nil
		}

		if !IsTargetFile(relSlash) {
			return nil
		}
		if len(files) >= MaxFiles {
			skipped++
			return nil
		}

		data, ok, err := readBoundedTextFile(p)
		if err != nil || !ok {
			skipped++
			return nil
		}

		files = append(files, model.FileEntry{
			Path:    relSlash,
			Content: data,
			Size:    int64(len(data)),
		})
		return nil
	})
	if err != nil {
		return nil, skipped, fmt.Errorf("walking %q: %w", root, err)
	}

	return files, skipped, nil
}

func readBoundedTextFile(p string) ([]byte, bool, error) {
	linfo, err := os.Lstat(p)
	if err != nil {
		return nil, false, err
	}
	if linfo.Mode()&os.ModeSymlink != 0 || !linfo.Mode().IsRegular() {
		return nil, false, nil
	}
	if linfo.Size() > MaxFileSize {
		return nil, false, nil
	}

	f, err := os.Open(p)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > MaxFileSize {
		return nil, false, nil
	}

	// Skip binary files containing NUL bytes in the first 512 bytes.
	headLen := len(data)
	if headLen > 512 {
		headLen = 512
	}
	if bytes.IndexByte(data[:headLen], 0) >= 0 {
		return nil, false, nil
	}

	return data, true, nil
}
