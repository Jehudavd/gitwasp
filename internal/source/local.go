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
	if base == ".gitmodules" || lower == ".git/config" || strings.HasSuffix(lower, "/.git/config") {
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

	// Standalone script files
	if scriptExts[path.Ext(lower)] {
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
			if strings.HasPrefix(relLower, ".git/") && relLower != ".git/hooks" {
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
