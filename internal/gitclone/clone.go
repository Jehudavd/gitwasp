package gitclone

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var reGitVer = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)

// ParseGitVersion extracts major, minor, and patch integers from `git --version` output.
func ParseGitVersion(output string) (major, minor, patch int, ok bool) {
	m := reGitVer.FindStringSubmatch(output)
	if len(m) < 3 {
		return 0, 0, 0, false
	}
	maj, err1 := strconv.Atoi(m[1])
	minVal, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return 0, 0, 0, false
	}
	pat := 0
	if len(m) >= 4 && m[3] != "" {
		pat, _ = strconv.Atoi(m[3])
	}
	return maj, minVal, pat, true
}

func versionLessThan(maj, min, pat, tMaj, tMin, tPat int) bool {
	if maj != tMaj {
		return maj < tMaj
	}
	if min != tMin {
		return min < tMin
	}
	return pat < tPat
}

// CheckGitVersionString evaluates a `git --version` string and returns a security
// warning if the Git client is older than patched releases for clone-time RCEs.
func CheckGitVersionString(output string) (ver string, warning string) {
	maj, min, pat, ok := ParseGitVersion(output)
	if !ok {
		return "", ""
	}
	ver = fmt.Sprintf("%d.%d.%d", maj, min, pat)
	switch {
	case versionLessThan(maj, min, pat, 2, 45, 1):
		return ver, fmt.Sprintf("warning: local Git %s is vulnerable to CVE-2024-32002 (clone RCE) and CVE-2025-48384; please upgrade Git", ver)
	case versionLessThan(maj, min, pat, 2, 50, 1):
		return ver, fmt.Sprintf("warning: local Git %s is older than 2.50.1 (CVE-2025-48384); consider upgrading Git", ver)
	default:
		return ver, ""
	}
}

// CheckLocalGitVersion runs `git --version` and checks whether the local Git client
// is up to date for cloning untrusted repositories.
func CheckLocalGitVersion(ctx context.Context) (ver string, warning string) {
	out, err := exec.CommandContext(ctx, "git", "--version").CombinedOutput()
	if err != nil {
		return "", "warning: unable to run 'git --version' (ensure Git is installed and on PATH)"
	}
	return CheckGitVersionString(string(out))
}

// ValidateCloneArgs rejects flag injection (leading '-') and control characters in clone inputs.
func ValidateCloneArgs(cloneURL, destDir string) error {
	if strings.TrimSpace(cloneURL) == "" {
		return fmt.Errorf("clone URL cannot be empty")
	}
	if strings.HasPrefix(cloneURL, "-") || strings.ContainsAny(cloneURL, "\r\n\x00") {
		return fmt.Errorf("unsafe clone URL %q", cloneURL)
	}
	if destDir != "" {
		if strings.HasPrefix(destDir, "-") || strings.ContainsAny(destDir, "\r\n\x00") {
			return fmt.Errorf("unsafe destination directory %q", destDir)
		}
	}
	return nil
}

// RunSafeClone runs `git clone --no-local -- <cloneURL> [destDir]` without recursive submodules.
func RunSafeClone(ctx context.Context, cloneURL, destDir string, stdout, stderr io.Writer) error {
	if err := ValidateCloneArgs(cloneURL, destDir); err != nil {
		return err
	}

	args := []string{"clone", "--no-local", "--", cloneURL}
	if destDir != "" {
		args = append(args, destDir)
	}

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}
