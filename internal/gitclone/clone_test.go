package gitclone

import (
	"strings"
	"testing"
)

func TestParseAndCheckGitVersionString(t *testing.T) {
	maj, min, pat, ok := ParseGitVersion("git version 2.44.0.windows.1")
	if !ok || maj != 2 || min != 44 || pat != 0 {
		t.Fatalf("ParseGitVersion failed: got %d.%d.%d ok=%v", maj, min, pat, ok)
	}

	if _, warn := CheckGitVersionString("git version 2.44.0.windows.1"); !strings.Contains(warn, "CVE-2024-32002") {
		t.Fatalf("expected CVE-2024-32002 warning for 2.44.0, got %q", warn)
	}

	if _, warn := CheckGitVersionString("git version 2.49.0 (Apple Git-154)"); !strings.Contains(warn, "CVE-2025-48384") {
		t.Fatalf("expected CVE-2025-48384 warning for 2.49.0, got %q", warn)
	}

	if ver, warn := CheckGitVersionString("git version 2.56.1.windows.1"); ver != "2.56.1" || warn != "" {
		t.Fatalf("expected clean check for 2.56.1, got ver=%q warn=%q", ver, warn)
	}
}

func TestValidateCloneArgs(t *testing.T) {
	if err := ValidateCloneArgs("https://github.com/Jehudavd/gitwasp.git", "gitwasp"); err != nil {
		t.Fatalf("valid clone args rejected: %v", err)
	}
	if err := ValidateCloneArgs("--upload-pack=evil", ""); err == nil {
		t.Fatalf("expected leading '-' URL to be rejected")
	}
	if err := ValidateCloneArgs("https://github.com/a/b.git", "-bad-dir"); err == nil {
		t.Fatalf("expected leading '-' destDir to be rejected")
	}
	if err := ValidateCloneArgs("https://github.com/a/b.git\nevil", ""); err == nil {
		t.Fatalf("expected newline in URL to be rejected")
	}
}
