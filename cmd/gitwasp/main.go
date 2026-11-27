package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"strings"

	"github.com/Jehudavd/gitwasp/internal/gitclone"
	"github.com/Jehudavd/gitwasp/internal/model"
	"github.com/Jehudavd/gitwasp/internal/report"
	"github.com/Jehudavd/gitwasp/internal/scanner"
	"github.com/Jehudavd/gitwasp/internal/source"
)

const defaultDevVersion = "v0.2.0-dev"

var (
	version = defaultDevVersion
	commit  = "none"
	date    = "unknown"
)

func formatVersion() string {
	bi, _ := debug.ReadBuildInfo()
	return formatVersionFrom(version, commit, date, bi)
}

func formatVersionFrom(ver, rev, built string, bi *debug.BuildInfo) string {
	if ver == defaultDevVersion && bi != nil && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		ver = bi.Main.Version
	}
	if rev == "none" && built == "unknown" {
		return fmt.Sprintf("gitwasp %s", ver)
	}
	return fmt.Sprintf("gitwasp %s (commit: %s, built: %s)", ver, rev, built)
}

type cliDeps struct {
	apiBaseURL  string
	httpClient  *http.Client
	stdin       io.Reader
	runClone    func(ctx context.Context, cloneURL, destDir string, stdout, stderr io.Writer) error
	checkGitVer func(ctx context.Context) (string, string)
}

func defaultDeps() cliDeps {
	return cliDeps{
		stdin:       os.Stdin,
		runClone:    gitclone.RunSafeClone,
		checkGitVer: gitclone.CheckLocalGitVersion,
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithDeps(args, stdout, stderr, defaultDeps())
}

func runWithDeps(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 1
	}

	switch args[0] {
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	case "version", "-v", "--version":
		fmt.Fprintln(stdout, formatVersion())
		return 0
	case "scan":
		return runScan(args[1:], stdout, stderr, deps)
	case "clone":
		return runCloneCmd(args[1:], stdout, stderr, deps)
	default:
		fmt.Fprintf(stderr, "gitwasp: unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 1
	}
}

var scanValueFlags = map[string]bool{
	"ref":   true,
	"token": true,
}

var cloneValueFlags = map[string]bool{
	"ref":   true,
	"token": true,
}

func runScan(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)

	jsonOut := fs.Bool("json", false, "output scan result as JSON")
	noColor := fs.Bool("no-color", false, "disable ANSI terminal colors")
	refFlag := fs.String("ref", "", "branch, tag, or commit SHA for remote scans")
	tokenFlag := fs.String("token", "", "GitHub token (defaults to GITHUB_TOKEN / GH_TOKEN)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: gitwasp scan [--json] [--no-color] [--ref <ref>] [--token <token>] <local-path | archive.zip | github-url | owner/repo>")
	}

	if err := fs.Parse(reorderFlags(args, scanValueFlags)); err != nil {
		return 1
	}

	if fs.NArg() != 1 {
		fs.Usage()
		return 1
	}

	target := fs.Arg(0)

	var (
		res model.ScanResult
	)

	if info, statErr := os.Stat(target); statErr == nil {
		if !info.IsDir() && source.IsZipFile(target) {
			files, skipped, meta, err := source.CollectZip(target)
			if err != nil {
				fmt.Fprintf(stderr, "gitwasp: %v\n", err)
				return 1
			}
			extra := buildZipArchiveFindings(meta)
			res = scanner.ScanWithExtraFindings(target, "zip archive (zero-extraction)", files, skipped, extra)
		} else {
			files, skipped, err := source.CollectLocal(target)
			if err != nil {
				fmt.Fprintf(stderr, "gitwasp: %v\n", err)
				return 1
			}
			res = scanner.Scan(target, "local (zero-execution)", files, skipped)
		}
	} else if source.LooksLikeRemoteTarget(target) {
		repo, err := source.ParseGitHubTarget(target)
		if err != nil {
			fmt.Fprintf(stderr, "gitwasp: %v\n", err)
			return 1
		}
		files, skipped, resolvedRef, err := source.CollectGitHub(context.Background(), repo, source.GitHubOptions{
			APIBaseURL: deps.apiBaseURL,
			Token:      *tokenFlag,
			Ref:        *refFlag,
			HTTPClient: deps.httpClient,
		})
		if err != nil {
			fmt.Fprintf(stderr, "gitwasp: %v\n", err)
			return 1
		}
		mode := fmt.Sprintf("remote GitHub API (zero local write, ref: %s)", resolvedRef)
		res = scanner.Scan(repo.CloneURL, mode, files, skipped)
	} else {
		files, skipped, err := source.CollectLocal(target)
		if err != nil {
			fmt.Fprintf(stderr, "gitwasp: %v\n", err)
			return 1
		}
		res = scanner.Scan(target, "local (zero-execution)", files, skipped)
	}

	if *jsonOut {
		if err := report.WriteJSON(stdout, res); err != nil {
			fmt.Fprintf(stderr, "gitwasp: writing JSON report: %v\n", err)
			return 1
		}
		return model.ExitCode(res.Verdict)
	}

	useColor := !*noColor && os.Getenv("NO_COLOR") == "" && isInteractiveWriter(stdout)
	if err := report.WriteTerminal(stdout, res, useColor); err != nil {
		fmt.Fprintf(stderr, "gitwasp: writing report: %v\n", err)
		return 1
	}

	return model.ExitCode(res.Verdict)
}

func runCloneCmd(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	fs := flag.NewFlagSet("clone", flag.ContinueOnError)
	fs.SetOutput(stderr)

	refFlag := fs.String("ref", "", "branch, tag, or commit SHA to scan before cloning")
	yesFlag := fs.Bool("yes", false, "proceed automatically on WARN verdict without prompting")
	forceFlag := fs.Bool("force", false, "proceed even on DANGER verdict (unsafe)")
	noColor := fs.Bool("no-color", false, "disable ANSI terminal colors")
	tokenFlag := fs.String("token", "", "GitHub token (defaults to GITHUB_TOKEN / GH_TOKEN)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: gitwasp clone [--ref <ref>] [--yes] [--force] [--no-color] [--token <token>] <github-url | owner/repo> [dest-dir]")
	}

	if err := fs.Parse(reorderFlags(args, cloneValueFlags)); err != nil {
		return 1
	}

	if fs.NArg() < 1 || fs.NArg() > 2 {
		fs.Usage()
		return 1
	}

	target := fs.Arg(0)
	destDir := ""
	if fs.NArg() == 2 {
		destDir = fs.Arg(1)
	}

	repo, err := source.ParseGitHubTarget(target)
	if err != nil {
		fmt.Fprintf(stderr, "gitwasp: %v\n", err)
		return 1
	}
	if err := gitclone.ValidateCloneArgs(repo.CloneURL, destDir); err != nil {
		fmt.Fprintf(stderr, "gitwasp: %v\n", err)
		return 1
	}

	ctx := context.Background()
	if deps.checkGitVer != nil {
		if _, warn := deps.checkGitVer(ctx); warn != "" {
			fmt.Fprintln(stderr, warn)
		}
	}

	files, skipped, resolvedRef, err := source.CollectGitHub(ctx, repo, source.GitHubOptions{
		APIBaseURL: deps.apiBaseURL,
		Token:      *tokenFlag,
		Ref:        *refFlag,
		HTTPClient: deps.httpClient,
	})
	if err != nil {
		fmt.Fprintf(stderr, "gitwasp: %v\n", err)
		return 1
	}

	mode := fmt.Sprintf("remote GitHub API (zero local write, ref: %s)", resolvedRef)
	res := scanner.Scan(repo.CloneURL, mode, files, skipped)

	useColor := !*noColor && os.Getenv("NO_COLOR") == "" && isInteractiveWriter(stdout)
	if err := report.WriteTerminal(stdout, res, useColor); err != nil {
		fmt.Fprintf(stderr, "gitwasp: writing report: %v\n", err)
		return 1
	}

	switch res.Verdict {
	case model.VerdictDanger:
		if !*forceFlag {
			fmt.Fprintln(stderr, "gitwasp: clone blocked due to DANGER verdict (re-run with --force to override)")
			return model.ExitCode(model.VerdictDanger)
		}
		fmt.Fprintln(stderr, "gitwasp: warning: proceeding with clone due to --force despite DANGER findings")
	case model.VerdictWarn:
		if !*yesFlag && !*forceFlag {
			fmt.Fprint(stderr, "Proceed with git clone despite warnings? [y/N]: ")
			if !readConfirmation(deps.stdin) {
				fmt.Fprintln(stderr, "gitwasp: clone aborted by user")
				return 1
			}
		}
	}

	if err := deps.runClone(ctx, repo.CloneURL, destDir, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "gitwasp: git clone failed: %v\n", err)
		return 1
	}
	return 0
}

func readConfirmation(r io.Reader) bool {
	if r == nil {
		return false
	}
	reader := bufio.NewReader(r)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return false
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes"
}

func reorderFlags(args []string, valueFlags map[string]bool) []string {
	var flags []string
	var positional []string
	stop := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		if stop {
			positional = append(positional, a)
			continue
		}
		if a == "--" {
			stop = true
			positional = append(positional, a)
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			flags = append(flags, a)
			if !strings.Contains(a, "=") {
				name := strings.TrimLeft(a, "-")
				if valueFlags[name] && i+1 < len(args) {
					i++
					flags = append(flags, args[i])
				}
			}
			continue
		}
		positional = append(positional, a)
	}
	return append(flags, positional...)
}

func isInteractiveWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func buildZipArchiveFindings(meta source.ZipMeta) []model.Finding {
	var extra []model.Finding
	if meta.HasEmbeddedGit {
		sample := ".git/"
		if len(meta.EmbeddedGitPaths) > 0 {
			sample = meta.EmbeddedGitPaths[0]
		}
		extra = append(extra, model.Finding{
			RuleID:    "ARC-001",
			Title:     "Archive Embeds Pre-Built .git Directory",
			Severity:  model.SeverityCritical,
			File:      sample,
			Line:      0,
			Detail:    "Archive contains an embedded .git/ directory (bypasses git clone safety protections and can auto-execute .git/config filters or hooks when opened in an IDE)",
			Snippet:   strings.Join(meta.EmbeddedGitPaths, ", "),
			Reference: "Trojanized .git archive vector (Contagious Interview)",
		})
	}
	if meta.HasZipSlip {
		sample := meta.ZipSlipPaths[0]
		extra = append(extra, model.Finding{
			RuleID:   "ARC-002",
			Title:    "Path Traversal (Zip Slip) Entry in Archive",
			Severity: model.SeverityCritical,
			File:     sample,
			Line:     0,
			Detail:   "Archive entry path escapes extraction directory via traversal or absolute path",
			Snippet:  strings.Join(meta.ZipSlipPaths, ", "),
		})
	}
	return extra
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "gitwasp - Pre-clone & pre-open security inspector for untrusted Git repositories")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  gitwasp scan [--json] [--no-color] [--ref <ref>] [--token <token>] <local-path | archive.zip | github-url | owner/repo>")
	fmt.Fprintln(w, "  gitwasp clone [--ref <ref>] [--yes] [--force] [--no-color] [--token <token>] <github-url | owner/repo> [dest-dir]")
	fmt.Fprintln(w, "  gitwasp version")
	fmt.Fprintln(w, "  gitwasp help")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Exit Codes:")
	fmt.Fprintln(w, "  0  SAFE   - No findings")
	fmt.Fprintln(w, "  1  WARN   - Medium/Low findings, aborted clone, or CLI error")
	fmt.Fprintln(w, "  2  DANGER - Critical/High findings detected")
}
