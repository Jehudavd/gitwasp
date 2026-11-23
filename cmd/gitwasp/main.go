package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Jehudavd/gitwasp/internal/model"
	"github.com/Jehudavd/gitwasp/internal/report"
	"github.com/Jehudavd/gitwasp/internal/scanner"
	"github.com/Jehudavd/gitwasp/internal/source"
)

const version = "v0.1.0-dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 1
	}

	switch args[0] {
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	case "version", "-v", "--version":
		fmt.Fprintf(stdout, "gitwasp %s\n", version)
		return 0
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "clone":
		fmt.Fprintln(stderr, "gitwasp: safe 'clone' wrapper is planned for Stage 2; run 'gitwasp scan <local-dir>' for v0.1")
		return 1
	default:
		fmt.Fprintf(stderr, "gitwasp: unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 1
	}
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)

	jsonOut := fs.Bool("json", false, "output scan result as JSON")
	noColor := fs.Bool("no-color", false, "disable ANSI terminal colors")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: gitwasp scan [--json] [--no-color] <local-path>")
	}

	if err := fs.Parse(reorderScanFlags(args)); err != nil {
		return 1
	}

	if fs.NArg() != 1 {
		fs.Usage()
		return 1
	}

	target := fs.Arg(0)
	if looksLikeRemoteTarget(target) {
		fmt.Fprintf(stderr, "gitwasp: remote pre-clone scanning (%s) is planned for Stage 2; pass a local directory path for v0.1\n", target)
		return 1
	}

	files, skipped, err := source.CollectLocal(target)
	if err != nil {
		fmt.Fprintf(stderr, "gitwasp: %v\n", err)
		return 1
	}

	res := scanner.Scan(target, "local (zero-execution)", files, skipped)

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

func reorderScanFlags(args []string) []string {
	var flags []string
	var positional []string
	stop := false
	for _, a := range args {
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
			continue
		}
		positional = append(positional, a)
	}
	return append(flags, positional...)
}

func looksLikeRemoteTarget(target string) bool {
	lower := strings.ToLower(strings.TrimSpace(target))
	return strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "ssh://") ||
		strings.HasPrefix(lower, "git@")
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

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "gitwasp - Pre-clone & pre-open security inspector for untrusted Git repositories")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  gitwasp scan [--json] [--no-color] <local-path>")
	fmt.Fprintln(w, "  gitwasp version")
	fmt.Fprintln(w, "  gitwasp help")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Exit Codes:")
	fmt.Fprintln(w, "  0  SAFE   - No findings")
	fmt.Fprintln(w, "  1  WARN   - Medium/Low findings or CLI error")
	fmt.Fprintln(w, "  2  DANGER - Critical/High findings detected")
}
