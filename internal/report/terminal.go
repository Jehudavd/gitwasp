package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/Jehudavd/gitwasp/internal/model"
)

const (
	ansiReset     = "\x1b[0m"
	ansiBold      = "\x1b[1m"
	ansiDim       = "\x1b[2m"
	ansiRed       = "\x1b[31m"
	ansiBrightRed = "\x1b[91m"
	ansiGreen     = "\x1b[32m"
	ansiYellow    = "\x1b[33m"
	ansiCyan      = "\x1b[36m"
)

// WriteTerminal prints a human-readable security report to w.
func WriteTerminal(w io.Writer, res model.ScanResult, useColor bool) error {
	paint := func(code, text string) string {
		if !useColor || code == "" {
			return text
		}
		return code + text + ansiReset
	}

	header := "gitwasp · Pre-Open Workspace Security Audit"
	if strings.HasPrefix(res.Mode, "remote") {
		header = "gitwasp · Pre-Clone Remote Repository Security Audit"
	} else if strings.HasPrefix(res.Mode, "zip") {
		header = "gitwasp · Pre-Extract Archive Security Audit"
	}
	fmt.Fprintf(w, "\n%s\n", paint(ansiBold, header))
	fmt.Fprintf(w, "%s %s\n", paint(ansiDim, "Target :"), res.Target)
	fmt.Fprintf(w, "%s %s\n", paint(ansiDim, "Mode   :"), res.Mode)
	fmt.Fprintf(w, "%s %d scanned, %d skipped\n\n", paint(ansiDim, "Files  :"), res.FilesScanned, res.FilesSkipped)

	if len(res.Findings) == 0 {
		fmt.Fprintln(w, paint(ansiGreen, "No workspace traps, AI hooks, or obfuscated payloads detected."))
	} else {
		for _, f := range res.Findings {
			badge := severityBadge(f.Severity, useColor)
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
				if f.Column > 0 {
					loc = fmt.Sprintf("%s:%d", loc, f.Column)
				}
			}

			fmt.Fprintf(w, "%s %s %s %s\n", badge, paint(ansiBold, f.RuleID), paint(ansiDim, "·"), paint(ansiBold, f.Title))
			fmt.Fprintf(w, "  %s %s\n", paint(ansiDim, "File  :"), loc)
			fmt.Fprintf(w, "  %s %s\n", paint(ansiDim, "Detail:"), f.Detail)
			if f.Snippet != "" {
				fmt.Fprintf(w, "  %s %s\n", paint(ansiDim, "Code  :"), f.Snippet)
			}
			if f.Reference != "" {
				fmt.Fprintf(w, "  %s %s\n", paint(ansiDim, "Ref   :"), f.Reference)
			}
			fmt.Fprintln(w)
		}
	}

	ruleLine := strings.Repeat("-", 64)
	fmt.Fprintln(w, paint(ansiDim, ruleLine))
	verdictText := fmt.Sprintf("VERDICT: %s", res.Verdict)
	summary := fmt.Sprintf("(%d Critical, %d High, %d Medium, %d Low)",
		res.Counts.Critical, res.Counts.High, res.Counts.Medium, res.Counts.Low)
	fmt.Fprintf(w, "%s %s\n\n", verdictColor(res.Verdict, verdictText, useColor), summary)
	return nil
}

func severityBadge(sev model.Severity, useColor bool) string {
	tag := fmt.Sprintf("[%s]", sev)
	if !useColor {
		return tag
	}
	switch sev {
	case model.SeverityCritical:
		return ansiBold + ansiBrightRed + tag + ansiReset
	case model.SeverityHigh:
		return ansiBold + ansiRed + tag + ansiReset
	case model.SeverityMedium:
		return ansiBold + ansiYellow + tag + ansiReset
	case model.SeverityLow:
		return ansiCyan + tag + ansiReset
	default:
		return tag
	}
}

func verdictColor(v model.Verdict, text string, useColor bool) string {
	if !useColor {
		return text
	}
	switch v {
	case model.VerdictDanger:
		return ansiBold + ansiBrightRed + text + ansiReset
	case model.VerdictWarn:
		return ansiBold + ansiYellow + text + ansiReset
	default:
		return ansiBold + ansiGreen + text + ansiReset
	}
}
