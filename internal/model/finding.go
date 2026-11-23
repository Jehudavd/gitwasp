package model

import "strings"

// Severity represents how dangerous a detected trap or misconfiguration is.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// SeverityRank returns a numeric priority for sorting findings (higher = more severe).
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// ParseSeverity parses a case-insensitive severity string.
func ParseSeverity(raw string) (Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case string(SeverityCritical):
		return SeverityCritical, true
	case string(SeverityHigh):
		return SeverityHigh, true
	case string(SeverityMedium):
		return SeverityMedium, true
	case string(SeverityLow):
		return SeverityLow, true
	default:
		return "", false
	}
}

// Verdict summarizes the overall trust recommendation for a scanned target.
type Verdict string

const (
	VerdictSafe   Verdict = "SAFE"
	VerdictWarn   Verdict = "WARN"
	VerdictDanger Verdict = "DANGER"
)

// ComputeVerdict determines the overall verdict from a slice of findings.
func ComputeVerdict(findings []Finding) Verdict {
	hasWarn := false
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical, SeverityHigh:
			return VerdictDanger
		case SeverityMedium, SeverityLow:
			hasWarn = true
		}
	}
	if hasWarn {
		return VerdictWarn
	}
	return VerdictSafe
}

// ExitCode maps a scan verdict to a CLI exit code.
func ExitCode(v Verdict) int {
	switch v {
	case VerdictDanger:
		return 2
	case VerdictWarn:
		return 1
	default:
		return 0
	}
}

// FileEntry holds the raw bytes of a collected file for static inspection.
type FileEntry struct {
	Path      string
	Content   []byte
	Size      int64
	Truncated bool
}

// Finding represents a single security finding produced by a rule.
type Finding struct {
	RuleID    string   `json:"rule_id"`
	Title     string   `json:"title"`
	Severity  Severity `json:"severity"`
	File      string   `json:"file"`
	Line      int      `json:"line"`
	Column    int      `json:"column,omitempty"`
	Detail    string   `json:"detail"`
	Snippet   string   `json:"snippet,omitempty"`
	Reference string   `json:"reference,omitempty"`
}

// Counts holds the number of findings per severity level.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// ScanResult holds the complete output of a gitwasp scan.
type ScanResult struct {
	Target       string    `json:"target"`
	Mode         string    `json:"mode"`
	FilesScanned int       `json:"files_scanned"`
	FilesSkipped int       `json:"files_skipped"`
	Findings     []Finding `json:"findings"`
	Verdict      Verdict   `json:"verdict"`
	Counts       Counts    `json:"counts"`
}
