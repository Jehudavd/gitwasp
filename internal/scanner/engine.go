package scanner

import (
	"sort"
	"strconv"

	"github.com/Jehudavd/gitwasp/internal/model"
)

type ruleFunc func(model.FileEntry) []model.Finding

var allRules = []ruleFunc{
	checkIDE,
	checkAI,
	checkPkg,
	checkGit,
	checkObf,
}

// Scan runs all static security rules over collected files and returns a sorted,
// deduplicated ScanResult without executing any code from the target.
func Scan(target, mode string, files []model.FileEntry, skipped int) model.ScanResult {
	return ScanWithExtraFindings(target, mode, files, skipped, nil)
}

// ScanWithExtraFindings runs all static security rules over collected files and
// merges pre-computed metadata findings (for example archive-level hazards).
func ScanWithExtraFindings(target, mode string, files []model.FileEntry, skipped int, extra []model.Finding) model.ScanResult {
	raw := make([]model.Finding, 0, len(extra))
	raw = append(raw, extra...)
	for _, f := range files {
		for _, rule := range allRules {
			findings := rule(f)
			if len(findings) > 0 {
				raw = append(raw, findings...)
			}
		}
	}

	deduped := deduplicateFindings(raw)

	sort.Slice(deduped, func(i, j int) bool {
		ri := model.SeverityRank(deduped[i].Severity)
		rj := model.SeverityRank(deduped[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if deduped[i].File != deduped[j].File {
			return deduped[i].File < deduped[j].File
		}
		if deduped[i].Line != deduped[j].Line {
			return deduped[i].Line < deduped[j].Line
		}
		return deduped[i].RuleID < deduped[j].RuleID
	})

	var counts model.Counts
	for _, f := range deduped {
		switch f.Severity {
		case model.SeverityCritical:
			counts.Critical++
		case model.SeverityHigh:
			counts.High++
		case model.SeverityMedium:
			counts.Medium++
		case model.SeverityLow:
			counts.Low++
		}
	}

	return model.ScanResult{
		Target:       target,
		Mode:         mode,
		FilesScanned: len(files),
		FilesSkipped: skipped,
		Findings:     deduped,
		Verdict:      model.ComputeVerdict(deduped),
		Counts:       counts,
	}
}

func deduplicateFindings(in []model.Finding) []model.Finding {
	if len(in) == 0 {
		return []model.Finding{}
	}
	seen := make(map[string]int, len(in))
	out := make([]model.Finding, 0, len(in))
	for _, f := range in {
		key := f.RuleID + "|" + f.File + "|" + strconv.Itoa(f.Line)
		if idx, ok := seen[key]; ok {
			if model.SeverityRank(f.Severity) > model.SeverityRank(out[idx].Severity) {
				out[idx] = f
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, f)
	}
	return out
}
