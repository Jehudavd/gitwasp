package scanner

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	rePipeToShell = regexp.MustCompile(`(?i)\b(curl|wget)\b[^\r\n]*\|\s*(sh|bash|zsh|dash|ash|powershell(?:\.exe)?|pwsh)\b`)
	rePSPipeIEX   = regexp.MustCompile(`(?i)\b(iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\r\n]*\|\s*(iex|invoke-expression)\b`)
	reShellFetch  = regexp.MustCompile(`(?i)\b(sh|bash|zsh)\s+-c\s+["'][^"']*\b(curl|wget)\b`)

	rePSEncoded = regexp.MustCompile(`(?i)\b(?:powershell(?:\.exe)?|pwsh)\b[^\r\n]*(?:\s-(?:e|en|enc|encodedcommand)\s+|\b(?:iex|invoke-expression|downloadstring|frombase64string)\b)`)
	rePSIEXCall = regexp.MustCompile(`(?i)\b(?:invoke-expression|downloadstring)\s*\(`)

	reEvalCall  = regexp.MustCompile(`(?i)\beval\s*\(`)
	reNewFunc   = regexp.MustCompile(`(?i)\bnew\s+Function\s*\(`)
	reBufferB64 = regexp.MustCompile(`(?i)Buffer\.from\s*\([^\r\n]{1,200},\s*['"]base64['"]\s*\)`)
	reAtobCall  = regexp.MustCompile(`(?i)\batob\s*\(`)
	reBase64Dec = regexp.MustCompile(`(?i)\bbase64\s+(?:-d|--decode)\b`)
	rePyInline  = regexp.MustCompile(`(?i)\bpython[23]?\b[^\r\n]*\s-c\s[^\r\n]*(?:\bexec\s*\(|\b__import__\s*\(|\beval\s*\(|\bb64decode\b)`)

	reDisguisedAsset = regexp.MustCompile(`(?i)\b(?:node|python[23]?|sh|bash|zsh|powershell(?:\.exe)?|pwsh)\b[^\r\n]*\.(?:woff2?|ttf|otf|png|jpe?g|gif|svg|ico|pdf)\b`)

	reRawIPURL = regexp.MustCompile(`(?i)https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?`)

	reCredAccess = regexp.MustCompile(`(?i)(?:~/\.ssh|\$HOME/\.ssh|~/\.aws|\$HOME/\.aws|\bid_rsa\b|\bid_ed25519\b|login\.keychain|\.kube/config)`)
	reNetCmd     = regexp.MustCompile(`(?i)\b(?:curl|wget|nc|ncat|scp|rsync|invoke-webrequest|irm)\b|https?://`)

	reShellOrNet = regexp.MustCompile(`(?i)\b(?:sh|bash|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|curl|wget|iwr|irm|iex|node|python[23]?)\b|https?://`)
)

// SuspiciousCommandMatch checks a command or script snippet for high-risk
// execution, obfuscation, or exfiltration patterns using ReDoS-safe stdlib regexes.
func SuspiciousCommandMatch(cmd string) (bool, string) {
	if strings.TrimSpace(cmd) == "" {
		return false, ""
	}

	if rePipeToShell.MatchString(cmd) || rePSPipeIEX.MatchString(cmd) || reShellFetch.MatchString(cmd) {
		return true, "downloads remote script and pipes to shell"
	}
	if rePSEncoded.MatchString(cmd) || rePSIEXCall.MatchString(cmd) {
		return true, "obfuscated or encoded PowerShell execution"
	}
	if reBufferB64.MatchString(cmd) {
		return true, "decodes Base64 buffer dynamically"
	}
	if reEvalCall.MatchString(cmd) || reNewFunc.MatchString(cmd) || reAtobCall.MatchString(cmd) || reBase64Dec.MatchString(cmd) || rePyInline.MatchString(cmd) {
		return true, "dynamic code evaluation or Base64 decoding"
	}
	if reDisguisedAsset.MatchString(cmd) {
		return true, "executes disguised non-code asset file"
	}
	if m := reRawIPURL.FindStringSubmatch(cmd); len(m) == 2 {
		ip := m[1]
		if ip != "127.0.0.1" && ip != "0.0.0.0" {
			return true, "connects to raw IP URL (" + ip + ")"
		}
	}
	if reCredAccess.MatchString(cmd) && reNetCmd.MatchString(cmd) {
		return true, "accesses credential paths alongside network command"
	}

	return false, ""
}

// HasRawPublicIPURL reports whether s contains an HTTP(S) URL pointing to a raw IP
// other than localhost loopback/unspecified addresses.
func HasRawPublicIPURL(s string) (bool, string) {
	for _, m := range reRawIPURL.FindAllStringSubmatch(s, -1) {
		if len(m) == 2 && m[1] != "127.0.0.1" && m[1] != "0.0.0.0" {
			return true, m[1]
		}
	}
	return false, ""
}

// ContainsShellOrNetwork reports whether cmd invokes a shell/interpreter or HTTP URL.
func ContainsShellOrNetwork(cmd string) bool {
	return reShellOrNet.MatchString(cmd)
}

// HiddenRuneCategory describes invisible or bidirectional Unicode characters.
type HiddenRuneCategory string

const (
	HiddenNone      HiddenRuneCategory = ""
	HiddenBiDi      HiddenRuneCategory = "BiDi override"
	HiddenTag       HiddenRuneCategory = "Unicode tag"
	HiddenZeroWidth HiddenRuneCategory = "zero-width"
)

// ClassifyHiddenRune classifies Trojan Source BiDi controls, Unicode Tag characters,
// and zero-width characters.
func ClassifyHiddenRune(r rune) HiddenRuneCategory {
	switch {
	case (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x061C || r == 0x200E || r == 0x200F:
		return HiddenBiDi
	case r >= 0xE0000 && r <= 0xE007F:
		return HiddenTag
	case (r >= 0x200B && r <= 0x200D) || r == 0xFEFF:
		return HiddenZeroWidth
	default:
		return HiddenNone
	}
}

// SanitizeSnippet neutralizes terminal escape sequences, control characters, and
// invisible/BiDi runes so untrusted files cannot spoof terminal output.
func SanitizeSnippet(s string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 140
	}

	var b strings.Builder
	b.Grow(len(s))

	lastSpace := false
	for _, r := range s {
		if r == '\r' || r == '\n' || r == '\t' || r == ' ' {
			if !lastSpace && b.Len() > 0 {
				b.WriteByte(' ')
				lastSpace = true
			}
			continue
		}
		lastSpace = false

		if r == 0x1B {
			b.WriteString("[ESC]")
			continue
		}
		if r < 0x20 || r == 0x7F {
			fmt.Fprintf(&b, "[U+%04X]", r)
			continue
		}
		if ClassifyHiddenRune(r) != HiddenNone {
			fmt.Fprintf(&b, "[U+%04X]", r)
			continue
		}
		b.WriteRune(r)
	}

	clean := strings.TrimSpace(b.String())
	if utf8.RuneCountInString(clean) <= maxLen {
		return clean
	}

	runes := []rune(clean)
	if maxLen <= 3 {
		return string(runes[:maxLen])
	}
	return string(runes[:maxLen-3]) + "..."
}

func flattenArgs(args []any) []string {
	var out []string
	for _, a := range args {
		switch v := a.(type) {
		case string:
			out = append(out, v)
		case map[string]any:
			if val, ok := v["value"].(string); ok {
				out = append(out, val)
			}
		}
	}
	return out
}

func splitLines(content []byte) []string {
	s := strings.ReplaceAll(string(content), "\r\n", "\n")
	return strings.Split(s, "\n")
}
