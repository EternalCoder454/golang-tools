// Command secscan is a pre-push secret scanner: it walks a directory and flags
// files that contain private keys, credentials, API tokens, or secret-looking
// assignments — the things you never want to push to a public repo. Built for a
// homelab where the CA private key and a cluster token live near the code.
//
// Exit status is non-zero when any HIGH-severity finding is present, so it drops
// straight into a git pre-push/pre-commit hook or CI step. Pure standard library.
//
//	secscan [-q] [-no-entropy] [path ...]     # default path: .
//
// Suppress a known-safe line with a trailing `secscan:ignore` comment.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type severity int

const (
	high severity = iota
	warn
)

func (s severity) String() string {
	if s == high {
		return "HIGH"
	}
	return "WARN"
}

type rule struct {
	name string
	re   *regexp.Regexp
	sev  severity
}

// High-confidence content rules. Patterns use character classes (not literal
// secrets) so secscan doesn't flag its own source.
var rules = []rule{
	{"private-key-block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`), high},
	{"aws-access-key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), high},
	{"github-token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`), high},
	{"slack-token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`), high},
	{"google-api-key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), high},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`), high},
	{"cluster-token", regexp.MustCompile(`(?i)CLUSTER_TOKEN\s*[:=]\s*["']?\S{8,}`), high},
	{"private-key-id", regexp.MustCompile(`(?i)"private_key_id"\s*:\s*"[0-9a-f]{20,}"`), high},
}

// secretAssign catches `name = value` where the name looks secret and the value
// is long/random enough to be a real credential (entropy-gated below).
// No leading \b so prefixed names (db_password, my_secret) still match; the
// trailing \b stops false hits like "tokenizer" / "passwordless".
var secretAssign = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*["']?([A-Za-z0-9+/_\-]{12,})["']?`)

// Filenames that are themselves secrets.
var secretFiles = regexp.MustCompile(`(?i)(^|/)(id_(rsa|dsa|ecdsa|ed25519)|ca\.key|.*\.(key|pem|pfx|p12|keystore|jks))$`)

var entropyTok = regexp.MustCompile(`[A-Za-z0-9+/_\-]{24,}`)

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".cache": true, "dist": true, "build": true}

type finding struct {
	path string
	line int
	rule string
	sev  severity
	snip string
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var e, n float64 = 0, float64(len(s))
	for _, c := range freq {
		if c > 0 {
			p := float64(c) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

// redact keeps the shape but hides the value so the report itself isn't a leak.
func redact(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 40 {
		s = s[:40] + "…"
	}
	b := []rune(s)
	for i := range b {
		if i >= 4 && b[i] != ' ' && b[i] != '=' && b[i] != ':' && b[i] != '"' && b[i] != '\'' && b[i] != '-' {
			b[i] = '•'
		}
	}
	return string(b)
}

func looksBinary(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

func scanFile(path string, noEntropy bool) (out []finding) {
	if secretFiles.MatchString(filepath.ToSlash(path)) {
		out = append(out, finding{path, 0, "secret-file", warn, "file looks like a key/credential — exclude from the repo"})
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := f.Read(head)
	if looksBinary(head[:n]) {
		return // skip binaries
	}
	f.Seek(0, 0)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	ln := 0
	inPEM := false // inside a -----BEGIN…END----- block
	for sc.Scan() {
		ln++
		line := sc.Text()
		if strings.Contains(line, "secscan:ignore") {
			if strings.Contains(line, "-----END") {
				inPEM = false
			}
			continue
		}
		// explicit high-confidence rules run on every line (incl. the BEGIN line)
		for _, r := range rules {
			if m := r.re.FindString(line); m != "" {
				out = append(out, finding{path, ln, r.name, r.sev, redact(m)})
			}
		}
		// inside a PEM block the body is public cert data or an already-flagged
		// key — skip the fuzzy heuristics that would just spam every base64 line.
		if strings.Contains(line, "-----BEGIN") {
			inPEM = true
		}
		if strings.Contains(line, "-----END") {
			inPEM = false
			continue
		}
		if inPEM {
			continue
		}
		if m := secretAssign.FindStringSubmatch(line); m != nil {
			val := m[2]
			if len(val) >= 20 || shannon(val) >= 3.5 { // gate generic matches on randomness
				out = append(out, finding{path, ln, "secret-assignment", high, redact(m[0])})
			}
		}
		if !noEntropy {
			trimmed := strings.TrimSpace(line)
			for _, tok := range entropyTok.FindAllString(line, -1) {
				// require surrounding context — a whole-line blob is data, not an inline secret
				if shannon(tok) >= 4.6 && len(tok) < len(trimmed) {
					out = append(out, finding{path, ln, "high-entropy", warn, redact(tok)})
					break
				}
			}
		}
	}
	return
}

func main() {
	quiet := flag.Bool("q", false, "only print findings (no per-scan summary)")
	noEntropy := flag.Bool("no-entropy", false, "disable the high-entropy heuristic (fewer false positives)")
	flag.Parse()
	paths := flag.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	var all []finding
	var scanned int
	for _, root := range paths {
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if info, err := d.Info(); err == nil && info.Size() > 5<<20 {
				return nil // skip files > 5 MiB
			}
			scanned++
			all = append(all, scanFile(p, *noEntropy)...)
			return nil
		})
	}

	var highN, warnN int
	for _, f := range all {
		loc := f.path
		if f.line > 0 {
			loc = fmt.Sprintf("%s:%d", f.path, f.line)
		}
		fmt.Printf("%-4s %-18s %s\n     %s\n", f.sev, f.rule, loc, f.snip)
		if f.sev == high {
			highN++
		} else {
			warnN++
		}
	}
	if !*quiet {
		if len(all) == 0 {
			fmt.Printf("✓ no secrets found in %d files\n", scanned)
		} else {
			fmt.Printf("\n%d file(s) scanned — %d HIGH, %d WARN\n", scanned, highN, warnN)
		}
	}
	if highN > 0 {
		os.Exit(1)
	}
}
