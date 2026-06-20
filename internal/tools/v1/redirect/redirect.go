// Package redirect tests open redirects: it injects external destinations into
// redirect-like parameters and confirms a hit when the response redirects off
// the original origin via the Location header or a meta-refresh tag.
package redirect

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
)

const evilHost = "evil.example"

var paramHint = regexp.MustCompile(`(?i)^(redirect|return|next|url|goto|dest|destination|continue|back|redir|target|r)$`)

var payloads = []string{
	"https://" + evilHost,
	"//" + evilHost,
	"/\\" + evilHost,
	"javascript:alert(1)",
	"data:text/html,<script>alert(1)</script>",
	"vbscript:msgbox(1)",
	"https://" + evilHost + "%2F@legitimate.com",
}

var metaRefreshRe = regexp.MustCompile(`(?i)<meta[^>]+http-equiv=["']refresh["'][^>]+url=([^"'>]+)`)

type response struct {
	status   int
	location string
	body     string
	dump     string
}

// Run injects open-redirect payloads into redirect-like parameters.
func Run(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	noRedirect := &http.Client{
		Transport: client.Transport,
		Timeout:   client.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

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

		if f, ok := testParam(cfg, noRedirect, p); ok {
			findings = append(findings, f)
		}
	}

	return findings
}

func testParam(cfg *config.Config, client *http.Client, p recon.Param) (finding.Finding, bool) {
	for _, payload := range payloads {
		resp := request(cfg, client, p, payload)
		if resp == nil {
			continue
		}

		destination := confirmRedirect(resp)
		if destination == "" {
			continue
		}

		return finding.Finding{
			Title:       "Open redirect via parameter '" + p.Name + "'",
			Module:      "redirect",
			Severity:    finding.Medium,
			OWASP:       "A01:2025 - Broken Access Control",
			CWE:         "CWE-601",
			CVSS:        6.1,
			Description: "The parameter controls the redirect destination, allowing an attacker to send victims to an external site for phishing or token theft.",
			Evidence: finding.Evidence{
				Request:   resp.dump,
				Response:  trim(resp.body, 400),
				Extracted: "payload: " + payload + "\ndestination: " + destination,
			},
			NextSteps: []string{
				"Redirect only to an allowlist of known-safe paths or hosts.",
				"Reject absolute URLs, protocol-relative values, and executable URL schemes in redirect parameters.",
			},
		}, true
	}

	return finding.Finding{}, false
}

// confirmRedirect returns the external or executable destination when the
// response redirects to one, or an empty string when it does not.
func confirmRedirect(resp *response) string {
	if resp.location != "" {
		if strings.Contains(resp.location, evilHost) || hasExecutableScheme(resp.location) {
			return resp.location
		}
	}

	if m := metaRefreshRe.FindStringSubmatch(resp.body); m != nil {
		if strings.Contains(m[1], evilHost) {
			return strings.TrimSpace(m[1])
		}
	}

	return ""
}

func hasExecutableScheme(raw string) bool {
	value := strings.ToLower(strings.TrimSpace(raw))

	return strings.HasPrefix(value, "javascript:") ||
		strings.HasPrefix(value, "data:") ||
		strings.HasPrefix(value, "vbscript:")
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

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	return &response{
		status:   resp.StatusCode,
		location: resp.Header.Get("Location"),
		body:     string(body),
		dump:     string(dump),
	}
}

func trim(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}

	return s
}
