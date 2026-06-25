// Package authtest checks authentication weaknesses: default credentials on
// login endpoints, missing account lockout, and JWTs signed with no algorithm
// or a weak, guessable secret.
package authtest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

// maxLoginEndpoints bounds how many login endpoints are probed so a large
// captured surface cannot make the tool exceed its timeout.
const maxLoginEndpoints = 12

var loginPaths = []string{
	"/login", "/signin", "/admin/login", "/user/login",
	"/api/login", "/rest/user/login", "/auth", "/account/login",
}

type credential struct {
	user string
	pass string
}

var defaultCredentials = []credential{
	{"admin", "admin"}, {"admin", "password"}, {"admin", "123456"}, {"admin", "admin123"},
	{"root", "root"}, {"root", "toor"}, {"test", "test"}, {"guest", "guest"},
	{"admin", ""}, {"administrator", "administrator"},
}

var weakSecrets = []string{"secret", "password", "123456", "jwt_secret"}

var (
	jwtRe         = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)
	tokenRe       = regexp.MustCompile(`(?i)"?(token|jwt|access_token|auth_token|sessionid|authentication)"?\s*[:=]`)
	lockSignature = regexp.MustCompile(`(?i)locked|too many|rate limit|try again later`)
)

type response struct {
	status    int
	body      string
	dump      string
	setCookie bool
}

// Run probes login endpoints for default credentials, missing lockout, and
// weak JWT signing.
func Run(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	base, err := url.Parse(cfg.Target)
	if err != nil {
		return nil
	}

	var findings []finding.Finding
	seenToken := map[string]bool{}

	endpoints := loginEndpoints(base, surface)
	if len(endpoints) > maxLoginEndpoints {
		endpoints = endpoints[:maxLoginEndpoints]
	}

	for _, endpoint := range endpoints {
		// Cheap reachability gate: skip endpoints that do not exist so dead
		// routes cost one request instead of the full credential/lockout sweep.
		if !reachable(cfg, client, endpoint) {
			continue
		}

		creds, resp := tryDefaultCredentials(cfg, client, endpoint)
		if resp != nil {
			findings = append(findings, defaultCredFinding(endpoint, creds, resp))
		}

		if f, ok := lockoutFinding(cfg, client, endpoint); ok {
			findings = append(findings, f)
		}

		if resp != nil {
			findings = append(findings, jwtFindings(resp.body, seenToken)...)
		}
	}

	return findings
}

// reachable reports whether a login endpoint exists, using a single POST. A nil
// response (network error) or a 404 means the endpoint is not worth probing.
func reachable(cfg *config.Config, client *http.Client, endpoint string) bool {
	resp := postJSON(cfg, client, endpoint, credential{"frx7probe", "frx7probe"})

	return resp != nil && resp.status != http.StatusNotFound
}

func loginEndpoints(base *url.URL, surface *recon.Surface) []string {
	seen := map[string]bool{}
	var list []string

	add := func(raw string) {
		if raw == "" || seen[raw] {
			return
		}

		seen[raw] = true
		list = append(list, raw)
	}

	for _, path := range loginPaths {
		if ref, err := base.Parse(path); err == nil {
			add(ref.String())
		}
	}

	for _, endpoint := range surface.Endpoints {
		lower := strings.ToLower(endpoint)
		if strings.Contains(lower, "login") || strings.Contains(lower, "signin") || strings.Contains(lower, "auth") {
			add(endpoint)
		}
	}

	return list
}

func tryDefaultCredentials(cfg *config.Config, client *http.Client, endpoint string) (credential, *response) {
	for _, cred := range defaultCredentials {
		for _, resp := range []*response{
			postJSON(cfg, client, endpoint, cred),
			postFormLogin(cfg, client, endpoint, cred),
		} {
			if resp != nil && loginSucceeded(resp) {
				return cred, resp
			}
		}
	}

	return credential{}, nil
}

func loginSucceeded(resp *response) bool {
	if resp.status != http.StatusOK {
		return false
	}

	return resp.setCookie || tokenRe.MatchString(resp.body)
}

func defaultCredFinding(endpoint string, cred credential, resp *response) finding.Finding {
	return finding.Finding{
		Title:       "Default credentials accepted at " + endpoint,
		Module:      "authtest",
		Severity:    finding.Critical,
		OWASP:       "A07:2025 - Identification and Authentication Failures",
		CWE:         "CWE-798",
		CVSS:        9.8,
		Description: "A login endpoint accepted a well-known default credential pair and issued a session token, granting authenticated access.",
		Evidence: finding.Evidence{
			Request:   resp.dump,
			Response:  trim(resp.body, 400),
			Extracted: "credential: " + cred.user + ":" + cred.pass + "\nresponse: " + trim(resp.body, 200),
		},
		NextSteps: []string{
			"Remove default accounts and force a password change on first use.",
			"Enforce a strong password policy and multi-factor authentication.",
		},
		Confidence: 1.0,
	}
}

// lockoutFinding sends repeated failed logins and reports when none are blocked.
func lockoutFinding(cfg *config.Config, client *http.Client, endpoint string) (finding.Finding, bool) {
	wrong := credential{"frx7user", "frx7wrongpass"}

	var last *response
	for i := 0; i < 10; i++ {
		resp := postJSON(cfg, client, endpoint, wrong)
		if resp == nil {
			return finding.Finding{}, false
		}

		if resp.status == http.StatusTooManyRequests || resp.status == http.StatusForbidden || lockSignature.MatchString(resp.body) {
			return finding.Finding{}, false
		}

		last = resp
	}

	if last == nil {
		return finding.Finding{}, false
	}

	return finding.Finding{
		Title:       "No account lockout on repeated failed logins at " + endpoint,
		Module:      "authtest",
		Severity:    finding.Medium,
		OWASP:       "A07:2025 - Identification and Authentication Failures",
		CWE:         "CWE-307",
		CVSS:        5.9,
		Description: "Ten consecutive failed login attempts were accepted without throttling or lockout, enabling password brute-force and credential stuffing.",
		Evidence: finding.Evidence{
			Request:   last.dump,
			Response:  trim(last.body, 400),
			Extracted: "10 failed logins, no 429/403/lockout observed",
		},
		NextSteps: []string{
			"Apply rate limiting and progressive lockout after failed attempts.",
			"Add CAPTCHA and multi-factor authentication on the login flow.",
		},
		// Absence of a 429/403/lockout over ten attempts is an indicator, not
		// hard proof: silent rate limiting or throttling may still be in place.
		Confidence: 0.6,
	}, true
}

// jwtFindings inspects a body for JWTs and reports any signed with a weak secret.
func jwtFindings(body string, seen map[string]bool) []finding.Finding {
	var findings []finding.Finding

	for _, token := range jwtRe.FindAllString(body, -1) {
		if seen[token] {
			continue
		}

		seen[token] = true

		secret, ok := crackJWT(token)
		if !ok {
			continue
		}

		forged := signJWT(jwtHeader(token), jwtPayload(token), secret)
		algNone := forgeAlgNone(token)

		findings = append(findings, finding.Finding{
			Title:       "JWT signed with a weak, guessable secret",
			Module:      "authtest",
			Severity:    finding.Critical,
			OWASP:       "A07:2025 - Identification and Authentication Failures",
			CWE:         "CWE-347",
			CVSS:        9.8,
			Description: "A JSON Web Token issued by the application is signed with a trivially guessable HMAC secret, so any token (including elevated-privilege ones) can be forged.",
			Evidence: finding.Evidence{
				Extracted: "token: " + token + "\ncracked secret: " + secret + "\nforged token: " + forged + "\nalg=none token: " + algNone,
			},
			NextSteps: []string{
				"Rotate the signing key to a long, random secret stored securely.",
				"Reject the 'none' algorithm and pin the expected algorithm server-side.",
			},
			Confidence: 1.0,
		})
	}

	return findings
}

func crackJWT(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}

	signingInput := parts[0] + "." + parts[1]

	for _, secret := range weakSecrets {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(signingInput))
		expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

		if hmac.Equal([]byte(expected), []byte(parts[2])) {
			return secret, true
		}
	}

	return "", false
}

func signJWT(header, payload, secret string) string {
	signingInput := header + "." + payload

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + signature
}

func forgeAlgNone(token string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))

	return header + "." + jwtPayload(token) + "."
}

func jwtHeader(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 1 {
		return ""
	}

	return parts[0]
}

func jwtPayload(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}

	return parts[1]
}

func postJSON(cfg *config.Config, client *http.Client, endpoint string, cred credential) *response {
	payload, _ := json.Marshal(map[string]string{
		"username": cred.user,
		"email":    cred.user,
		"password": cred.pass,
	})

	return do(cfg, client, endpoint, "application/json", string(payload))
}

func postFormLogin(cfg *config.Config, client *http.Client, endpoint string, cred credential) *response {
	form := url.Values{}
	form.Set("username", cred.user)
	form.Set("email", cred.user)
	form.Set("password", cred.pass)

	return do(cfg, client, endpoint, "application/x-www-form-urlencoded", form.Encode())
}

func do(cfg *config.Config, client *http.Client, endpoint, contentType, payload string) *response {
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

	return &response{
		status:    resp.StatusCode,
		body:      string(body),
		dump:      string(dump),
		setCookie: resp.Header.Get("Set-Cookie") != "",
	}
}

func trim(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}

	return s
}
