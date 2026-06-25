// Package access tests broken access control: sensitive endpoints reachable
// without authentication, and IDOR by enumerating numeric identifiers.
package access

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
	"github.com/sayseven7/frameseven/internal/verify"
)

// spaSignatures mark an HTML body as a single-page-app shell, the generic 200
// catch-all that many SPAs return for unknown paths. They must not be reported
// as exposed sensitive endpoints.
var spaSignatures = []string{
	"<app-root>", "ng-version", "data-reactroot", "__NEXT_DATA__",
	"<div id=\"root\"", "<div id=\"app\"", "window.__nuxt__",
}

// adminPaths are endpoints that should normally require authentication.
var adminPaths = []string{
	"/admin",
	"/admin/",
	"/administrator",
	"/dashboard",
	"/api/admin",
	"/api/users",
	"/actuator",
	"/actuator/env",
	"/manager/html",
	"/console",
	"/config",
	"/metrics",
	"/cpanel",
	"/wp-admin/",
}

type response struct {
	status      int
	body        string
	dump        string
	contentType string
}

// Run probes unauthenticated access and IDOR.
func Run(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	base, err := url.Parse(cfg.Target)
	if err != nil {
		return nil
	}

	var findings []finding.Finding

	findings = append(findings, unauthEndpoints(cfg, client, base, surface)...)

	// IDOR probing mutates numeric identifiers and can reach data belonging to
	// other users, so it is treated as an active technique and only runs when
	// the operator opts in to an active scan.
	if cfg.ActiveScan {
		findings = append(findings, idor(cfg, client, surface)...)
		findings = append(findings, pathIDOR(cfg, client, surface)...)
		findings = append(findings, collectionIDOR(cfg, client, surface)...)
	}

	return findings
}

func unauthEndpoints(cfg *config.Config, client *http.Client, base *url.URL, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	reported := map[string]bool{}

	root := get(cfg, client, base.String())

	// Probe a path that should not exist so soft-404 pages (a 200 catch-all for
	// unknown routes) can be told apart from a genuinely reachable endpoint.
	var control *response
	if ref, err := base.Parse("/frameseven-access-probe-404"); err == nil {
		control = get(cfg, client, ref.String())
	}

	for _, path := range allAdminPaths(cfg) {
		ref, err := base.Parse(path)
		if err != nil {
			continue
		}

		normalized := strings.TrimRight(path, "/")
		if reported[normalized] {
			continue
		}

		resp := get(cfg, client, ref.String())
		if resp == nil {
			continue
		}

		reported[normalized] = true

		switch resp.status {
		case http.StatusOK:
			// A 200 alone is not exposure: SPA shells, soft-404 catch-alls, and
			// login pages all answer 200. Each of these means the endpoint is not
			// actually serving protected data without authentication.
			if verify.MatchesBaseline(surface.Baseline, resp.status, resp.contentType, []byte(resp.body)) {
				continue // catch-all, not an exposed endpoint
			}

			if isSPAIndex(resp, root) || looksSoft404(resp, control) {
				continue
			}

			if looksLogin(resp) {
				findings = append(findings, adminCandidate(path, resp,
					"An administrative path returned a login page, so it is gated by authentication."))

				continue
			}

			findings = append(findings, finding.Finding{
				Title:       "Sensitive endpoint reachable without authentication: " + path,
				Module:      "access",
				Severity:    finding.High,
				OWASP:       "A01:2025 - Broken Access Control",
				CWE:         "CWE-284",
				CVSS:        7.5,
				Description: "An administrative or internal endpoint returned 200 without any authentication.",
				Evidence: finding.Evidence{
					Request:   resp.dump,
					Response:  trim(resp.body, 400),
					Extracted: unauthExtracted(path, resp),
				},
				NextSteps: []string{
					"Require authentication and authorization on this endpoint.",
					"Verify access checks are enforced server-side, not only in the UI.",
				},
			})
		case http.StatusUnauthorized, http.StatusForbidden:
			findings = append(findings, adminCandidate(path, resp,
				"An administrative path exists and returned an authentication or authorization response."))
		}
	}

	return findings
}

func allAdminPaths(cfg *config.Config) []string {
	seen := map[string]bool{}
	var selected []string

	for _, path := range adminPaths {
		selected = appendAdminPath(selected, seen, path)
	}

	for _, payload := range cfg.NormalizedCustomPayloads() {
		if strings.Contains(payload, "://") {
			continue
		}

		path := payload
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		selected = appendAdminPath(selected, seen, path)
	}

	return selected
}

func appendAdminPath(paths []string, seen map[string]bool, path string) []string {
	path = strings.TrimSpace(path)
	if path == "" || seen[path] {
		return paths
	}

	seen[path] = true

	return append(paths, path)
}

// isSPAIndex reports whether a 200 HTML response is the single-page-app shell
// rather than a distinct sensitive endpoint. It matches known SPA markers and
// treats a body whose size is within 5% of the root page as the SPA catch-all.
func isSPAIndex(resp, root *response) bool {
	if !strings.Contains(strings.ToLower(resp.contentType), "text/html") {
		return false
	}

	for _, sig := range spaSignatures {
		if strings.Contains(resp.body, sig) {
			return true
		}
	}

	if root != nil && root.status == http.StatusOK && sizeWithin(resp.body, root.body, 0.05) {
		return true
	}

	return false
}

// loginSignatures are markers that an HTML body is a login/sign-in page. Their
// presence on an admin path means the endpoint is gated by authentication, not
// exposed, so a 200 must not be reported as an unauthenticated exposure.
var loginSignatures = []string{
	"type=\"password\"", "type='password'", "name=\"password\"", "name='password'",
	"id=\"password\"", "login-form", "loginform", "sign in", "sign-in", "log in",
	"please log in", "please sign in", "csrf",
}

// looksLogin reports whether an HTML response is a login or sign-in page.
func looksLogin(resp *response) bool {
	if resp == nil || !strings.Contains(strings.ToLower(resp.contentType), "text/html") {
		return false
	}

	lower := strings.ToLower(resp.body)
	for _, sig := range loginSignatures {
		if strings.Contains(lower, sig) {
			return true
		}
	}

	return false
}

// looksSoft404 reports whether a 200 response is the target's catch-all page for
// unknown paths, judged against a control probe of a path that should not exist.
func looksSoft404(resp, control *response) bool {
	if resp == nil || control == nil || control.status != http.StatusOK {
		return false
	}

	if resp.status != http.StatusOK {
		return false
	}

	return resp.body == control.body || comparableSize(resp.body, control.body)
}

// adminCandidate builds the informational finding for an administrative path
// that exists but is gated (a 401/403 response or a 200 login page) rather than
// exposed.
func adminCandidate(path string, resp *response, description string) finding.Finding {
	return finding.Finding{
		Title:       "Administrative interface candidate discovered: " + path,
		Module:      "access",
		Severity:    finding.Info,
		OWASP:       "A01:2025 - Broken Access Control",
		CWE:         "CWE-200",
		Description: description,
		Evidence: finding.Evidence{
			Request:   resp.dump,
			Response:  trim(resp.body, 400),
			Extracted: path + " (" + strconv.Itoa(resp.status) + ")",
		},
		NextSteps: []string{
			"Confirm this interface is intentionally exposed.",
			"Keep authorization checks server-side and monitor access attempts.",
		},
	}
}

// sizeWithin reports whether two bodies are the same size within the tolerance.
func sizeWithin(a, b string, tolerance float64) bool {
	la, lb := len(a), len(b)
	if la == 0 || lb == 0 {
		return false
	}

	diff := la - lb
	if diff < 0 {
		diff = -diff
	}

	return float64(diff)/float64(lb) <= tolerance
}

// unauthExtracted renders the evidence for an exposed endpoint, including the
// JSON body and its exact size when the response is JSON.
func unauthExtracted(path string, resp *response) string {
	if !strings.Contains(strings.ToLower(resp.contentType), "json") {
		return path
	}

	return path + "\nContent-Type: " + resp.contentType +
		"\nSize: " + strconv.Itoa(len(resp.body)) + " bytes\n\n" +
		trim(resp.body, 500)
}

var idRe = regexp.MustCompile(`^\d+$`)

// emailRe matches an email address, a strong indicator of per-user data.
var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// sensitiveKeywords are lower-case markers that suggest a response body holds
// data scoped to a specific user or account rather than public content.
var sensitiveKeywords = []string{
	"password", "passwd",
	"private", "ssn", "social security",
	"credit card", "card number", "cardnumber", "cvv",
	"api_key", "apikey", "access_token", "auth_token", "secret",
	"account number", "accountnumber", "iban", "routing number",
	"date of birth", "dateofbirth", "birthdate", "phone number",
}

func idor(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	tested := map[string]bool{}

	for _, p := range surface.Params {
		// Cache-busting / resize / versioning params are not object references.
		if verify.IsStaticAssetParam(p.Name) {
			continue
		}

		u, err := url.Parse(p.Endpoint)
		if err != nil {
			continue
		}

		value := u.Query().Get(p.Name)
		if !idRe.MatchString(value) {
			continue
		}

		key := p.Name + "|" + u.Path
		if tested[key] {
			continue
		}

		tested[key] = true

		if f, ok := probeIDOR(cfg, client, p, value); ok {
			findings = append(findings, f)
		}
	}

	return findings
}

func probeIDOR(cfg *config.Config, client *http.Client, p recon.Param, value string) (finding.Finding, bool) {
	id, _ := strconv.Atoi(value)

	base := getParam(cfg, client, p, value)
	if base == nil || base.status != http.StatusOK {
		return finding.Finding{}, false
	}

	// Authorization checks on static assets (CSS/JS/images) are noise.
	if verify.IsStaticAssetResponse(base.contentType, p.Endpoint) {
		return finding.Finding{}, false
	}

	resource := resourceFromParam(p)

	for _, delta := range []int{1, -1, 2} {
		neighbor := id + delta
		if neighbor < 0 {
			continue
		}

		resp := getParam(cfg, client, p, strconv.Itoa(neighbor))
		if resp == nil {
			continue
		}

		// Require a real delta between the two ids: identical responses for
		// different ids are cache-busting/resize behavior, not an IDOR.
		diff := verify.CompareResponses(base.status, []byte(base.body), resp.status, []byte(resp.body))
		if !diff.HasDelta {
			continue
		}

		severity, marker, ok := classifyNeighbor(resource, base, resp)
		if !ok {
			continue
		}

		extracted := p.Name + "=" + value + " -> " + p.Name + "=" + strconv.Itoa(neighbor)
		title := idorTitle(severity, "parameter '"+p.Name+"'")

		if severity == finding.High {
			if summary := enumerateIDs(func(id int) *response {
				return getParam(cfg, client, p, strconv.Itoa(id))
			}); summary != "" {
				extracted += "\n" + summary
			}
		}

		return buildIDOR(severity, title, extracted, marker, resp), true
	}

	return finding.Finding{}, false
}

// maxPathIDORTemplates bounds how many distinct path templates are probed so a
// large captured surface cannot blow up the access tool's runtime.
const maxPathIDORTemplates = 50

// pathIDOR tests broken object-level authorization on REST routes whose object
// identifier sits in a numeric path segment, for example /rest/basket/6 or
// /api/Users/1. These are the common SPA/API IDOR shapes that the query-string
// IDOR check cannot reach. Requests run with the captured session, so a
// successful read of another object proves a missing ownership check.
func pathIDOR(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	tested := map[string]bool{}

	for _, endpoint := range surface.Endpoints {
		u, err := url.Parse(endpoint)
		if err != nil {
			continue
		}

		segments := strings.Split(u.Path, "/")
		for i, segment := range segments {
			if !idRe.MatchString(segment) {
				continue
			}

			template := u.Host + "|" + pathTemplate(segments, i)
			if tested[template] {
				continue
			}

			if len(tested) >= maxPathIDORTemplates {
				return findings
			}

			tested[template] = true

			if f, ok := probePathIDOR(cfg, client, u, segments, i); ok {
				findings = append(findings, f)
			}
		}
	}

	return findings
}

func probePathIDOR(cfg *config.Config, client *http.Client, u *url.URL, segments []string, idx int) (finding.Finding, bool) {
	value := segments[idx]

	id, err := strconv.Atoi(value)
	if err != nil {
		return finding.Finding{}, false
	}

	base := get(cfg, client, withSegment(u, segments, idx, value))
	if base == nil || base.status != http.StatusOK {
		return finding.Finding{}, false
	}

	template := pathTemplate(segments, idx)
	resource := precedingSegment(segments, idx)

	for _, delta := range []int{1, -1, 2} {
		neighbor := id + delta
		if neighbor < 0 {
			continue
		}

		resp := get(cfg, client, withSegment(u, segments, idx, strconv.Itoa(neighbor)))

		severity, marker, ok := classifyNeighbor(resource, base, resp)
		if !ok {
			continue
		}

		extracted := template + ": " + value + " -> " + strconv.Itoa(neighbor)
		title := idorTitle(severity, "path '"+template+"'")

		if severity == finding.High {
			if summary := enumerateIDs(func(id int) *response {
				return get(cfg, client, withSegment(u, segments, idx, strconv.Itoa(id)))
			}); summary != "" {
				extracted += "\n" + summary
			}
		}

		return buildIDOR(severity, title, extracted, marker, resp), true
	}

	return finding.Finding{}, false
}

// pathTemplate renders the path with the segment at idx replaced by {id}, used
// to deduplicate probes and to label findings, e.g. /rest/basket/{id}.
func pathTemplate(segments []string, idx int) string {
	replaced := make([]string, len(segments))
	copy(replaced, segments)
	replaced[idx] = "{id}"

	return strings.Join(replaced, "/")
}

// withSegment returns the URL string with the path segment at idx set to value.
func withSegment(u *url.URL, segments []string, idx int, value string) string {
	replaced := make([]string, len(segments))
	copy(replaced, segments)
	replaced[idx] = value

	clone := *u
	clone.Path = strings.Join(replaced, "/")

	return clone.String()
}

// ownerRoots are substrings that mark a resource as user- or account-owned.
// When a candidate reference targets one of these, an adjacent identifier that
// returns another 200 object (instead of 403/404) is a missing ownership check,
// not merely an enumerable public reference.
var ownerRoots = []string{
	"user", "account", "customer",
	"basket", "cart", "order", "invoice", "receipt",
	"card", "wallet", "payment", "transaction",
	"address", "profile", "contact", "phone", "email",
	"message", "ticket", "document", "report",
	"booking", "reservation", "subscription", "passport",
}

// isOwnedResource reports whether name references a user-owned object type.
func isOwnedResource(name string) bool {
	lower := strings.ToLower(name)
	for _, root := range ownerRoots {
		if strings.Contains(lower, root) {
			return true
		}
	}

	return false
}

// looksStructured reports whether a body is a JSON object or array, the usual
// shape of an API resource. It separates a real object from an SPA's HTML
// fallback that many apps return with 200 for unknown identifiers.
func looksStructured(body string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return false
	}

	return trimmed[0] == '{' || trimmed[0] == '['
}

// classifyNeighbor decides whether a neighbor object reference is a real IDOR
// (High), an enumerable-but-public reference (Info), or nothing. The decision
// follows ownership semantics rather than blind id enumeration: a user-owned
// resource that returns a distinct 200 object under the authenticated session is
// a broken ownership check, regardless of whether the body happens to contain an
// email. A neighbor that returns 403/404 (ownership enforced) yields nothing.
func classifyNeighbor(resource string, base, neighbor *response) (finding.Severity, string, bool) {
	if neighbor == nil || neighbor.status != http.StatusOK {
		return "", "", false
	}

	if base != nil && neighbor.body == base.body {
		return "", "", false
	}

	structured := looksStructured(neighbor.body)
	sized := base != nil && comparableSize(base.body, neighbor.body)

	// Guard against the app's generic 200 fallback: require either a structured
	// object or a distinct response of comparable size to the baseline.
	if !structured && !sized {
		return "", "", false
	}

	marker, sensitive := sensitiveMarker(neighbor.body)

	if isOwnedResource(resource) {
		if marker == "" {
			marker = strings.TrimSpace(resource) + " object owned by another user"
		}

		return finding.High, marker, true
	}

	if sensitive {
		return finding.High, marker, true
	}

	return finding.Info, "", true
}

// enumerateIDs confirms the breadth of a verified IDOR by requesting identifiers
// 1..20 and summarizing how many returned distinct HTTP 200 data, a sample of
// each, and any email addresses found.
func enumerateIDs(fetch func(id int) *response) string {
	seen := map[string]bool{}
	emails := map[string]bool{}
	var samples []string
	count := 0

	for id := 1; id <= 20; id++ {
		resp := fetch(id)
		if resp == nil || resp.status != http.StatusOK || seen[resp.body] {
			continue
		}

		seen[resp.body] = true
		count++

		if len(samples) < 5 {
			samples = append(samples, "id="+strconv.Itoa(id)+": "+trim(resp.body, 300))
		}

		for _, m := range emailRe.FindAllString(resp.body, -1) {
			emails[m] = true
		}
	}

	if count == 0 {
		return ""
	}

	summary := fmt.Sprintf("enumerated %d identifiers returning distinct HTTP 200 data", count)

	if len(emails) > 0 {
		var list []string
		for email := range emails {
			list = append(list, email)
		}

		summary += "\nemails: " + strings.Join(list, ", ")
	}

	summary += "\nsamples:\n" + strings.Join(samples, "\n")

	return summary
}

// buildIDOR assembles an access-control finding for a confirmed object reference.
func buildIDOR(severity finding.Severity, title, extracted, marker string, resp *response) finding.Finding {
	f := finding.Finding{
		Title:      title,
		Module:     "access",
		Severity:   severity,
		OWASP:      "A01:2025 - Broken Access Control",
		CWE:        "CWE-639",
		Confidence: 0.7,
		Evidence: finding.Evidence{
			Request:   resp.dump,
			Response:  trim(resp.body, 400),
			Extracted: extracted,
		},
	}

	if severity == finding.High {
		f.CVSS = 7.1
		f.Description = "Under the authenticated session, changing the object identifier returned another object (" + marker + ") with HTTP 200 instead of 403/404, so the server is not enforcing object-level ownership."
		f.NextSteps = []string{
			"Confirm the returned record belongs to a different user or account.",
			"Enforce object-level authorization tied to the authenticated user on every request.",
			"Prefer unguessable identifiers and verify ownership server-side.",
		}

		return f
	}

	f.Description = "Adjacent identifier values return distinct HTTP 200 objects, so the reference is enumerable. On its own this is not an IDOR: public content (products, articles) behaves the same way. It is a vulnerability only if the objects expose data restricted to other users or accounts."
	f.NextSteps = []string{
		"Manually verify whether the returned objects contain data owned by other users/accounts (e.g. baskets, orders, profiles).",
		"If the data is private, enforce object-level authorization and prefer unguessable identifiers.",
	}

	return f
}

// idorTitle builds a finding title from the severity and the reference subject.
func idorTitle(severity finding.Severity, subject string) string {
	if severity == finding.High {
		return "Possible IDOR in " + subject
	}

	return "Enumerable object reference in " + subject
}

// resourceFromParam derives a resource label for ownership analysis from a
// parameter name and its endpoint path.
func resourceFromParam(p recon.Param) string {
	resource := p.Name
	if u, err := url.Parse(p.Endpoint); err == nil {
		resource += " " + lastPathSegment(u.Path)
	}

	return resource
}

// precedingSegment returns the path segment just before idx, the resource that
// owns the identifier (e.g. "basket" in /rest/basket/6).
func precedingSegment(segments []string, idx int) string {
	for i := idx - 1; i >= 0; i-- {
		if segments[i] != "" {
			return segments[i]
		}
	}

	return ""
}

// lastPathSegment returns the final non-empty segment of a path.
func lastPathSegment(path string) string {
	segments := strings.Split(path, "/")
	for i := len(segments) - 1; i >= 0; i-- {
		if segments[i] != "" {
			return segments[i]
		}
	}

	return ""
}

// hasNumericSegment reports whether any path segment is purely numeric.
func hasNumericSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if idRe.MatchString(segment) {
			return true
		}
	}

	return false
}

// collectionIDOR probes user-owned collection endpoints (e.g. /api/Addresss,
// /api/Cards) by requesting sequential item identifiers. When several ids return
// distinct 200 objects under the authenticated session, the server is not
// scoping the collection to the current user. This reaches item endpoints that
// an SPA never calls directly, which passive capture alone would miss.
func collectionIDOR(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	tested := map[string]bool{}

	for _, endpoint := range surface.Endpoints {
		u, err := url.Parse(endpoint)
		if err != nil || hasNumericSegment(u.Path) {
			continue
		}

		resource := lastPathSegment(u.Path)
		if !isOwnedResource(resource) {
			continue
		}

		key := u.Host + "|" + u.Path
		if tested[key] {
			continue
		}

		if len(tested) >= maxPathIDORTemplates {
			break
		}

		tested[key] = true

		if f, ok := probeCollectionItems(cfg, client, u, resource); ok {
			findings = append(findings, f)
		}
	}

	return findings
}

func probeCollectionItems(cfg *config.Config, client *http.Client, u *url.URL, resource string) (finding.Finding, bool) {
	basePath := strings.TrimRight(u.Path, "/")

	var objects []*response
	for _, id := range []string{"1", "2", "3"} {
		clone := *u
		clone.Path = basePath + "/" + id

		resp := get(cfg, client, clone.String())
		if resp == nil || resp.status != http.StatusOK || !looksStructured(resp.body) {
			continue
		}

		objects = append(objects, resp)
	}

	// Two or more sequential ids returning distinct structured objects under our
	// session means the collection is not scoped to the authenticated user.
	if len(objects) < 2 || objects[0].body == objects[len(objects)-1].body {
		return finding.Finding{}, false
	}

	other := objects[len(objects)-1]

	marker, _ := sensitiveMarker(other.body)
	if marker == "" {
		marker = resource + " objects belonging to other users"
	}

	template := basePath + "/{id}"
	extracted := basePath + "/1 .. /3 -> distinct " + resource + " objects (HTTP 200)"

	if summary := enumerateIDs(func(id int) *response {
		clone := *u
		clone.Path = basePath + "/" + strconv.Itoa(id)

		return get(cfg, client, clone.String())
	}); summary != "" {
		extracted += "\n" + summary
	}

	return buildIDOR(finding.High, idorTitle(finding.High, "path '"+template+"'"), extracted, marker, other), true
}

// sensitiveMarker reports whether a response body carries data that looks
// user- or account-bound. Its presence is what separates a genuine IDOR
// candidate from ordinary enumerable public content. It returns a short label
// describing the first marker found.
func sensitiveMarker(body string) (string, bool) {
	if emailRe.MatchString(body) {
		return "email address", true
	}

	lower := strings.ToLower(body)
	for _, kw := range sensitiveKeywords {
		if strings.Contains(lower, kw) {
			return kw, true
		}
	}

	return "", false
}

func comparableSize(a, b string) bool {
	la, lb := len(a), len(b)
	if la == 0 || lb == 0 {
		return false
	}

	ratio := float64(la) / float64(lb)

	return ratio > 0.5 && ratio < 2
}

func getParam(cfg *config.Config, client *http.Client, p recon.Param, value string) *response {
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

	return &response{
		status:      resp.StatusCode,
		body:        string(body),
		dump:        string(dump),
		contentType: resp.Header.Get("Content-Type"),
	}
}

func trim(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}

	return strings.TrimSpace(s)
}
