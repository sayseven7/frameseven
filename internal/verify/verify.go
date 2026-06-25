// Package verify provides generic, platform-agnostic signal verifiers used to
// suppress false positives at the source. Each verifier is a building block:
// rules call one or more verifiers and only emit a confirmed finding when the
// required signals pass.
package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Baseline captures what a host returns for a known-bogus path. It is the
// reference point for detecting catch-all / soft-404 / wildcard behavior.
type Baseline struct {
	Status      int    `json:"status,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	BodyHash    string `json:"body_hash,omitempty"`
	BodyLen     int    `json:"body_len,omitempty"`
	Title       string `json:"title,omitempty"`
}

// CalibrateBaseline issues 2-3 requests to randomly-named paths that should
// not exist on any normal server, and records the common response shape.
// If the host returns the same body shape for all bogus paths, that body
// shape is the "catch-all" baseline and any future "found file" matching
// it must be rejected as a false positive.
func CalibrateBaseline(client *http.Client, base *url.URL) (Baseline, bool) {
	paths := []string{
		"/frx7-" + randomToken(12),
		"/no-such-" + randomToken(8) + ".bogus",
		"/" + randomToken(16),
	}

	var samples []Baseline
	for _, p := range paths {
		u := *base
		u.Path = p

		resp, err := client.Get(u.String())
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		samples = append(samples, Baseline{
			Status:      resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
			BodyHash:    bodyHash(body),
			BodyLen:     len(body),
			Title:       extractTitle(body),
		})
	}

	if len(samples) < 2 {
		return Baseline{}, false
	}

	// Catch-all detected when all bogus paths return identical body hash
	// AND status is 200 (or 2xx with content)
	first := samples[0]
	for _, s := range samples[1:] {
		if s.BodyHash != first.BodyHash {
			return Baseline{}, false
		}
	}

	if first.Status >= 200 && first.Status < 300 {
		return first, true
	}

	return Baseline{}, false
}

// MatchesBaseline reports whether a response matches the catch-all baseline.
// Used to suppress "exposed file" / "endpoint reachable" findings that are
// actually the homepage being served for any path.
func MatchesBaseline(baseline Baseline, status int, contentType string, body []byte) bool {
	if baseline.BodyHash == "" {
		return false
	}

	if status != baseline.Status {
		return false
	}

	if bodyHash(body) == baseline.BodyHash {
		return true
	}

	// Soft match: same content-type, body length within 5%, same title
	if normalizeContentType(contentType) == normalizeContentType(baseline.ContentType) {
		delta := abs(len(body) - baseline.BodyLen)
		if baseline.BodyLen > 0 && float64(delta)/float64(baseline.BodyLen) < 0.05 {
			if extractTitle(body) == baseline.Title && baseline.Title != "" {
				return true
			}
		}
	}

	return false
}

// DifferentialResult is the outcome of comparing a control request and a test
// request. Without a meaningful delta, the hypothesis is not confirmed.
type DifferentialResult struct {
	HasDelta      bool
	StatusChanged bool
	LengthDelta   int
	BodyChanged   bool
	Detail        string
}

// CompareResponses computes the delta between a control and a test response.
// Used to verify IDOR (does the body actually change between different IDs?),
// boolean SQLi, and any other "varying input changes response" hypothesis.
// A response is considered "changed" only if the delta exceeds tolerance:
// >5% length change OR different status OR different body hash.
func CompareResponses(controlStatus int, controlBody []byte, testStatus int, testBody []byte) DifferentialResult {
	res := DifferentialResult{
		StatusChanged: controlStatus != testStatus,
		LengthDelta:   len(testBody) - len(controlBody),
		BodyChanged:   bodyHash(controlBody) != bodyHash(testBody),
	}

	// Tolerance: length within 2% AND same body hash = no real delta
	if !res.BodyChanged && !res.StatusChanged {
		res.Detail = "identical response"
		return res
	}

	if !res.StatusChanged && controlStatus == testStatus {
		relativeChange := 0.0
		if len(controlBody) > 0 {
			relativeChange = float64(abs(res.LengthDelta)) / float64(len(controlBody))
		}

		if relativeChange < 0.02 && !res.BodyChanged {
			res.Detail = "length delta < 2%, same hash"
			return res
		}
	}

	res.HasDelta = true
	if res.StatusChanged {
		res.Detail = "status differs"
	} else {
		res.Detail = "body differs"
	}

	return res
}

// ShapeOf reports whether a response body matches the expected format for
// a given file kind. Used to confirm sensitive file exposure: a .env that
// returns HTML is not an .env exposure, it's a catch-all hit.
//
// Supported kinds (extend as needed): "env", "git_config", "htaccess",
// "ds_store", "robots", "json", "xml", "sql_dump".
func ShapeOf(kind string, contentType string, body []byte) bool {
	s := string(body)
	ct := strings.ToLower(contentType)

	switch kind {
	case "env":
		// KEY=value lines, no HTML
		if strings.Contains(ct, "html") {
			return false
		}
		return hasKeyValueLines(s)
	case "git_config":
		return strings.Contains(s, "[core]") || strings.Contains(s, "[remote ")
	case "htaccess":
		if strings.Contains(ct, "html") {
			return false
		}
		return strings.Contains(s, "RewriteEngine") || strings.Contains(s, "Order ") || strings.Contains(s, "Allow ")
	case "ds_store":
		// Binary, starts with magic bytes 00 00 00 01 42 75 64 31
		if len(body) < 8 {
			return false
		}
		return body[0] == 0 && body[1] == 0 && body[2] == 0 && body[3] == 1 &&
			body[4] == 0x42 && body[5] == 0x75 && body[6] == 0x64 && body[7] == 0x31
	case "robots":
		return strings.Contains(s, "User-agent") || strings.Contains(s, "Disallow") || strings.Contains(s, "Allow:")
	case "json":
		if !strings.Contains(ct, "json") {
			return false
		}
		trimmed := strings.TrimSpace(s)
		return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
	case "xml":
		return strings.Contains(ct, "xml") && strings.Contains(s, "<?xml")
	case "sql_dump":
		return strings.Contains(s, "INSERT INTO") || strings.Contains(s, "CREATE TABLE")
	}

	return false
}

// IsStaticAssetParam reports whether a parameter name is part of a denylist
// of well-known non-object-reference parameters (cache busting, resize,
// versioning). IDOR/authorization checks must skip these.
func IsStaticAssetParam(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "v", "_", "t", "ts", "cb", "ver", "version",
		"width", "height", "w", "h", "dpr",
		"quality", "q", "format", "fmt",
		"sig", "signature", "hash", "etag":
		return true
	}

	return false
}

// IsStaticAssetResponse reports whether a response is a static asset
// (CSS, JS, image, font). Authorization checks on static assets are noise.
func IsStaticAssetResponse(contentType string, urlPath string) bool {
	ct := strings.ToLower(contentType)
	if strings.HasPrefix(ct, "text/css") ||
		strings.HasPrefix(ct, "application/javascript") ||
		strings.HasPrefix(ct, "text/javascript") ||
		strings.HasPrefix(ct, "image/") ||
		strings.HasPrefix(ct, "font/") ||
		strings.HasPrefix(ct, "application/font-") {
		return true
	}

	lower := strings.ToLower(urlPath)
	for _, ext := range []string{".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}

	return false
}

// --- helpers ---

func bodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func extractTitle(body []byte) string {
	s := strings.ToLower(string(body))
	start := strings.Index(s, "<title>")
	if start < 0 {
		return ""
	}

	end := strings.Index(s[start:], "</title>")
	if end < 0 {
		return ""
	}

	return strings.TrimSpace(string(body[start+7 : start+end]))
}

func normalizeContentType(ct string) string {
	parts := strings.Split(ct, ";")
	return strings.ToLower(strings.TrimSpace(parts[0]))
}

func hasKeyValueLines(s string) bool {
	lines := strings.Split(s, "\n")
	matched := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !strings.Contains(line, "=") {
			continue
		}

		key := strings.TrimSpace(strings.Split(line, "=")[0])
		if key == "" || strings.ContainsAny(key, " <>{}()") {
			continue
		}

		matched++
		if matched >= 2 {
			return true
		}
	}

	return false
}

func abs(x int) int {
	if x < 0 {
		return -x
	}

	return x
}

func randomToken(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[r.Intn(len(chars))]
	}

	return string(b)
}
