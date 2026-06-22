// Package ratelimit measures whether the target throttles repeated requests by
// firing a burst and observing status-code and latency variation.
package ratelimit

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"sort"
	"strings"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

// sensitiveMarkers identify endpoints where rate limiting is expected:
// authentication, account recovery/creation, and token issuance.
var sensitiveMarkers = []string{
	"login", "signin", "sign-in", "log-in", "auth", "session", "token",
	"password", "passwd", "reset", "forgot", "recover", "register",
	"signup", "sign-up", "otp", "verify", "mfa", "2fa", "oauth",
}

// Run bursts requests at a sensitive endpoint (login, password recovery, token
// issuance) discovered by recon and reports if no throttling is observed. When
// no such endpoint is known it falls back to the target root and reports the
// result as inconclusive, since a generic page is not expected to be throttled.
func Run(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	target, targeted := sensitiveTarget(cfg, surface)

	statuses := map[int]int{}
	var latencies []time.Duration
	throttled := false
	var firstDump string

	for i := 0; i < cfg.RateRequests; i++ {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			return nil
		}

		req.Header.Set("User-Agent", cfg.UserAgent)

		if firstDump == "" {
			dump, _ := httputil.DumpRequestOut(req, false)
			firstDump = string(dump)
		}

		start := time.Now()

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		latencies = append(latencies, time.Since(start))
		statuses[resp.StatusCode]++

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			throttled = true
		}

		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}

	if len(latencies) == 0 {
		return nil
	}

	if throttled {
		return nil
	}

	min, avg, max := stats(latencies)

	extracted := fmt.Sprintf(
		"endpoint: %s\nrequests: %d\nstatus distribution: %s\nlatency min/avg/max: %s / %s / %s\nno 429/503 observed",
		target, cfg.RateRequests, formatStatuses(statuses), min, avg, max,
	)

	// Only a sensitive endpoint (login, recovery, token issuance) yields a
	// confident missing-rate-limit finding. A generic root-page burst is
	// reported as informational, because such pages are not expected to throttle.
	if !targeted {
		return []finding.Finding{{
			Title:       "Rate limiting not confirmed on a sensitive endpoint",
			Module:      "ratelimit",
			Severity:    finding.Info,
			OWASP:       "A04:2025 - Insecure Design",
			CWE:         "CWE-770",
			Description: fmt.Sprintf("No authentication or recovery endpoint was discovered, so %d requests were sent to the target root. A generic page is not expected to be rate limited, so this result is inconclusive.", cfg.RateRequests),
			Evidence: finding.Evidence{
				Request:   firstDump,
				Extracted: extracted,
			},
			NextSteps: []string{
				"Re-run against a sensitive endpoint (login, password reset, token issuance).",
				"Apply per-IP / per-account rate limiting on authentication and other costly endpoints.",
			},
		}}
	}

	return []finding.Finding{{
		Title:       "Missing rate limiting",
		Module:      "ratelimit",
		Severity:    finding.Medium,
		OWASP:       "A04:2025 - Insecure Design",
		CWE:         "CWE-770",
		CVSS:        5.3,
		Description: fmt.Sprintf("Sent %d requests to %s with no throttling response, leaving the endpoint open to brute force and abuse.", cfg.RateRequests, target),
		Evidence: finding.Evidence{
			Request:   firstDump,
			Extracted: extracted,
		},
		NextSteps: []string{
			"Apply per-IP / per-account rate limiting and return 429 when exceeded.",
			"Add throttling and lockout on authentication and other costly endpoints.",
		},
	}}
}

// sensitiveTarget returns a sensitive endpoint URL discovered by recon and true,
// or the target root and false when no such endpoint is known. Surface
// endpoints are checked in order so the result is deterministic.
func sensitiveTarget(cfg *config.Config, surface *recon.Surface) (string, bool) {
	if surface == nil {
		return cfg.Target, false
	}

	for _, endpoint := range surface.Endpoints {
		if isSensitive(endpoint) {
			return endpoint, true
		}
	}

	for _, p := range surface.Params {
		if isSensitive(p.Endpoint) {
			return p.Endpoint, true
		}
	}

	return cfg.Target, false
}

func isSensitive(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	for _, marker := range sensitiveMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}

	return false
}

func stats(latencies []time.Duration) (time.Duration, time.Duration, time.Duration) {
	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	var total time.Duration
	for _, l := range latencies {
		total += l
	}

	avg := total / time.Duration(len(latencies))

	return latencies[0], avg, latencies[len(latencies)-1]
}

func formatStatuses(statuses map[int]int) string {
	codes := make([]int, 0, len(statuses))
	for code := range statuses {
		codes = append(codes, code)
	}

	sort.Ints(codes)

	var parts []string
	for _, code := range codes {
		parts = append(parts, fmt.Sprintf("%d=%d", code, statuses[code]))
	}

	return strings.Join(parts, " ")
}
