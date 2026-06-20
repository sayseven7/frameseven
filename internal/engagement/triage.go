package engagement

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// Override is a manual triage decision for one finding.
type Override struct {
	FindingID string
	Status    Status
	Reason    string
}

// TriageResult summarizes a triage pass.
type TriageResult struct {
	AutoFalsePositives int
	Confirmed          int
	FalsePositives     int
	NeedsReview        int
	Open               int
}

// Triage applies automatic false-positive heuristics (when auto is true) and
// then any manual overrides. Manual findings are never auto-flagged, and a
// manual override always wins over an automatic decision.
func (e *Engagement) Triage(auto bool, overrides []Override) (TriageResult, error) {
	if auto {
		e.autoTriage()
	}

	for _, override := range overrides {
		index := e.indexByID(override.FindingID)
		if index < 0 {
			continue
		}

		item := &e.Findings[index]

		if override.Status != "" {
			item.Status = override.Status
		}

		if override.Reason != "" {
			item.TriageReason = override.Reason
		}

		item.UpdatedAt = time.Now().UTC()
	}

	if err := e.save(); err != nil {
		return TriageResult{}, err
	}

	return e.triageResult(), nil
}

// autoTriage flags SPA catch-all false positives. A single-page app returns its
// index.html shell with HTTP 200 for unknown routes, so a scanner reports many
// "found" paths that are really the same document. When the same HTML shell body
// is returned for two or more distinct findings, those findings are marked as
// false positives. Manual findings and findings already confirmed by the
// operator are left untouched.
func (e *Engagement) autoTriage() {
	bodyCounts := map[string]int{}

	for _, item := range e.Findings {
		if !isHTMLDocument(item.Response) {
			continue
		}

		bodyCounts[bodyHash(item.Response)]++
	}

	for i := range e.Findings {
		item := &e.Findings[i]

		if item.Source == SourceManual || item.Status == StatusConfirmed {
			continue
		}

		if !isHTMLDocument(item.Response) {
			continue
		}

		if bodyCounts[bodyHash(item.Response)] < 2 {
			continue
		}

		item.Status = StatusFalsePositive
		item.TriageReason = "SPA catch-all: identical index.html shell returned for multiple distinct routes"
		item.UpdatedAt = time.Now().UTC()
	}
}

func (e *Engagement) triageResult() TriageResult {
	var result TriageResult

	for _, item := range e.Findings {
		switch item.Status {
		case StatusConfirmed:
			result.Confirmed++
		case StatusFalsePositive:
			result.FalsePositives++
			if item.Source != SourceManual {
				result.AutoFalsePositives++
			}
		case StatusNeedsReview:
			result.NeedsReview++
		}

		if item.IsOpen() {
			result.Open++
		}
	}

	return result
}

// isHTMLDocument reports whether a response body looks like a full HTML document
// (an SPA application shell) rather than an API or data response.
func isHTMLDocument(body string) bool {
	lower := strings.ToLower(body)

	return strings.Contains(lower, "<!doctype html") ||
		strings.Contains(lower, "<html") ||
		strings.Contains(lower, "<app-root") ||
		strings.Contains(lower, "<div id=\"root\"")
}

func bodyHash(body string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(body)))

	return hex.EncodeToString(sum[:])
}
