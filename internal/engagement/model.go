// Package engagement keeps a persistent record of every finding gathered during
// an assessment: scanner output plus manual work (dumps, cracked credentials,
// exfiltrated files). It deduplicates, triages false positives, and feeds the
// consolidated, triaged result into the report renderers so that manual findings
// and extracted data always make it into the final report.
package engagement

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/sayseven7/frameseven/internal/finding"
)

// Source records whether a finding came from an automated scanner tool or from
// manual operator work.
type Source string

const (
	SourceScanner Source = "scanner"
	SourceManual  Source = "manual"
)

// Status is the triage state of a finding.
type Status string

const (
	StatusNew           Status = "new"
	StatusConfirmed     Status = "confirmed"
	StatusFalsePositive Status = "false_positive"
	StatusNeedsReview   Status = "needs_review"
)

// Meta is the engagement header persisted in meta.json.
type Meta struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Host      string    `json:"host"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Finding is a single issue tracked in the engagement store. It is richer than
// a scanner finding.Finding because it also carries manual proof, extracted
// data, triage state, and the linked remediation playbook.
type Finding struct {
	ID           string `json:"id"`
	EngagementID string `json:"engagement_id"`

	Source Source `json:"source"`
	Tool   string `json:"tool"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Title       string `json:"title"`
	Description string `json:"description"`

	// SeverityScanner is the severity the scanner assigned. SeverityEffective
	// is the severity used by the report; a manual override sets it without
	// losing the original scanner value.
	SeverityScanner   finding.Severity `json:"severity_scanner,omitempty"`
	SeverityEffective finding.Severity `json:"severity_effective"`

	CVSS  float64 `json:"cvss,omitempty"`
	CWE   string  `json:"cwe,omitempty"`
	OWASP string  `json:"owasp,omitempty"`

	Endpoint string `json:"endpoint,omitempty"`
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`

	PoC      string `json:"poc,omitempty"`
	Evidence string `json:"evidence,omitempty"`

	// ExtractedData holds dumps, cracked credentials, or exfiltrated file
	// contents. It is a first-class field so the report can always surface it.
	ExtractedData string `json:"extracted_data,omitempty"`

	Status       Status `json:"status"`
	TriageReason string `json:"triage_reason,omitempty"`

	RelatedSkill string `json:"related_skill,omitempty"`

	References  []string `json:"references,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Occurrences int      `json:"occurrences"`
}

// signature is the dedupe key for a finding: same tool, title, endpoint, and
// evidence collapse onto one stored finding instead of duplicating.
func (f Finding) signature() string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(f.Tool)),
		strings.ToLower(strings.TrimSpace(f.Title)),
		strings.ToLower(strings.TrimSpace(f.Endpoint)),
		strings.TrimSpace(f.Evidence),
	}

	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))

	return hex.EncodeToString(sum[:])
}

// IsOpen reports whether a finding should appear in the main report body. False
// positives are excluded; everything else (new, confirmed, needs_review) is kept.
func (f Finding) IsOpen() bool {
	return f.Status != StatusFalsePositive
}
