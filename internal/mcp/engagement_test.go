package mcp

import (
	"context"
	"strings"
	"testing"
)

// withEngagementDir points the engagement store at a temporary directory for the
// duration of a test.
func withEngagementDir(t *testing.T) {
	t.Helper()
	t.Setenv("FRAMESEVEN_ENGAGEMENTS_DIR", t.TempDir())
}

func TestEngagementToolsEndToEnd(t *testing.T) {
	withEngagementDir(t)
	ctx := context.Background()

	_, opened, err := V1EngagementOpen(ctx, nil, engagementOpenInput{Target: "https://preview.owasp-juice.shop/"})
	if err != nil {
		t.Fatalf("V1EngagementOpen: %v", err)
	}

	if opened.EngagementID == "" {
		t.Fatalf("expected an engagement id")
	}

	_, added, err := V1FindingAdd(ctx, nil, findingAddInput{
		EngagementID:  opened.EngagementID,
		Title:         "UNION SQLi full Users dump",
		Severity:      "CRITICAL",
		CWE:           "CWE-89",
		Endpoint:      "/rest/products/search?q=",
		ExtractedData: "admin@juice-sh.op:0192023a7bbd73250516f069df18b500 (admin123)",
	})
	if err != nil {
		t.Fatalf("V1FindingAdd: %v", err)
	}

	if added.RelatedSkill == "" {
		t.Fatalf("expected a remediation playbook link for CWE-89")
	}

	_, report, err := V1ReportEngagement(ctx, nil, reportEngagementInput{
		EngagementID: opened.EngagementID,
		Format:       "markdown",
	})
	if err != nil {
		t.Fatalf("V1ReportEngagement: %v", err)
	}

	if !strings.Contains(report.ReportMarkdown, "Sensitive Data Extracted") {
		t.Fatalf("report missing extracted data section:\n%s", report.ReportMarkdown)
	}

	if !strings.Contains(report.ReportMarkdown, "admin123") {
		t.Fatalf("report missing the dump:\n%s", report.ReportMarkdown)
	}
}

func TestFindingUpdateOverridesSeverity(t *testing.T) {
	withEngagementDir(t)
	ctx := context.Background()

	_, opened, err := V1EngagementOpen(ctx, nil, engagementOpenInput{Target: "https://example.com"})
	if err != nil {
		t.Fatalf("V1EngagementOpen: %v", err)
	}

	_, added, err := V1FindingAdd(ctx, nil, findingAddInput{
		EngagementID: opened.EngagementID,
		Title:        "Suspicious SQL response",
		Severity:     "MEDIUM",
		Status:       "needs_review",
	})
	if err != nil {
		t.Fatalf("V1FindingAdd: %v", err)
	}

	_, updated, err := V1FindingUpdate(ctx, nil, findingUpdateInput{
		EngagementID:  opened.EngagementID,
		FindingID:     added.FindingID,
		Status:        "confirmed",
		Severity:      "CRITICAL",
		ExtractedData: "users table dumped",
	})
	if err != nil {
		t.Fatalf("V1FindingUpdate: %v", err)
	}

	if updated.SeverityEffective != "CRITICAL" {
		t.Fatalf("severity override not applied, got %q", updated.SeverityEffective)
	}

	if updated.Status != "confirmed" {
		t.Fatalf("status not applied, got %q", updated.Status)
	}
}

func TestParseSeverityRejectsUnknown(t *testing.T) {
	if _, err := parseSeverity("bogus"); err == nil {
		t.Fatalf("expected an error for an unknown severity")
	}
}

func TestParseStatusAliases(t *testing.T) {
	status, err := parseStatus("fp", "")
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}

	if status != "false_positive" {
		t.Fatalf("status = %q, want false_positive", status)
	}
}
