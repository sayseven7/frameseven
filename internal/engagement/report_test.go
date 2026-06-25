package engagement

import (
	"strings"
	"testing"

	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/report"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

func TestBuildReportIncludesExtractedDataAndExcludesFalsePositives(t *testing.T) {
	dir := t.TempDir()

	eng, err := Open(dir, "https://preview.owasp-juice.shop")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Scanner-detected SQLi rated MEDIUM, later confirmed CRITICAL with a dump.
	ids, err := eng.AddScanFindings("sqli", []finding.Finding{
		{Title: "SQL injection in product search", Module: "sqli", Severity: finding.Medium, CWE: "CWE-89", Evidence: finding.Evidence{Response: "suspicious"}},
	})
	if err != nil {
		t.Fatalf("AddScanFindings: %v", err)
	}

	dump := "admin@juice-sh.op:0192023a7bbd73250516f069df18b500 (admin123)"

	err = eng.Update(ids[0], Patch{
		Status:        StatusConfirmed,
		Severity:      finding.Critical,
		ExtractedData: dump,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	// A false positive that must be excluded from the body.
	fpID, err := eng.Add(Finding{
		Title:             "Exposed admin path /admin",
		Tool:              "access",
		SeverityEffective: finding.High,
		Status:            StatusFalsePositive,
		TriageReason:      "SPA index.html shell",
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	rep := eng.BuildReport(true)

	if !rep.Confidential {
		t.Fatalf("report should be confidential when extracted data is present")
	}

	if len(rep.ExtractedData) != 1 || !strings.Contains(rep.ExtractedData[0].Data, "admin123") {
		t.Fatalf("extracted data section missing dump: %+v", rep.ExtractedData)
	}

	if len(rep.FalsePositives) != 1 || rep.FalsePositives[0].Reason == "" {
		t.Fatalf("false positive appendix missing entry: %+v", rep.FalsePositives)
	}

	for _, item := range rep.Findings {
		if item.Title == "Exposed admin path /admin" {
			t.Fatalf("false positive leaked into findings body")
		}
	}

	if len(rep.Findings) != 1 {
		t.Fatalf("expected 1 open finding, got %d", len(rep.Findings))
	}

	if rep.Findings[0].Severity != finding.Critical {
		t.Fatalf("effective severity not used, got %q", rep.Findings[0].Severity)
	}

	_ = fpID
}

func TestBuildReportRendersToAllFormats(t *testing.T) {
	dir := t.TempDir()

	eng, err := Open(dir, "https://example.com")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	_, err = eng.Add(Finding{
		Title:             "Database dump via UNION SQLi",
		Tool:              "manual",
		SeverityEffective: finding.Critical,
		CWE:               "CWE-89",
		ExtractedData:     "users table: 12 rows dumped",
		Status:            StatusConfirmed,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	rep := eng.BuildReport(false)

	text := report.RenderText(rep)
	for _, want := range []string{"CONFIDENTIAL", "sensitive data extracted", "users table: 12 rows dumped"} {
		if !strings.Contains(text, want) {
			t.Errorf("text report missing %q\n%s", want, text)
		}
	}

	markdown, err := report.RenderMarkdown(rep)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}

	if !strings.Contains(markdown, "## Sensitive Data Extracted") {
		t.Errorf("markdown missing extracted data section\n%s", markdown)
	}

	html, err := report.RenderHTML(rep)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}

	if !strings.Contains(html, "Sensitive data extracted") {
		t.Errorf("html missing extracted data section")
	}

	if !strings.Contains(html, "confidential-banner") {
		t.Errorf("html missing confidentiality banner")
	}
}

func TestBuildReport_FiltersUnverified(t *testing.T) {
	dir := t.TempDir()

	eng, err := Open(dir, "https://example.com")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Confirmed manual finding gets default confidence 0.6 and passes the gate.
	_, err = eng.Add(Finding{
		Title:             "Confirmed SQL injection",
		Tool:              "sqli",
		SeverityEffective: finding.High,
		Status:            StatusConfirmed,
	})
	if err != nil {
		t.Fatalf("Add confirmed: %v", err)
	}

	// Needs-review finding gets default confidence 0.3 and is held back.
	_, err = eng.Add(Finding{
		Title:             "Possible open redirect",
		Tool:              "redirect",
		SeverityEffective: finding.Medium,
		Status:            StatusNeedsReview,
	})
	if err != nil {
		t.Fatalf("Add needs_review: %v", err)
	}

	rep := eng.BuildReport(false)

	if len(rep.Findings) != 1 || rep.Findings[0].Title != "Confirmed SQL injection" {
		t.Fatalf("expected only the confirmed finding in body, got %+v", rep.Findings)
	}

	if len(rep.Unverified) != 1 || rep.Unverified[0].Title != "Possible open redirect" {
		t.Fatalf("expected the needs_review finding in unverified, got %+v", rep.Unverified)
	}

	full := eng.BuildReport(true)

	if len(full.Findings) != 2 {
		t.Fatalf("expected all findings in body with includeUnverified, got %d", len(full.Findings))
	}

	if len(full.Unverified) != 0 {
		t.Fatalf("expected no unverified items with includeUnverified, got %d", len(full.Unverified))
	}
}

func TestBuildReportUsesPersistedSurface(t *testing.T) {
	dir := t.TempDir()

	eng, err := Open(dir, "https://example.com")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	surface := recon.Surface{
		Host:           "example.com",
		Technologies:   []recon.Technology{{Name: "nginx", Source: "header"}},
		Endpoints:      []string{"/login"},
		Params:         []recon.Param{{Name: "id", Endpoint: "/item", Method: "GET"}},
		SensitiveFiles: []string{"/.git/config"},
	}

	if err := eng.SetSurface(surface); err != nil {
		t.Fatalf("SetSurface: %v", err)
	}

	rep := eng.BuildReport(false)

	if len(rep.Surface.Technologies) == 0 {
		t.Errorf("report surface technologies are empty")
	}

	if len(rep.Surface.Endpoints) == 0 {
		t.Errorf("report surface endpoints are empty")
	}

	if len(rep.Surface.Params) == 0 {
		t.Errorf("report surface params are empty")
	}

	if len(rep.Surface.SensitiveFiles) == 0 {
		t.Errorf("report surface sensitive files are empty")
	}
}
