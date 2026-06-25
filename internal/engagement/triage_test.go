package engagement

import (
	"testing"

	"github.com/sayseven7/frameseven/internal/finding"
)

const spaIndex = `<!doctype html><html><head><title>OWASP Juice Shop</title></head><body><app-root></app-root></body></html>`

func TestAutoTriageFlagsSPAFalsePositives(t *testing.T) {
	dir := t.TempDir()

	eng, err := Open(dir, "https://preview.owasp-juice.shop")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	spaFindings := []finding.Finding{
		{Title: "Exposed admin path /admin", Module: "access", Severity: finding.High, Evidence: finding.Evidence{Response: spaIndex}},
		{Title: "Exposed file /.env", Module: "content", Severity: finding.High, Evidence: finding.Evidence{Response: spaIndex}},
		{Title: "Exposed endpoint /actuator", Module: "content", Severity: finding.Medium, Evidence: finding.Evidence{Response: spaIndex}},
	}

	realFinding := finding.Finding{
		Title:    "Open FTP directory listing /ftp",
		Module:   "access",
		Severity: finding.High,
		Evidence: finding.Evidence{Response: `{"files":["package.json.bak","coupons_2013.md.bak"]}`},
	}

	if _, err := eng.AddScanFindings("access", append(spaFindings, realFinding)); err != nil {
		t.Fatalf("AddScanFindings: %v", err)
	}

	result, err := eng.Triage(true, nil)
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}

	if result.AutoFalsePositives != 3 {
		t.Fatalf("auto false positives = %d, want 3", result.AutoFalsePositives)
	}

	for _, item := range eng.Findings {
		isSPA := item.Response == spaIndex

		if isSPA && item.Status != StatusFalsePositive {
			t.Errorf("SPA finding %q should be false positive, got %q", item.Title, item.Status)
		}

		if !isSPA && item.Status == StatusFalsePositive {
			t.Errorf("real finding %q wrongly marked false positive", item.Title)
		}
	}
}

func TestTriageOverrideBeatsAuto(t *testing.T) {
	dir := t.TempDir()

	eng, err := Open(dir, "https://example.com")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ids, err := eng.AddScanFindings("access", []finding.Finding{
		{Title: "Path /admin", Module: "access", Severity: finding.High, Evidence: finding.Evidence{Response: spaIndex}},
		{Title: "Path /metrics", Module: "access", Severity: finding.High, Evidence: finding.Evidence{Response: spaIndex}},
	})
	if err != nil {
		t.Fatalf("AddScanFindings: %v", err)
	}

	// Auto flags both as SPA false positives, but the operator confirms one.
	_, err = eng.Triage(true, []Override{
		{FindingID: ids[1], Status: StatusConfirmed, Reason: "real Prometheus metrics endpoint"},
	})
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}

	confirmed, _ := eng.Find(ids[1])
	if confirmed.Status != StatusConfirmed {
		t.Fatalf("override did not win, status = %q", confirmed.Status)
	}

	flagged, _ := eng.Find(ids[0])
	if flagged.Status != StatusFalsePositive {
		t.Fatalf("auto FP was lost, status = %q", flagged.Status)
	}
}

func TestTriageBySelector_ByTool(t *testing.T) {
	dir := t.TempDir()

	eng, err := Open(dir, "https://example.com")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if _, err := eng.AddScanFindings("access", []finding.Finding{
		{Title: "Path /admin", Module: "access", Severity: finding.High},
		{Title: "Path /metrics", Module: "access", Severity: finding.High},
		{Title: "Path /backup", Module: "access", Severity: finding.Medium},
	}); err != nil {
		t.Fatalf("AddScanFindings access: %v", err)
	}

	if _, err := eng.AddScanFindings("sqli", []finding.Finding{
		{Title: "SQL injection in search", Module: "sqli", Severity: finding.High},
	}); err != nil {
		t.Fatalf("AddScanFindings sqli: %v", err)
	}

	if _, err := eng.Triage(false, []Override{
		{ByTool: "access", Status: StatusFalsePositive, Reason: "noisy access module"},
	}); err != nil {
		t.Fatalf("Triage: %v", err)
	}

	for _, item := range eng.Findings {
		if item.Tool == "access" && item.Status != StatusFalsePositive {
			t.Errorf("access finding %q not flagged, status = %q", item.Title, item.Status)
		}

		if item.Tool == "sqli" && item.Status == StatusFalsePositive {
			t.Errorf("sqli finding %q wrongly flagged", item.Title)
		}
	}
}

func TestTriageBySelector_ByTitleRegex(t *testing.T) {
	dir := t.TempDir()

	eng, err := Open(dir, "https://example.com")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if _, err := eng.AddScanFindings("content", []finding.Finding{
		{Title: "Exposed file /backup.zip", Module: "content", Severity: finding.High},
		{Title: "Exposed file /db.sql", Module: "content", Severity: finding.High},
		{Title: "Open redirect on /go", Module: "redirect", Severity: finding.Medium},
	}); err != nil {
		t.Fatalf("AddScanFindings: %v", err)
	}

	if _, err := eng.Triage(false, []Override{
		{ByTitleRegex: "^Exposed file", Status: StatusFalsePositive, Reason: "static assets"},
	}); err != nil {
		t.Fatalf("Triage: %v", err)
	}

	flagged := 0
	for _, item := range eng.Findings {
		matches := item.Title == "Exposed file /backup.zip" || item.Title == "Exposed file /db.sql"

		if matches && item.Status != StatusFalsePositive {
			t.Errorf("finding %q should be flagged", item.Title)
		}

		if !matches && item.Status == StatusFalsePositive {
			t.Errorf("finding %q wrongly flagged", item.Title)
		}

		if item.Status == StatusFalsePositive {
			flagged++
		}
	}

	if flagged != 2 {
		t.Fatalf("expected 2 flagged findings, got %d", flagged)
	}
}
