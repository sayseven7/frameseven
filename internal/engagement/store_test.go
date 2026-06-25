package engagement

import (
	"testing"

	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

func TestOpenReusesStoreForSameTarget(t *testing.T) {
	dir := t.TempDir()

	first, err := Open(dir, "https://preview.owasp-juice.shop/")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	second, err := Open(dir, "https://preview.owasp-juice.shop/")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	if first.Meta.ID != second.Meta.ID {
		t.Fatalf("expected same engagement id, got %q and %q", first.Meta.ID, second.Meta.ID)
	}

	if second.Meta.Host != "preview.owasp-juice.shop" {
		t.Fatalf("host = %q", second.Meta.Host)
	}
}

func TestAddScanFindingsDeduplicates(t *testing.T) {
	dir := t.TempDir()

	eng, err := Open(dir, "https://example.com")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	scanFindings := []finding.Finding{
		{
			Title:    "SQL injection",
			Module:   "sqli",
			Severity: finding.Medium,
			Evidence: finding.Evidence{Response: "suspicious"},
		},
	}

	if _, err := eng.AddScanFindings("sqli", scanFindings); err != nil {
		t.Fatalf("AddScanFindings: %v", err)
	}

	if _, err := eng.AddScanFindings("sqli", scanFindings); err != nil {
		t.Fatalf("AddScanFindings second: %v", err)
	}

	if len(eng.Findings) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(eng.Findings))
	}

	if eng.Findings[0].Occurrences != 2 {
		t.Fatalf("expected occurrences 2, got %d", eng.Findings[0].Occurrences)
	}

	// Reloading from disk must preserve the single deduplicated finding.
	reloaded, err := LoadByID(dir, eng.Meta.ID)
	if err != nil {
		t.Fatalf("LoadByID: %v", err)
	}

	if len(reloaded.Findings) != 1 {
		t.Fatalf("expected 1 finding after reload, got %d", len(reloaded.Findings))
	}
}

func TestAddScanFindingsReturnsIDs(t *testing.T) {
	dir := t.TempDir()

	eng, err := Open(dir, "https://example.com")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	scanFindings := []finding.Finding{
		{Title: "SQL injection", Module: "sqli", Severity: finding.Medium, Evidence: finding.Evidence{Response: "suspicious"}},
	}

	ids, err := eng.AddScanFindings("sqli", scanFindings)
	if err != nil {
		t.Fatalf("AddScanFindings: %v", err)
	}

	if len(ids) != 1 || ids[0] == "" {
		t.Fatalf("expected one non-empty id on insert, got %v", ids)
	}

	// A merged (deduplicated) finding must still return its id.
	ids, err = eng.AddScanFindings("sqli", scanFindings)
	if err != nil {
		t.Fatalf("AddScanFindings second: %v", err)
	}

	if len(ids) != 1 || ids[0] == "" {
		t.Fatalf("expected one non-empty id on merge, got %v", ids)
	}
}

func TestConfidenceDefaultsApplied(t *testing.T) {
	dir := t.TempDir()

	eng, err := Open(dir, "https://example.com")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	confirmedID, err := eng.Add(Finding{
		Title:             "Confirmed manual finding",
		Tool:              "manual",
		SeverityEffective: finding.High,
		Status:            StatusConfirmed,
	})
	if err != nil {
		t.Fatalf("Add confirmed: %v", err)
	}

	reviewID, err := eng.Add(Finding{
		Title:             "Needs review manual finding",
		Tool:              "manual",
		SeverityEffective: finding.Medium,
		Status:            StatusNeedsReview,
	})
	if err != nil {
		t.Fatalf("Add needs_review: %v", err)
	}

	newID, err := eng.Add(Finding{
		Title:             "New manual finding",
		Tool:              "manual",
		SeverityEffective: finding.Low,
		Status:            StatusNew,
	})
	if err != nil {
		t.Fatalf("Add new: %v", err)
	}

	confirmed, _ := eng.Find(confirmedID)
	if confirmed.Confidence != DefaultConfidenceConfirmed {
		t.Errorf("confirmed confidence = %v, want %v", confirmed.Confidence, DefaultConfidenceConfirmed)
	}

	review, _ := eng.Find(reviewID)
	if review.Confidence != DefaultConfidenceNeedsReview {
		t.Errorf("needs_review confidence = %v, want %v", review.Confidence, DefaultConfidenceNeedsReview)
	}

	newFinding, _ := eng.Find(newID)
	if newFinding.Confidence != 0 {
		t.Errorf("new confidence = %v, want 0", newFinding.Confidence)
	}
}

func TestManualOverrideKeepsScannerEvidenceAndRaisesSeverity(t *testing.T) {
	dir := t.TempDir()

	eng, err := Open(dir, "https://example.com")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	scannerFinding := finding.Finding{
		Title:    "SQL injection in search",
		Module:   "sqli",
		Severity: finding.Medium,
		Evidence: finding.Evidence{Response: "suspicious response, verify manually"},
	}

	ids, err := eng.AddScanFindings("sqli", []finding.Finding{scannerFinding})
	if err != nil {
		t.Fatalf("AddScanFindings: %v", err)
	}

	id := ids[0]

	err = eng.Update(id, Patch{
		Status:        StatusConfirmed,
		Severity:      finding.Critical,
		ExtractedData: "admin@juice-sh.op:0192023a7bbd73250516f069df18b500",
		TriageReason:  "UNION dump confirmed and MD5 cracked",
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	stored, ok := eng.Find(id)
	if !ok {
		t.Fatalf("finding %q not found", id)
	}

	if stored.SeverityScanner != finding.Medium {
		t.Fatalf("scanner severity changed, got %q", stored.SeverityScanner)
	}

	if stored.SeverityEffective != finding.Critical {
		t.Fatalf("effective severity = %q, want CRITICAL", stored.SeverityEffective)
	}

	if stored.Response == "" {
		t.Fatalf("original scanner evidence was lost")
	}

	if stored.ExtractedData == "" {
		t.Fatalf("extracted data was not attached")
	}
}

func TestAddManualLinksRemediationSkill(t *testing.T) {
	dir := t.TempDir()

	eng, err := Open(dir, "https://example.com")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	id, err := eng.Add(Finding{
		Title:             "Admin account takeover",
		SeverityEffective: finding.High,
		CWE:               "CWE-89",
		Status:            StatusConfirmed,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	stored, _ := eng.Find(id)
	if stored.RelatedSkill != skillURIPrefix+"sqli-sql-injection/SKILL.md" {
		t.Fatalf("related skill = %q", stored.RelatedSkill)
	}
}

func TestSetSurfacePersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()

	eng, err := Open(dir, "https://example.com")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	surface := recon.Surface{
		Host:           "example.com",
		Technologies:   []recon.Technology{{Name: "nginx", Version: "1.25", Source: "header"}},
		Endpoints:      []string{"/login"},
		Params:         []recon.Param{{Name: "id", Endpoint: "/item", Method: "GET"}},
		SensitiveFiles: []string{"/.git/config"},
	}

	if err := eng.SetSurface(surface); err != nil {
		t.Fatalf("SetSurface: %v", err)
	}

	reloaded, err := LoadByID(dir, eng.Meta.ID)
	if err != nil {
		t.Fatalf("LoadByID: %v", err)
	}

	got := reloaded.Meta.Surface

	if got.Host != "example.com" {
		t.Fatalf("host = %q", got.Host)
	}

	if len(got.Technologies) != 1 || got.Technologies[0].Name != "nginx" {
		t.Fatalf("technologies = %+v", got.Technologies)
	}

	if len(got.Endpoints) != 1 || got.Endpoints[0] != "/login" {
		t.Fatalf("endpoints = %+v", got.Endpoints)
	}

	if len(got.Params) != 1 || got.Params[0].Name != "id" {
		t.Fatalf("params = %+v", got.Params)
	}

	if len(got.SensitiveFiles) != 1 || got.SensitiveFiles[0] != "/.git/config" {
		t.Fatalf("sensitive files = %+v", got.SensitiveFiles)
	}
}

func TestSetSurfaceReplacesPreviousSurface(t *testing.T) {
	dir := t.TempDir()

	eng, err := Open(dir, "https://example.com")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := eng.SetSurface(recon.Surface{Host: "example.com", Endpoints: []string{"/old"}}); err != nil {
		t.Fatalf("first SetSurface: %v", err)
	}

	if err := eng.SetSurface(recon.Surface{Host: "example.com", Endpoints: []string{"/new"}}); err != nil {
		t.Fatalf("second SetSurface: %v", err)
	}

	if len(eng.Meta.Surface.Endpoints) != 1 || eng.Meta.Surface.Endpoints[0] != "/new" {
		t.Fatalf("expected latest surface to replace previous, got %+v", eng.Meta.Surface.Endpoints)
	}
}

func TestSetSurfaceDoesNotWipeWithEmptyScan(t *testing.T) {
	dir := t.TempDir()

	eng, err := Open(dir, "https://example.com")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// First scan ran recon and mapped the surface.
	mapped := recon.Surface{
		Host:           "example.com",
		Technologies:   []recon.Technology{{Name: "nginx", Source: "header"}},
		Endpoints:      []string{"/login"},
		Params:         []recon.Param{{Name: "id", Endpoint: "/item", Method: "GET"}},
		SensitiveFiles: []string{"/.git/config"},
	}

	if err := eng.SetSurface(mapped); err != nil {
		t.Fatalf("first SetSurface: %v", err)
	}

	// A later scan (e.g. misconfig) does not pull in recon and reports an
	// empty surface; it must not wipe the previously mapped data.
	if err := eng.SetSurface(recon.Surface{Host: "example.com"}); err != nil {
		t.Fatalf("second SetSurface: %v", err)
	}

	got := eng.Meta.Surface

	if len(got.Technologies) != 1 || len(got.Endpoints) != 1 || len(got.Params) != 1 || len(got.SensitiveFiles) != 1 {
		t.Fatalf("empty scan wiped surface: %+v", got)
	}
}
