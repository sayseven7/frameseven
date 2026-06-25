package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"

	"github.com/sayseven7/frameseven/internal/engagement"
)

// rawRequest builds a raw HTTP request dump for the given absolute URL, matching
// what the scanners store as a finding's Request.
func rawRequest(t *testing.T, target string) string {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	dump, err := httputil.DumpRequestOut(req, false)
	if err != nil {
		t.Fatalf("dump request: %v", err)
	}

	return string(dump)
}

func TestFindingVerifyElevatesAndLowers(t *testing.T) {
	withEngagementDir(t)
	ctx := context.Background()

	// The server always returns a body carrying a distinctive hex marker.
	const marker = "deadbeefdeadbeefdeadbeefdeadbeef00"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("dump row: token=" + marker + " ok"))
	}))
	defer srv.Close()

	eng, err := engagement.Open(engagementsBaseDir(), srv.URL)
	if err != nil {
		t.Fatalf("engagement.Open: %v", err)
	}

	confirmID, err := eng.Add(engagement.Finding{
		Title:         "marker still present",
		Endpoint:      srv.URL + "/dump",
		Request:       rawRequest(t, srv.URL+"/dump"),
		ExtractedData: marker,
		Status:        engagement.StatusConfirmed,
		Confidence:    0.6,
	})
	if err != nil {
		t.Fatalf("add confirm finding: %v", err)
	}

	failID, err := eng.Add(engagement.Finding{
		Title:         "marker no longer present",
		Endpoint:      srv.URL + "/dump",
		Request:       rawRequest(t, srv.URL+"/dump"),
		ExtractedData: "cafebabecafebabecafebabecafebabe11",
		Response:      "a totally different stored response body",
		Status:        engagement.StatusConfirmed,
		Confidence:    0.6,
	})
	if err != nil {
		t.Fatalf("add fail finding: %v", err)
	}

	_, confirmed, err := V1FindingVerify(ctx, nil, findingVerifyInput{
		EngagementID: eng.Meta.ID,
		FindingID:    confirmID,
	})
	if err != nil {
		t.Fatalf("V1FindingVerify (confirm): %v", err)
	}

	if !confirmed.Verified {
		t.Fatalf("expected confirm finding to verify, got %+v", confirmed)
	}

	if confirmed.Status != string(engagement.StatusConfirmed) {
		t.Fatalf("expected status confirmed, got %q", confirmed.Status)
	}

	if confirmed.Confidence <= 0.6 {
		t.Fatalf("expected confidence elevated above 0.6, got %v", confirmed.Confidence)
	}

	_, failed, err := V1FindingVerify(ctx, nil, findingVerifyInput{
		EngagementID: eng.Meta.ID,
		FindingID:    failID,
	})
	if err != nil {
		t.Fatalf("V1FindingVerify (fail): %v", err)
	}

	if failed.Verified {
		t.Fatalf("expected fail finding to not verify, got %+v", failed)
	}

	if failed.Status != string(engagement.StatusNeedsReview) {
		t.Fatalf("expected status needs_review, got %q", failed.Status)
	}

	if failed.Confidence >= 0.6 {
		t.Fatalf("expected confidence lowered below 0.6, got %v", failed.Confidence)
	}
}

func TestFindingAddWithoutEvidenceNeedsReview(t *testing.T) {
	withEngagementDir(t)
	ctx := context.Background()

	_, opened, err := V1EngagementOpen(ctx, nil, engagementOpenInput{Target: "https://example.com"})
	if err != nil {
		t.Fatalf("V1EngagementOpen: %v", err)
	}

	_, added, err := V1FindingAdd(ctx, nil, findingAddInput{
		EngagementID: opened.EngagementID,
		Title:        "Hunch with no proof",
		Severity:     "HIGH",
	})
	if err != nil {
		t.Fatalf("V1FindingAdd: %v", err)
	}

	eng, err := engagement.LoadByID(engagementsBaseDir(), opened.EngagementID)
	if err != nil {
		t.Fatalf("LoadByID: %v", err)
	}

	stored, ok := eng.Find(added.FindingID)
	if !ok {
		t.Fatalf("stored finding not found")
	}

	if stored.Status != engagement.StatusNeedsReview {
		t.Fatalf("expected needs_review, got %q", stored.Status)
	}

	if stored.Confidence != engagement.DefaultConfidenceNeedsReview {
		t.Fatalf("expected confidence %v, got %v", engagement.DefaultConfidenceNeedsReview, stored.Confidence)
	}
}
