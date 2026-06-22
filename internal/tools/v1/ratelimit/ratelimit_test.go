package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

func TestStats(t *testing.T) {
	latencies := []time.Duration{
		30 * time.Millisecond,
		10 * time.Millisecond,
		20 * time.Millisecond,
	}

	min, avg, max := stats(latencies)

	if min != 10*time.Millisecond {
		t.Errorf("min = %v, want 10ms", min)
	}

	if max != 30*time.Millisecond {
		t.Errorf("max = %v, want 30ms", max)
	}

	if avg != 20*time.Millisecond {
		t.Errorf("avg = %v, want 20ms", avg)
	}
}

func TestFormatStatuses(t *testing.T) {
	got := formatStatuses(map[int]int{200: 3, 404: 1})

	if got != "200=3 404=1" {
		t.Errorf("formatStatuses = %q, want \"200=3 404=1\"", got)
	}
}

func TestRunReportsMissingRateLimitOnSensitiveEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second
	cfg.RateRequests = 5

	surface := &recon.Surface{Endpoints: []string{srv.URL + "/login"}}

	findings := Run(&cfg, srv.Client(), surface)

	if len(findings) != 1 || findings[0].CWE != "CWE-770" {
		t.Fatalf("expected one missing-rate-limit finding, got %+v", findings)
	}

	if findings[0].Severity != finding.Medium {
		t.Errorf("severity = %q, want Medium for a sensitive endpoint", findings[0].Severity)
	}
}

func TestRunRootFallbackIsInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second
	cfg.RateRequests = 5

	// No sensitive endpoint in the surface, so the burst hits the root and the
	// result must be downgraded to informational rather than a Medium finding.
	findings := Run(&cfg, srv.Client(), &recon.Surface{})

	if len(findings) != 1 || findings[0].Severity != finding.Info {
		t.Fatalf("expected one informational finding, got %+v", findings)
	}
}

func TestRunSilentWhenThrottled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second
	cfg.RateRequests = 5

	if findings := Run(&cfg, srv.Client(), nil); len(findings) != 0 {
		t.Errorf("expected no finding when throttled, got %+v", findings)
	}
}
