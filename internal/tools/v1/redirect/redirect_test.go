package redirect

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

func TestParamHint(t *testing.T) {
	for _, name := range []string{"redirect", "url", "next", "return", "r"} {
		if !paramHint.MatchString(name) {
			t.Errorf("expected %q to be redirect-like", name)
		}
	}

	if paramHint.MatchString("quantity") {
		t.Errorf("did not expect %q to be redirect-like", "quantity")
	}
}

func TestRunDetectsOpenRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dest := r.URL.Query().Get("next")
		http.Redirect(w, r, dest, http.StatusFound)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "next", Endpoint: srv.URL + "/go?next=/home", Method: http.MethodGet},
		},
	}

	findings := Run(&cfg, srv.Client(), &surface)

	for _, f := range findings {
		if f.CWE == "CWE-601" {
			return
		}
	}

	t.Errorf("expected open redirect finding, got %+v", findings)
}

func TestConfirmRedirectDetectsExecutableSchemes(t *testing.T) {
	tests := []struct {
		name     string
		location string
		want     bool
	}{
		{name: "javascript", location: "javascript:alert(1)", want: true},
		{name: "data", location: "data:text/html,<script>alert(1)</script>", want: true},
		{name: "vbscript", location: "vbscript:msgbox(1)", want: true},
		{name: "mixed case", location: "JaVaScRiPt:alert(1)", want: true},
		{name: "safe internal path", location: "/home", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := confirmRedirect(&response{location: tt.location}) != ""
			if got != tt.want {
				t.Fatalf("confirmRedirect() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRunNoFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always redirect to a fixed internal path regardless of input.
		http.Redirect(w, r, "/home", http.StatusFound)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "next", Endpoint: srv.URL + "/go?next=/home", Method: http.MethodGet},
		},
	}

	if findings := Run(&cfg, srv.Client(), &surface); len(findings) != 0 {
		t.Errorf("expected no findings, got %+v", findings)
	}
}
