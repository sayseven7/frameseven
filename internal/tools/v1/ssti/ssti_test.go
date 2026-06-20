package ssti

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

// evalEngine simulates a Jinja2-like engine: it evaluates 7*7, 7*'7', and the
// `id` RCE payload.
func evalEngine(input string) string {
	switch {
	case strings.Contains(input, "7*'7'"):
		return "7777777"
	case strings.Contains(input, "7*7"):
		return "49"
	case strings.Contains(input, "'id'"):
		return "uid=0(root) gid=0(root)"
	default:
		return input
	}
}

func TestRunDetectsSSTIWithRCE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		fmt.Fprintf(w, "<html>Hello %s</html>", evalEngine(name))
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "name", Endpoint: srv.URL + "/greet?name=test", Method: http.MethodGet},
		},
	}

	findings := Run(&cfg, srv.Client(), &surface)

	for _, f := range findings {
		if f.CWE == "CWE-94" && f.Severity == "CRITICAL" && strings.Contains(f.Evidence.Extracted, "uid=0(root)") {
			return
		}
	}

	t.Errorf("expected SSTI RCE finding, got %+v", findings)
}

func TestRunNoFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		fmt.Fprintf(w, "<html>Hello %s</html>", name)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "name", Endpoint: srv.URL + "/greet?name=test", Method: http.MethodGet},
		},
	}

	if findings := Run(&cfg, srv.Client(), &surface); len(findings) != 0 {
		t.Errorf("expected no findings, got %+v", findings)
	}
}
