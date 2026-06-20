package cmdi

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

func TestParamHint(t *testing.T) {
	for _, name := range []string{"cmd", "host", "ip", "exec", "ping"} {
		if !paramHint.MatchString(name) {
			t.Errorf("expected %q to be command-like", name)
		}
	}

	if paramHint.MatchString("quantity") {
		t.Errorf("did not expect %q to be command-like", "quantity")
	}
}

func TestRunDetectsTimeBasedAndOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")

		if strings.Contains(host, "sleep") {
			time.Sleep(4600 * time.Millisecond)
			fmt.Fprint(w, "done")
			return
		}

		if strings.Contains(host, "id") {
			fmt.Fprint(w, "uid=0(root) gid=0(root) groups=0(root)")
			return
		}

		fmt.Fprint(w, "pong")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 15 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "host", Endpoint: srv.URL + "/ping?host=127.0.0.1", Method: http.MethodGet},
		},
	}

	findings := Run(&cfg, srv.Client(), &surface)

	for _, f := range findings {
		if f.CWE == "CWE-78" && strings.Contains(f.Evidence.Extracted, "uid=0(root)") {
			return
		}
	}

	t.Errorf("expected command injection finding with output, got %+v", findings)
}

func TestRunNoFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "pong")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "host", Endpoint: srv.URL + "/ping?host=127.0.0.1", Method: http.MethodGet},
		},
	}

	if findings := Run(&cfg, srv.Client(), &surface); len(findings) != 0 {
		t.Errorf("expected no findings, got %+v", findings)
	}
}
