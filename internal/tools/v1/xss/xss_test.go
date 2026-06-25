package xss

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

func TestRunDetectsReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<html>results for %s</html>", q)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "q", Endpoint: srv.URL + "/search?q=test", Method: http.MethodGet},
		},
	}

	findings := Run(&cfg, srv.Client(), &surface)

	for _, f := range findings {
		if f.CWE == "CWE-79" && f.Severity == "HIGH" {
			return
		}
	}

	t.Errorf("expected reflected XSS finding, got %+v", findings)
}

func TestRunNoFalsePositiveWhenEncoded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		encoded := strings.ReplaceAll(q, "<", "&lt;")
		encoded = strings.ReplaceAll(encoded, ">", "&gt;")
		fmt.Fprintf(w, "<html>results for %s</html>", encoded)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "q", Endpoint: srv.URL + "/search?q=test", Method: http.MethodGet},
		},
	}

	if findings := Run(&cfg, srv.Client(), &surface); len(findings) != 0 {
		t.Errorf("expected no findings for encoded output, got %+v", findings)
	}
}

func TestRunRejectsTextareaContext(t *testing.T) {
	// The payload is reflected verbatim but inside a textarea, where markup is
	// treated as text and does not execute.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<html><body><textarea>%s</textarea></body></html>", q)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "q", Endpoint: srv.URL + "/search?q=test", Method: http.MethodGet},
		},
	}

	if findings := Run(&cfg, srv.Client(), &surface); len(findings) != 0 {
		t.Errorf("expected no findings for reflection inside a textarea, got %+v", findings)
	}
}

func TestRunDetectsStored(t *testing.T) {
	var stored string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			stored = r.FormValue("comment")
			w.WriteHeader(http.StatusOK)
			return
		}

		fmt.Fprintf(w, "<html>%s</html>", stored)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "comment", Endpoint: srv.URL + "/comments", Method: http.MethodGet},
		},
	}

	findings := Run(&cfg, srv.Client(), &surface)

	for _, f := range findings {
		if f.Severity == "CRITICAL" && strings.Contains(f.Title, "Stored XSS") {
			return
		}
	}

	t.Errorf("expected stored XSS finding, got %+v", findings)
}

func TestRunDetectsDOMSink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") {
			fmt.Fprint(w, "var x = location.hash; document.getElementById('o').innerHTML = x;")
			return
		}

		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Endpoints: []string{srv.URL + "/app.js"},
	}

	findings := Run(&cfg, srv.Client(), &surface)

	for _, f := range findings {
		if f.Severity == "INFO" && strings.Contains(f.Title, "DOM XSS") {
			return
		}
	}

	t.Errorf("expected DOM XSS finding, got %+v", findings)
}
