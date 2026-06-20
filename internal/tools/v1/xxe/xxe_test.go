package xxe

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

func TestRunDetectsFileRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "file:///etc/passwd") {
			fmt.Fprint(w, "<root><data>root:x:0:0:root:/root:/bin/bash</data></root>")
			return
		}

		fmt.Fprint(w, "<root><data></data></root>")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{}

	findings := Run(&cfg, srv.Client(), &surface)

	for _, f := range findings {
		if f.CWE == "CWE-611" {
			return
		}
	}

	t.Errorf("expected XXE file read finding, got %+v", findings)
}

func TestRunDetectsInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "frx7injected") {
			fmt.Fprint(w, "<root><data></tag><injected>frx7injected</injected></data></root>")
			return
		}

		fmt.Fprint(w, "<root></root>")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{}

	findings := Run(&cfg, srv.Client(), &surface)

	for _, f := range findings {
		if f.CWE == "CWE-91" {
			return
		}
	}

	t.Errorf("expected XML injection finding, got %+v", findings)
}

func TestRunNoFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<root><data>ok</data></root>")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{}

	if findings := Run(&cfg, srv.Client(), &surface); len(findings) != 0 {
		t.Errorf("expected no findings, got %+v", findings)
	}
}
