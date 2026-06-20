package authtest

import (
	"encoding/base64"
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

func TestRunDetectsDefaultCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"password":"admin"`) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"token":"abc.def.ghi"}`)
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{}

	findings := Run(&cfg, srv.Client(), &surface)

	for _, f := range findings {
		if f.CWE == "CWE-798" {
			return
		}
	}

	t.Errorf("expected default credentials finding, got %+v", findings)
}

func TestRunDetectsMissingLockout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Always 401 for wrong creds, never throttles.
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{}

	findings := Run(&cfg, srv.Client(), &surface)

	for _, f := range findings {
		if f.CWE == "CWE-307" {
			return
		}
	}

	t.Errorf("expected missing lockout finding, got %+v", findings)
}

func TestRunDetectsWeakJWT(t *testing.T) {
	token := signJWT(
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"user":"admin"}`)),
		"secret",
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "admin") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"token":"%s"}`, token)
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{}

	findings := Run(&cfg, srv.Client(), &surface)

	for _, f := range findings {
		if f.CWE == "CWE-347" && strings.Contains(f.Evidence.Extracted, "cracked secret: secret") {
			return
		}
	}

	t.Errorf("expected weak JWT finding, got %+v", findings)
}
