package misconfig

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
)

func TestRunFlagsMisconfigurations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect any Origin with credentials and set no security headers.
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		// Accept every method (including PUT/DELETE/TRACE) with 200.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second
	cfg.ActiveScan = true

	findings := Run(&cfg, srv.Client(), nil)

	cwes := map[string]bool{}
	for _, f := range findings {
		cwes[f.CWE] = true
	}

	if !cwes["CWE-693"] {
		t.Errorf("expected missing security headers finding (CWE-693)")
	}

	if !cwes["CWE-650"] {
		t.Errorf("expected dangerous HTTP methods finding (CWE-650)")
	}

	if !cwes["CWE-942"] {
		t.Errorf("expected permissive CORS finding (CWE-942)")
	}
}

// recordMethods runs the method check against a server that accepts every method
// and returns the HTTP methods the check actually sent.
func recordMethods(t *testing.T, activeScan bool) []string {
	t.Helper()

	var mu sync.Mutex
	var methods []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second
	cfg.ActiveScan = activeScan

	checkMethods(&cfg, srv.Client())

	return methods
}

func TestCheckMethodsDefaultSkipsStateChanging(t *testing.T) {
	for _, method := range recordMethods(t, false) {
		if method == http.MethodPut || method == http.MethodDelete {
			t.Errorf("default scan sent state-changing method %s", method)
		}
	}
}

func TestCheckMethodsActiveScanSendsStateChanging(t *testing.T) {
	var sawPut, sawDelete bool
	for _, method := range recordMethods(t, true) {
		switch method {
		case http.MethodPut:
			sawPut = true
		case http.MethodDelete:
			sawDelete = true
		}
	}

	if !sawPut || !sawDelete {
		t.Errorf("active scan did not send PUT and DELETE (put=%t delete=%t)", sawPut, sawDelete)
	}
}
