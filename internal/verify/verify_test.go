package verify

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestCalibrateBaseline_DetectsCatchAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><title>Home</title><body>same page for any path</body></html>"))
	}))
	defer srv.Close()

	base, _ := url.Parse(srv.URL)

	baseline, isCatchAll := CalibrateBaseline(srv.Client(), base)
	if !isCatchAll {
		t.Fatal("expected catch-all to be detected")
	}

	if baseline.Status != http.StatusOK {
		t.Fatalf("expected baseline status 200, got %d", baseline.Status)
	}

	if baseline.BodyHash == "" {
		t.Fatal("expected baseline body hash to be set")
	}
}

func TestCalibrateBaseline_NoCatchAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	base, _ := url.Parse(srv.URL)

	_, isCatchAll := CalibrateBaseline(srv.Client(), base)
	if isCatchAll {
		t.Fatal("expected no catch-all for a real 404 server")
	}
}

func TestMatchesBaseline_IdenticalBody(t *testing.T) {
	body := []byte("<html><title>Home</title></html>")
	baseline := Baseline{
		Status:      http.StatusOK,
		ContentType: "text/html",
		BodyHash:    bodyHash(body),
		BodyLen:     len(body),
		Title:       "home",
	}

	if !MatchesBaseline(baseline, http.StatusOK, "text/html", body) {
		t.Fatal("expected identical body to match baseline")
	}
}

func TestMatchesBaseline_DifferentBody(t *testing.T) {
	baselineBody := []byte("<html><title>Home</title></html>")
	baseline := Baseline{
		Status:      http.StatusOK,
		ContentType: "text/html",
		BodyHash:    bodyHash(baselineBody),
		BodyLen:     len(baselineBody),
		Title:       "home",
	}

	other := []byte("DB_PASSWORD=secret\nAPI_KEY=abcdef\n")
	if MatchesBaseline(baseline, http.StatusOK, "text/plain", other) {
		t.Fatal("expected different body not to match baseline")
	}
}

func TestCompareResponses_IdenticalResponses(t *testing.T) {
	body := []byte("same response")

	diff := CompareResponses(http.StatusOK, body, http.StatusOK, body)
	if diff.HasDelta {
		t.Fatalf("expected no delta for identical responses, got %+v", diff)
	}
}

func TestCompareResponses_DifferentBody(t *testing.T) {
	control := []byte("user 1 profile data here")
	test := []byte("a completely different user 2 record with other data")

	diff := CompareResponses(http.StatusOK, control, http.StatusOK, test)
	if !diff.HasDelta {
		t.Fatalf("expected a delta for different bodies, got %+v", diff)
	}
}

func TestShapeOf_EnvHTMLResponse_Rejects(t *testing.T) {
	body := []byte("<html><body>KEY=value looking but it is HTML</body></html>")
	if ShapeOf("env", "text/html", body) {
		t.Fatal("expected an HTML response not to be accepted as a .env")
	}
}

func TestShapeOf_EnvProperContent_Accepts(t *testing.T) {
	body := []byte("KEY=value\nDB=secret\n")
	if !ShapeOf("env", "text/plain", body) {
		t.Fatal("expected proper KEY=value content to be accepted as a .env")
	}
}

func TestIsStaticAssetParam(t *testing.T) {
	for _, name := range []string{"v", "width", "dpr"} {
		if !IsStaticAssetParam(name) {
			t.Errorf("expected %q to be a static-asset param", name)
		}
	}

	for _, name := range []string{"id", "user_id"} {
		if IsStaticAssetParam(name) {
			t.Errorf("expected %q not to be a static-asset param", name)
		}
	}
}

func TestIsStaticAssetResponse(t *testing.T) {
	cases := []struct {
		contentType string
		path        string
		want        bool
	}{
		{"text/css", "/style", true},
		{"", "/app.js", true},
		{"image/png", "/logo", true},
		{"application/json", "/api/users/1", false},
	}

	for _, c := range cases {
		if got := IsStaticAssetResponse(c.contentType, c.path); got != c.want {
			t.Errorf("IsStaticAssetResponse(%q, %q) = %v, want %v", c.contentType, c.path, got, c.want)
		}
	}
}
