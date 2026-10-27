package serve

import (
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	inlineShape = regexp.MustCompile(`</?(a|strong)\b[^>]*>`)
	tagShape    = regexp.MustCompile(`<[^>]*>`)
	spaceShape  = regexp.MustCompile(`\s+`)
)

// visible is the text a browser shows of the page body: its inline tags dropped, every
// other tag a space, its characters unescaped, each run of white space one space.
func visible(body string) string {
	body = tagShape.ReplaceAllString(inlineShape.ReplaceAllString(body, ""), " ")
	return strings.TrimSpace(spaceShape.ReplaceAllString(html.UnescapeString(body), " "))
}

// shows is whether the page body shows line, read as visible reads it.
func shows(body, line string) bool {
	return strings.Contains(visible(body), visible(line))
}

// refusalShown checks that rec is the refusal page of status, heading and line: HTML
// under the pages' Content-Security-Policy, with a link back to Qory Apiary at apiary.
func refusalShown(t *testing.T, rec *httptest.ResponseRecorder, status int, heading, line, apiary string) {
	t.Helper()
	body := rec.Body.String()
	if rec.Code != status || rec.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(body, `<h1 class="q-su-h1">`+html.EscapeString(heading)+`</h1>`) ||
		!shows(body, line) || !strings.Contains(body, `<a class="btn btn-md btn-primary" href="`+apiary+`">Back to Qory Apiary</a>`) {
		t.Errorf("answered %d %q, want %d %q %q", rec.Code, body, status, heading, line)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp != pageCSP("") {
		t.Errorf("the Content-Security-Policy %q", csp)
	}
}

// TestThePagesCSPAllowsOnlyTheirStylesAndFont pins the Content-Security-Policy of a page
// that loads the stylesheet: nothing but serve's styles and font, and what the page
// adds.
func TestThePagesCSPAllowsOnlyTheirStylesAndFont(t *testing.T) {
	for more, want := range map[string]string{
		"":                   "default-src 'none'; frame-ancestors 'none'; style-src 'self'; font-src 'self'",
		"form-action 'self'": "default-src 'none'; frame-ancestors 'none'; form-action 'self'; style-src 'self'; font-src 'self'",
	} {
		if got := pageCSP(more); got != want {
			t.Errorf("%q: %q, want %q", more, got, want)
		}
	}
}

// TestTheAssetsAreServedAtTheirHashedPaths serves the stylesheet and the font in the
// no-App phase and in the serving phase: each at its hashed path, of its media type,
// for every cache to keep a year; the stylesheet loads the font by its hashed name.
// Any other path under the assets is not found, and a POST is not allowed.
func TestTheAssetsAreServedAtTheirHashedPaths(t *testing.T) {
	if !regexp.MustCompile(`^/setup/assets/setup\.[0-9a-f]{16}\.css$`).MatchString(stylesAsset) ||
		!regexp.MustCompile(`^/setup/assets/Geist-Variable\.[0-9a-f]{16}\.woff2$`).MatchString(fontAsset) {
		t.Fatalf("the paths %s %s", stylesAsset, fontAsset)
	}
	rig := newSetupRig(t, true)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	for _, p := range []*phase{
		{health: healthNoApp, unavailable: unavailableNoApp, setup: rig.setup},
		{health: healthServing, setup: rig.setup, next: next},
	} {
		for path, want := range map[string]struct {
			kind string
			file string
		}{
			stylesAsset: {"text/css; charset=utf-8", "assets/setup.css"},
			fontAsset:   {"font/woff2", "assets/Geist-Variable.woff2"},
		} {
			w := httptest.NewRecorder()
			p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			body, _ := io.ReadAll(w.Body)
			if w.Code != http.StatusOK || w.Header().Get("Content-Type") != want.kind || w.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" ||
				w.Header().Get("X-Content-Type-Options") != "nosniff" || len(body) == 0 {
				t.Errorf("%s answered %d %v", path, w.Code, w.Header())
			}
			if path == fontAsset && string(body) != string(mustAsset(want.file)) {
				t.Errorf("the font is not the embedded file")
			}
			if path == stylesAsset && (!strings.Contains(string(body), `url("`+strings.TrimPrefix(fontAsset, assetsPath)+`")`) ||
				!strings.Contains(string(body), "Copied from Qory Apiary Core assets/css/app.css at 86938770.")) {
				t.Errorf("the stylesheet does not load the font by its hashed name")
			}
			w = httptest.NewRecorder()
			p.ServeHTTP(w, httptest.NewRequest(http.MethodHead, path, nil))
			if w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get("Content-Length") != strconv.Itoa(len(body)) {
				t.Errorf("HEAD %s answered %d %v", path, w.Code, w.Header())
			}
			w = httptest.NewRecorder()
			p.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, nil))
			if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" || w.Body.Len() != 0 {
				t.Errorf("POST %s answered %d %v", path, w.Code, w.Header())
			}
		}
		for _, path := range []string{"/setup/assets/setup.css", "/setup/assets/Geist-Variable.woff2", "/setup/assets/OFL.txt", "/setup/assets/", "/setup/other", stylesAsset + "x"} {
			w := httptest.NewRecorder()
			p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			if w.Code != http.StatusNotFound || w.Header().Get("Cache-Control") == "public, max-age=31536000, immutable" {
				t.Errorf("%s answered %d %v", path, w.Code, w.Header())
			}
		}
	}
}

// TestEveryPageLoadsTheStylesheet checks that a page of each kind links the
// stylesheet, has no inline style, and no image.
func TestEveryPageLoadsTheStylesheet(t *testing.T) {
	rig := newSetupRig(t, true)
	j, token := rig.begin(rig.pass())
	pages := map[string]string{
		"start":    rig.do(j, http.MethodGet, "/setup/continue", nil).Body.String(),
		"manifest": rig.do(j, http.MethodPost, "/setup/continue", url.Values{"token": {token}, "organisation": {"acme"}, "install": {installPrivate}}).Body.String(),
		"refusal":  rig.do(jar{}, http.MethodGet, "/setup/continue", nil).Body.String(),
	}
	for name, body := range pages {
		if !strings.Contains(body, `<link rel="stylesheet" href="`+stylesAsset+`">`) || strings.Contains(body, "style=") || strings.Contains(body, "<style") || strings.Contains(body, "<img") {
			t.Errorf("the %s page: %s", name, body)
		}
	}
}
