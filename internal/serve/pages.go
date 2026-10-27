package serve

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"html/template"
	"net/http"
	"strconv"
	"strings"
)

// assets are the files the set-up and Connect pages load: setup.css, which copies the
// rules of Qory Apiary Core's stylesheet that the pages use, the Geist font, and the
// font's licence, OFL.txt, which the SIL Open Font License 1.1 requires beside the
// font.
//
//go:embed assets/setup.css assets/Geist-Variable.woff2 assets/OFL.txt
var assets embed.FS

// asset is one file serve sends under [assetsPath]: its bytes and their media type.
type asset struct {
	body []byte
	kind string
}

// assetsPath is where the pages' stylesheet and font are sent, under the setup's path,
// which every phase with a setup answers.
const assetsPath = setupPath + "/assets/"

// fontAsset and stylesAsset are the font's and the stylesheet's paths, each named with
// the first 16 hex digits of the SHA-256 of its bytes, so a browser keeps each for a
// year and loads it again when its bytes change. The stylesheet refers to the font by
// its hashed name. assetFiles are both, by path.
var fontAsset, stylesAsset, assetFiles = func() (string, string, map[string]asset) {
	font := mustAsset("assets/Geist-Variable.woff2")
	fontName := "Geist-Variable." + shortHash(font) + ".woff2"
	css := strings.Replace(string(mustAsset("assets/setup.css")), `url("Geist-Variable.woff2")`, `url("`+fontName+`")`, 1)
	cssName := "setup." + shortHash([]byte(css)) + ".css"
	return assetsPath + fontName, assetsPath + cssName, map[string]asset{
		assetsPath + fontName: {body: font, kind: "font/woff2"},
		assetsPath + cssName:  {body: []byte(css), kind: "text/css; charset=utf-8"},
	}
}()

func mustAsset(name string) []byte {
	b, err := assets.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return b
}

// shortHash is the first 16 hex digits of the SHA-256 of b.
func shortHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// serveAsset answers a GET or HEAD of an asset at its hashed path, which every cache may
// keep for a year unchanged, and is false when the path is not one.
func serveAsset(w http.ResponseWriter, r *http.Request) bool {
	a, ok := assetFiles[r.URL.Path]
	if !ok {
		return false
	}
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return true
	}
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	h.Set("Content-Type", a.kind)
	h.Set("Content-Length", strconv.Itoa(len(a.body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		w.Write(a.body)
	}
	return true
}

// pageCSP is the Content-Security-Policy of a page that loads the stylesheet and the
// font from serve, with the sources more, when set, before them.
func pageCSP(more string) string {
	csp := "default-src 'none'; frame-ancestors 'none'"
	if more != "" {
		csp += "; " + more
	}
	return csp + "; style-src 'self'; font-src 'self'"
}

// pageFrame is what every page shows around its content: its title, the heading, and,
// for the setup's pages, the line Connect Qory Apiary › GitHub above the heading; Step,
// from 1 to 3, places the step indicator, and 0 leaves it out; Context is whether the
// page has a context column; Refresh, when above 0, reloads the page every Refresh
// seconds; Apiary is Qory Apiary's origin, which the logo links to. A page with the
// indicator or a context column is laid out in two columns from 1024 px, and any other
// page in one.
type pageFrame struct {
	Title, Heading string
	Where, Context bool
	Step, Refresh  int
	Apiary         string
}

// setupSteps are the names of the setup's three steps, in order.
var setupSteps = [...]string{"Start", "On GitHub", "Done"}

// stepMark is one step of the indicator: its name, and whether it is done or the
// current one; a step that is neither is to come.
type stepMark struct {
	Name          string
	Done, Current bool
}

// Marks are the indicator's steps, marked against Step.
func (f pageFrame) Marks() []stepMark {
	m := make([]stepMark, len(setupSteps))
	for i, name := range setupSteps {
		m[i] = stepMark{Name: name, Done: i+1 < f.Step, Current: i+1 == f.Step}
	}
	return m
}

// StepName is the name of the current step.
func (f pageFrame) StepName() string { return setupSteps[f.Step-1] }

// Styles is the stylesheet's path.
func (f pageFrame) Styles() string { return stylesAsset }

// pageBase is the frame every page fills in: a page's template defines main, the form
// column, and ctx, the context column, which pageFrame.Context shows.
const pageBase = `{{define "ic-check"}}<svg class="ic{{.}}" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M12.416 3.376a.75.75 0 0 1 .208 1.04l-5 7.5a.75.75 0 0 1-1.154.114l-3-3a.75.75 0 0 1 1.06-1.06l2.353 2.353 4.493-6.74a.75.75 0 0 1 1.04-.207Z"/></svg>{{end}}
{{- define "ic-error"}}<svg class="ic" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M8 15A7 7 0 1 0 8 1a7 7 0 0 0 0 14ZM8 4a.75.75 0 0 1 .75.75v3a.75.75 0 0 1-1.5 0v-3A.75.75 0 0 1 8 4Zm0 8a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z"/></svg>{{end}}
{{- define "ic-success"}}<svg class="ic" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M8 15A7 7 0 1 0 8 1a7 7 0 0 0 0 14Zm3.844-8.791a.75.75 0 0 0-1.188-.918l-3.7 4.79-1.649-1.833a.75.75 0 1 0-1.114 1.004l2.25 2.5a.75.75 0 0 0 1.15-.043l4.25-5.5Z"/></svg>{{end}}
{{- define "ic-info"}}<svg class="ic" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M15 8A7 7 0 1 1 1 8a7 7 0 0 1 14 0ZM9 5a1 1 0 1 1-2 0 1 1 0 0 1 2 0ZM6.75 8a.75.75 0 0 0 0 1.5h.75v1.75a.75.75 0 0 0 1.5 0v-2.5A.75.75 0 0 0 8.25 8h-1.5Z"/></svg>{{end}}
{{- define "ic-warning"}}<svg class="ic" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M6.701 2.25c.577-1 2.02-1 2.598 0l5.196 9a1.5 1.5 0 0 1-1.299 2.25H2.804a1.5 1.5 0 0 1-1.3-2.25l5.197-9ZM8 4a.75.75 0 0 1 .75.75v3a.75.75 0 1 1-1.5 0v-3A.75.75 0 0 1 8 4Zm0 8a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z"/></svg>{{end}}
{{- define "ctx"}}{{end}}
{{- define "page"}}<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{{if gt .Refresh 0}}<meta http-equiv="refresh" content="{{.Refresh}}">
{{end}}<title>{{.Title}}</title>
<link rel="stylesheet" href="{{.Styles}}">
</head>
<body>
<a class="btn q-skip" href="#main">Skip to content</a>
<header class="q-top">{{if .Apiary}}<a class="q-brand" href="{{.Apiary}}">{{else}}<span class="q-brand">{{end}}<svg viewBox="0 0 32 32" aria-hidden="true"><path fill="var(--color-primary)" fill-rule="evenodd" d="M16 2.2 27.95 9.1v13.8L16 29.8 4.05 22.9V9.1L16 2.2Zm0 7.6-5.37 3.1v6.2L16 22.2l5.37-3.1v-6.2L16 9.8Z"/><path fill="var(--color-base-content)" d="m17.35 17.1 2.6-1.5 6.2 10.74-2.6 1.5z"/></svg><span>Qory Apiary</span>{{if .Apiary}}</a>{{else}}</span>{{end}}<span class="q-top-side">GitHub adapter</span></header>
<main id="main" class="q-page"><div class="q-su-frame{{if or .Context (gt .Step 0)}} q-su-has-ctx{{end}}">
<div class="q-su-head">{{if .Where}}<p class="q-su-where">Connect Qory Apiary › GitHub</p>{{end}}<h1 class="q-su-h1">{{.Heading}}</h1></div>
{{if gt .Step 0}}<nav id="set-up-steps" class="q-su-steps" aria-label="Set-up steps"><div class="q-su-count"><p id="set-up-step" class="q-su-count-wide">Step {{.Step}} of 3</p><p class="q-su-count-bar">Step {{.Step}} of 3: {{.StepName}}</p><progress class="q-su-progress" value="{{.Step}}" max="3" aria-labelledby="set-up-step"></progress></div><ol class="q-su-list">
{{- range .Marks}}<li>{{if .Done}}<span class="q-su-step is-done"><span class="q-su-mark" aria-hidden="true">{{template "ic-check" " ic-sm"}}</span><span class="q-su-nm">{{.Name}}</span><span class="sr-only">, done</span></span>{{else if .Current}}<span class="q-su-step is-current" aria-current="step"><span class="q-su-mark" aria-hidden="true"></span><span class="q-su-nm">{{.Name}}</span></span>{{else}}<span class="q-su-step is-left"><span class="q-su-mark" aria-hidden="true"></span><span class="q-su-nm">{{.Name}}</span></span>{{end}}</li>{{end -}}
</ol></nav>
{{end}}<div class="q-su-form">
{{template "main" .}}
</div>
{{if .Context}}<aside id="set-up-context" class="q-context" aria-labelledby="set-up-context-h"><h2 id="set-up-context-h" class="q-context-h">About this step</h2>
{{template "ctx" .}}
</aside>
{{end}}</div></main>
</body>
</html>
{{end}}`

// pageTemplate is a page's template: the frame, [pageBase], with main and ctx as defs
// defines them.
func pageTemplate(defs string) *template.Template {
	return template.Must(template.Must(template.New("base").Parse(pageBase)).Parse(defs))
}

// writePage answers status with the page t makes of data, under the
// Content-Security-Policy csp.
func writePage(w http.ResponseWriter, status int, csp string, t *template.Template, data any) {
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	t.ExecuteTemplate(w, "page", data)
}

// refusalPageHTML is the page that refuses a request: a line, whose web address, when
// it has one, is a link, and a link back to Qory Apiary.
var refusalPageHTML = pageTemplate(`{{define "main"}}<p>{{.Before}}{{if .Link}}<a class="q-link" href="{{.Link}}">{{.Link}}</a>{{end}}{{.After}}</p>
<div class="q-su-acts"><a class="btn btn-md btn-primary" href="{{.Apiary}}">Back to Qory Apiary</a></div>{{end}}`)

// refusalView is what [refusalPageHTML] shows: the line Before, Link and After make.
type refusalView struct {
	pageFrame
	Before, Link, After string
}

// refusalPage answers the page of the refusal rf, inside frame, with rf's line, whose
// web address rf.link, when set, is a link.
func refusalPage(w http.ResponseWriter, frame pageFrame, rf refusal) {
	frame.Title = frame.Heading
	v := refusalView{pageFrame: frame, Before: rf.page}
	if before, after, ok := strings.Cut(rf.page, rf.link); ok && rf.link != "" {
		v.Before, v.Link, v.After = before, rf.link, after
	}
	writePage(w, rf.status, pageCSP(""), refusalPageHTML, v)
}
