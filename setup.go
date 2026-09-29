package github

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"
)

// WebURL is where an App is created.
const WebURL = "https://github.com"

// Setup creates a GitHub App for Qory with GitHub's manifest flow and writes its private
// key to a file. It listens on loopback for GitHub's redirect, and a person approves the
// App in the browser: nothing is created without them.
type Setup struct {
	// Org, when set, creates the App under that organisation instead of the person's
	// account.
	Org string
	// Name is the App's name, which GitHub requires to be unique; it can be changed on
	// the page before the App is created.
	Name string
	// KeyFile is where the private key is written, 0600. A file that exists is never
	// written over.
	KeyFile string
	// Web is GitHub's web URL; empty is [WebURL].
	Web string
	// Client reaches the API to exchange the redirect's code for the App.
	Client Client
	// Open receives the local page's URL to open in a browser; nil opens nothing, and
	// the caller prints the URL.
	Open func(string) error
	// Wait is how long a person has to approve; zero is ten minutes.
	Wait time.Duration
}

// App is the App [Setup] created.
type App struct {
	ID       int64
	Slug     string
	ClientID string
	// KeyFile is where its private key is: [Setup.KeyFile] or, when that could
	// not be written, a new file beside it.
	KeyFile string
	// Moved, when set, is why the key is not in [Setup.KeyFile].
	Moved error
}

// InstallURL is where a person installs the App on the repositories runs work on.
func (a App) InstallURL(web string) string {
	if web == "" {
		web = WebURL
	}
	return web + "/apps/" + url.PathEscape(a.Slug) + "/installations/new"
}

// Manifest is the App Setup requests from GitHub: private, with no webhook, allowed to
// read and write repository contents and pull requests and to read metadata, which is
// the most a run's token can then be granted.
func Manifest(name, redirect string) map[string]any {
	return map[string]any{
		"name":                name,
		"url":                 "https://github.com/qoryai/qory-github",
		"redirect_url":        redirect,
		"public":              false,
		"hook_attributes":     map[string]any{"url": "https://github.com/qoryai/qory-github", "active": false},
		"default_permissions": map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"},
		"default_events":      []string{},
	}
}

var codeShape = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

// page is the local page that posts the manifest to GitHub as the manifest flow requires.
var page = template.Must(template.New("page").Parse(`<!doctype html>
<meta charset="utf-8"><title>qory-github setup</title>
<form id="f" method="post" action="{{.Action}}">
<input type="hidden" name="manifest" value="{{.Manifest}}">
<button type="submit">Create the GitHub App</button>
</form>
<script>document.getElementById("f").submit()</script>
`))

// Start listens on loopback and returns the local page's URL and a function that waits
// for GitHub's redirect, exchanges its code for the App and writes the key. The
// listener is closed when the wait returns.
func (s Setup) Start(ctx context.Context) (string, func() (*App, error), error) {
	if s.KeyFile == "" {
		return "", nil, errors.New("no key file")
	}
	if _, err := os.Stat(s.KeyFile); err == nil {
		return "", nil, fmt.Errorf("the key file %s exists; choose another or move it away", s.KeyFile)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", nil, fmt.Errorf("the key file: %w", err)
	}
	web := s.Web
	if web == "" {
		web = WebURL
	}
	b := make([]byte, 16)
	rand.Read(b)
	state := hex.EncodeToString(b)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	local := "http://" + ln.Addr().String()
	manifest, _ := json.Marshal(Manifest(s.Name, local+"/callback"))
	action := web + "/settings/apps/new?state=" + state
	if s.Org != "" {
		action = web + "/organizations/" + url.PathEscape(s.Org) + "/settings/apps/new?state=" + state
	}
	codes := make(chan string, 1)
	host := ln.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		page.Execute(w, map[string]string{"Action": action, "Manifest": string(manifest)})
	})
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 || !codeShape.MatchString(q.Get("code")) {
			http.Error(w, "qory-github answers only GitHub's redirect containing the state it sent and a code", http.StatusBadRequest)
			return
		}
		select {
		case codes <- q.Get("code"):
			fmt.Fprintln(w, "The App is created. Return to the terminal.")
		default:
			http.Error(w, "already done", http.StatusConflict)
		}
	})
	// Only a request for the listener's own address is answered, so a page of another
	// origin that resolves a name of its own to loopback reaches nothing.
	own := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != host {
			http.Error(w, "qory-github answers its own address alone, "+host, http.StatusMisdirectedRequest)
			return
		}
		mux.ServeHTTP(w, r)
	})
	srv := &http.Server{Handler: own, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	wait := s.Wait
	if wait == 0 {
		wait = 10 * time.Minute
	}
	done := func() (*App, error) {
		defer srv.Close()
		ctx, cancel := context.WithTimeout(ctx, wait)
		defer cancel()
		select {
		case code := <-codes:
			return s.exchange(ctx, code)
		case <-ctx.Done():
			return nil, fmt.Errorf("no App was created within %s", wait)
		}
	}
	if s.Open != nil {
		if err := s.Open(local + "/"); err != nil {
			srv.Close()
			return "", nil, fmt.Errorf("opening the browser: %w", err)
		}
	}
	return local + "/", done, nil
}

// exchange turns the redirect's code into the App, and writes its key. GitHub hands the
// key out once, so it is never dropped: when [Setup.KeyFile] cannot be written, the
// key goes to a new file beside it, and when that cannot be written either, the error
// identifies the App and where to generate another key. Neither contains the key.
func (s Setup) exchange(ctx context.Context, code string) (*App, error) {
	var got struct {
		ID       int64  `json:"id"`
		Slug     string `json:"slug"`
		ClientID string `json:"client_id"`
		HTMLURL  string `json:"html_url"`
		PEM      string `json:"pem"`
	}
	if err := s.Client.call(ctx, http.MethodPost, "/app-manifests/"+code+"/conversions", "", nil, http.StatusCreated, &got); err != nil {
		return nil, fmt.Errorf("exchanging the code for the App: %w", err)
	}
	if got.ID == 0 || got.Slug == "" {
		return nil, errors.New("exchanging the code for the App: GitHub answered without the App")
	}
	app := &App{ID: got.ID, Slug: got.Slug, ClientID: got.ClientID, KeyFile: s.KeyFile}
	if _, err := ParseKey([]byte(got.PEM)); err != nil {
		return nil, fmt.Errorf("the App %d (%s) is created, but its key: %w; generate a private key at %s", got.ID, got.Slug, err, s.keysURL(got.Slug))
	}
	err := writeKeyFile(s.KeyFile, []byte(got.PEM))
	if err == nil {
		return app, nil
	}
	b := make([]byte, 8)
	rand.Read(b)
	app.KeyFile = s.KeyFile + "." + hex.EncodeToString(b)
	app.Moved = err
	if err2 := writeKeyFile(app.KeyFile, []byte(got.PEM)); err2 != nil {
		return nil, fmt.Errorf("the App %d (%s, %s) is created, but its private key could not be written: %v, and beside it: %v; generate a private key at %s", got.ID, got.Slug, got.HTMLURL, err, err2, s.keysURL(got.Slug))
	}
	return app, nil
}

// keysURL is the App's settings page on GitHub, where a private key is generated.
func (s Setup) keysURL(slug string) string {
	web := s.Web
	if web == "" {
		web = WebURL
	}
	if s.Org != "" {
		return web + "/organizations/" + url.PathEscape(s.Org) + "/settings/apps/" + url.PathEscape(slug)
	}
	return web + "/settings/apps/" + url.PathEscape(slug)
}

// IDString is the App's numeric id as a command line takes it.
func (a App) IDString() string { return strconv.FormatInt(a.ID, 10) }
