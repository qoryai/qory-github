package github

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	"strings"
	"time"
)

// WebURL is where an App is created.
const WebURL = "https://github.com"

// webURLShape is GitHub's website as [CheckWebURL] takes it: https://github.com, with
// or without a trailing slash, and for a test http or https on a loopback host, with
// any port; the loopback hosts are those [CheckAPIURL] takes.
var webURLShape = regexp.MustCompile(`^(https://github\.com|https?://(localhost|\[::1\]|127(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})(:([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?)/?$`)

// CheckWebURL takes GitHub's website, where setup sends a person to approve the App
// and the manifest goes: https://github.com, with or without a trailing slash, and for a
// test http or https on a loopback host, 127.0.0.0/8, [::1] or localhost, with any
// port. Nothing else is taken: no other host, GitHub Enterprise Server among them, no
// port on github.com, no path, user, query or fragment, and only in lower case. The
// error names the rule, never the URL.
func CheckWebURL(web string) error {
	if !webURLShape.MatchString(web) {
		return errors.New("the web URL is neither https://github.com nor, for a test, http or https on a loopback host; GitHub Enterprise Server is not supported")
	}
	return nil
}

// webBase is GitHub's website as the URLs setup builds start, [WebURL] when none is
// set, without a trailing slash.
func webBase(web string) string {
	if web == "" {
		return WebURL
	}
	return strings.TrimSuffix(web, "/")
}

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
	// Web is GitHub's web URL, which [CheckWebURL] takes; empty is [WebURL].
	Web string
	// Client reaches the API to exchange the redirect's code for the App, and setup's
	// command looks the App's account up through it, see [Client.Account].
	Client Client
	// Open receives the local page's URL to open in a browser; nil opens nothing, and
	// the caller prints the URL.
	Open func(string) error
	// Wait is how long a person has to approve; zero is ten minutes.
	Wait time.Duration
	// PublicURL, when set, is where serve is reached from outside, which
	// [CheckPublicURL] takes: the App then gets what serve needs, see [serveManifest],
	// its client secret is written to ClientSecretFile and its webhook secret to
	// WebhookSecretFile, which must both be set then. Only serve uses them, where
	// QORY_FEATURES names factory.
	PublicURL         string
	ClientSecretFile  string
	WebhookSecretFile string
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
	// ClientSecretFile is where its client secret is, when [Setup.PublicURL] is set,
	// and ClientSecretErr, when set, is why it is not kept.
	ClientSecretFile string
	ClientSecretErr  error
	// WebhookSecretFile is where its webhook secret is, when [Setup.PublicURL] is set,
	// and WebhookSecretErr, when set, is why it is not kept.
	WebhookSecretFile string
	WebhookSecretErr  error
}

// InstallURL is where a person installs the App on the repositories runs work on.
func (a App) InstallURL(web string) string {
	return webBase(web) + "/apps/" + url.PathEscape(a.Slug) + "/installations/new"
}

// Manifest is the App Setup requests from GitHub without [Setup.PublicURL]: private,
// with no webhook, allowed to read and write repository contents and pull requests and
// to read metadata, which is the most a run's token can then be granted. With it,
// [serveManifest] changes it to the public App serve needs.
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

// WebhookPath is where serve receives the App's webhook deliveries, under its public
// URL; serve's receiver listens on it.
const WebhookPath = "/github/webhook"

// The bounds of a webhook secret serve's receiver takes, which setup keeps to:
// MinWebhookSecret is the shortest secret, in bytes, and MaxWebhookSecretFile the most
// its file may hold, the secret and a line break.
const (
	MinWebhookSecret     = 16
	MaxWebhookSecretFile = 4 << 10
)

// serveManifest changes the manifest m to the App serve needs, under serve's public
// URL publicURL: public, so it can be installed on an account other than its owner's;
// what Connect needs, see [ConnectManifest]; a webhook, active, at [WebhookPath], for
// the events issues, issue_comment, workflow_run, pull_request and push; and, in place
// of those [Manifest] sets, the permissions metadata read, issues write, members read,
// contents write, pull_requests write, actions write, checks write and administration
// read, which an installation approves once, when it is made. Each installation token
// serve mints is narrowed to its step all the same, see [Client.MintListingToken] and
// [Client.MintInstallationToken].
func serveManifest(m map[string]any, publicURL string) {
	ConnectManifest(m, publicURL)
	m["public"] = true
	m["hook_attributes"] = map[string]any{"url": publicURL + WebhookPath, "active": true}
	m["default_events"] = []string{"issues", "issue_comment", "workflow_run", "pull_request", "push"}
	m["default_permissions"] = map[string]string{
		"metadata": "read", "issues": "write", "members": "read", "contents": "write",
		"pull_requests": "write", "actions": "write", "checks": "write", "administration": "read",
	}
}

// The kinds of GitHub account [Client.Account] answers, as GitHub names them.
const (
	AccountOrganization = "Organization"
	AccountUser         = "User"
)

// ErrNoAccount is [Client.Account]'s error for a handle GitHub has no organisation or
// user by.
var ErrNoAccount = errors.New("GitHub has no organisation or user by the handle")

// handleShape is a GitHub account's handle, 39 characters at most: ASCII letters and
// digits, with single hyphens between them, never first or last.
var handleShape = regexp.MustCompile(`^[A-Za-z0-9]+(-[A-Za-z0-9]+)*$`)

// Account looks the account handle up with GitHub, GET /users/{handle} without a
// token, and returns its login, as GitHub writes it, and its kind, [AccountOrganization]
// or [AccountUser]. A handle not of GitHub's shape is never sent: it, GitHub's 404, an
// account of another kind and a login that is not the handle apart from case are
// [ErrNoAccount]. Any other answer, or an API that
// cannot be reached, is an error as every other request's.
func (c Client) Account(ctx context.Context, handle string) (login, kind string, err error) {
	if len(handle) > 39 || !handleShape.MatchString(handle) {
		return "", "", ErrNoAccount
	}
	var got struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	}
	if err := c.call(ctx, "looking up the GitHub account", http.MethodGet, "/users/"+url.PathEscape(handle), "", nil, http.StatusOK, &got); err != nil {
		var answered *answerError
		if errors.As(err, &answered) && answered.status == http.StatusNotFound {
			return "", "", ErrNoAccount
		}
		return "", "", err
	}
	if got.Type != AccountOrganization && got.Type != AccountUser {
		return "", "", ErrNoAccount
	}
	// GitHub writes the login as its account has it, which may differ from the handle
	// in case alone. A login not of GitHub's shape, or that differs otherwise, is not
	// the account asked for. Both are ASCII once the shape passes, so the fold is
	// ASCII's.
	if len(got.Login) > 39 || !handleShape.MatchString(got.Login) || !strings.EqualFold(got.Login, handle) {
		return "", "", ErrNoAccount
	}
	return got.Login, got.Type, nil
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
// for GitHub's redirect, exchanges its code for the App and writes the key. The page,
// which carries the state GitHub's redirect must return, is at a random path, so a
// process on the machine that does not know the URL cannot read it: every other path but
// the redirect's is not found. The listener is closed when the wait returns. Before
// anything else it refuses a web URL [CheckWebURL] refuses and an API [CheckAPIURL]
// refuses.
func (s Setup) Start(ctx context.Context) (string, func() (*App, error), error) {
	if err := s.Check(); err != nil {
		return "", nil, err
	}
	web := webBase(s.Web)
	state := randomHex()
	pagePath := "/" + randomHex()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	local := "http://" + ln.Addr().String()
	m := Manifest(s.Name, local+"/callback")
	if s.PublicURL != "" {
		public, _ := CheckPublicURL(s.PublicURL)
		serveManifest(m, public)
	}
	manifest, _ := json.Marshal(m)
	action := web + "/settings/apps/new?state=" + state
	if s.Org != "" {
		action = web + "/organizations/" + url.PathEscape(s.Org) + "/settings/apps/new?state=" + state
	}
	codes := make(chan string, 1)
	host := ln.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+pagePath, func(w http.ResponseWriter, _ *http.Request) {
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
	// Only a request for the listener's address is answered, so a page of another
	// origin that resolves a name it controls to loopback reaches nothing.
	own := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != host {
			http.Error(w, "qory-github answers only requests to "+host, http.StatusMisdirectedRequest)
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
		approval, cancel := context.WithTimeout(ctx, wait)
		defer cancel()
		select {
		case code := <-codes:
			// The calls after the approval are bound by ctx and by
			// [afterApprovalTimeout] each, never by what is left of the wait.
			return s.exchange(ctx, code)
		case <-approval.Done():
			return nil, fmt.Errorf("no App was created within %s", wait)
		}
	}
	if s.Open != nil {
		if err := s.Open(local + pagePath); err != nil {
			srv.Close()
			return "", nil, fmt.Errorf("opening the browser: %w", err)
		}
	}
	return local + pagePath, done, nil
}

// Check refuses what [Setup.Start] refuses before it listens, so a caller refuses it
// before it asks anything: a web URL [CheckWebURL] refuses, an API [CheckAPIURL]
// refuses, no key file or one that exists, and with [Setup.PublicURL] what
// [Setup.checkConnect] refuses. It creates, listens on and opens nothing.
func (s Setup) Check() error {
	if err := CheckWebURL(cmp.Or(s.Web, WebURL)); err != nil {
		return err
	}
	if err := CheckAPIURL(s.Client.base()); err != nil {
		return err
	}
	if s.KeyFile == "" {
		return errors.New("no key file")
	}
	if _, err := os.Stat(s.KeyFile); err == nil {
		return fmt.Errorf("the key file %s exists; choose another or move it away", s.KeyFile)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("the key file: %w", err)
	}
	if s.PublicURL != "" {
		return s.checkConnect()
	}
	return nil
}

// afterApprovalTimeout is how long each call setup makes once the person has approved
// the App may take, the exchange of the code and the setting of the webhook secret:
// 30 seconds, as long as the API client gives one request, so a slow answer fails
// rather than leaving setup waiting, and an approval near the end of the wait still
// leaves each call the whole of it. A test shortens it.
var afterApprovalTimeout = 30 * time.Second

// randomHex is 16 random bytes from crypto/rand in hex, 32 digits, which no one guesses.
func randomHex() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// exchange turns the redirect's code into the App, and writes its key. GitHub hands the
// key out once, so it is never dropped: when [Setup.KeyFile] cannot be written, the
// key goes to a new file beside it, and when that cannot be written either, the error
// identifies the App and where to generate another key. Neither contains the key. With
// [Setup.PublicURL], once the key is kept, it keeps the App's client secret, then its
// webhook secret, see [Setup.keepWebhookSecret]. Each call it makes has
// [afterApprovalTimeout] within ctx.
func (s Setup) exchange(ctx context.Context, code string) (*App, error) {
	var got struct {
		ID       int64  `json:"id"`
		Slug     string `json:"slug"`
		ClientID string `json:"client_id"`
		HTMLURL  string `json:"html_url"`
		PEM      string `json:"pem"`
		// ClientSecret and WebhookSecret are read only when [Setup.PublicURL] is set;
		// GitHub answers a webhook_secret of null when the App has none.
		ClientSecret  string `json:"client_secret"`
		WebhookSecret string `json:"webhook_secret"`
	}
	exchanging, cancel := context.WithTimeout(ctx, afterApprovalTimeout)
	defer cancel()
	if err := s.Client.call(exchanging, "exchanging the code for the App", http.MethodPost, "/app-manifests/"+code+"/conversions", "", nil, http.StatusCreated, &got); err != nil {
		// GitHub does not redirect the exchange; should it, the code is not sent on.
		var answered *answerError
		if errors.As(err, &answered) && answered.redirect() {
			return nil, errors.New("exchanging the code for the App: GitHub answered with a redirect, which setup never follows, so the code is sent nowhere else")
		}
		return nil, err
	}
	if got.ID == 0 || got.Slug == "" {
		return nil, errors.New("exchanging the code for the App: GitHub answered without the App")
	}
	app := &App{ID: got.ID, Slug: got.Slug, ClientID: got.ClientID, KeyFile: s.KeyFile}
	key, err := ParseKey([]byte(got.PEM))
	if err != nil {
		return nil, fmt.Errorf("the App %d (%s) is created, but its key: %w; generate a private key at %s", got.ID, got.Slug, err, s.keysURL(got.Slug))
	}
	err = writeKeyFile(s.KeyFile, []byte(got.PEM))
	if err == nil {
		return s.keepSecrets(ctx, app, key, got.ClientSecret, got.WebhookSecret), nil
	}
	b := make([]byte, 8)
	rand.Read(b)
	app.KeyFile = s.KeyFile + "." + hex.EncodeToString(b)
	app.Moved = err
	if err2 := writeKeyFile(app.KeyFile, []byte(got.PEM)); err2 != nil {
		if s.PublicURL != "" {
			return nil, fmt.Errorf("the App %d (%s, %s) is created, but its private key could not be written: %v, and beside it: %v, so neither its client secret nor its webhook secret was kept; generate a private key and a client secret at %s, and set a webhook secret there", got.ID, got.Slug, got.HTMLURL, err, err2, s.keysURL(got.Slug))
		}
		return nil, fmt.Errorf("the App %d (%s, %s) is created, but its private key could not be written: %v, and beside it: %v; generate a private key at %s", got.ID, got.Slug, got.HTMLURL, err, err2, s.keysURL(got.Slug))
	}
	return s.keepSecrets(ctx, app, key, got.ClientSecret, got.WebhookSecret), nil
}

// keepSecrets keeps the App's client secret, then its webhook secret, when
// [Setup.PublicURL] is set, and returns app with where they are or why they are not.
func (s Setup) keepSecrets(ctx context.Context, app *App, key *rsa.PrivateKey, clientSecret, webhookSecret string) *App {
	if s.PublicURL == "" {
		return app
	}
	s.keepClientSecret(app, clientSecret)
	s.keepWebhookSecret(ctx, app, key, webhookSecret)
	return app
}

// checkConnect refuses, before anything is created, a public URL [CheckPublicURL]
// refuses, no client secret file or no webhook secret file, or one that exists.
func (s Setup) checkConnect() error {
	if _, err := CheckPublicURL(s.PublicURL); err != nil {
		return fmt.Errorf("the public URL %w", err)
	}
	if s.ClientSecretFile == "" {
		return errors.New("no client secret file")
	}
	if _, err := os.Lstat(s.ClientSecretFile); err == nil {
		return fmt.Errorf("the client secret file %s exists; choose another or move it away", s.ClientSecretFile)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("the client secret file: %w", err)
	}
	if s.WebhookSecretFile == "" {
		return errors.New("no webhook secret file")
	}
	if _, err := os.Lstat(s.WebhookSecretFile); err == nil {
		return fmt.Errorf("the webhook secret file %s exists; choose another or move it away", s.WebhookSecretFile)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("the webhook secret file: %w", err)
	}
	return nil
}

// keepClientSecret writes the App's client secret to [Setup.ClientSecretFile], 0600,
// and sets where it is on app. GitHub shows a client secret once, but a new one can be
// generated on the App's settings page: when the secret cannot be kept,
// [App.ClientSecretErr] says why and names that page, and the App is kept all the
// same, its key kept. The error never contains the secret.
func (s Setup) keepClientSecret(app *App, secret string) {
	if app.ClientID == "" || secret == "" || strings.ContainsFunc(secret, func(r rune) bool { return r <= ' ' || r >= 0x7f }) {
		app.ClientSecretErr = fmt.Errorf("the App's client secret was not kept: GitHub's answer holds no client id, or no client secret setup can keep; generate a client secret at %s", s.keysURL(app.Slug))
		return
	}
	if err := writeOwnerFile(s.ClientSecretFile, "the client secret file", []byte(secret+"\n")); err != nil {
		app.ClientSecretErr = fmt.Errorf("the App's client secret was not kept: %v; generate a client secret at %s", err, s.keysURL(app.Slug))
		return
	}
	app.ClientSecretFile = s.ClientSecretFile
}

// webhookSecretBytes is how many random bytes a webhook secret setup makes holds; it is
// written as their hex, 64 digits, which serve's receiver takes as it is.
const webhookSecretBytes = 32

// keepWebhookSecret writes the App's webhook secret to [Setup.WebhookSecretFile], 0600,
// and sets where it is on app. GitHub's answer holds the secret, or null when the App
// has none: setup then makes one, 32 random bytes from crypto/rand in hex, sets it on
// the App's webhook with PATCH /app/hook/config, authenticated as the App with key, and
// only once GitHub has confirmed it writes the file. When GitHub does not confirm it, no
// file is written: whether the App's webhook has the secret is not known, and serve
// takes none of its deliveries until a secret is set on the App and written to the
// file. A secret in GitHub's answer that serve's receiver would refuse, shorter than
// [MinWebhookSecret], too large for [MaxWebhookSecretFile] or with white space or a
// control character in it, is not kept. When the secret is not kept,
// [App.WebhookSecretErr] says why and what to do: set a secret on the App's settings
// page, write it to a file, and name that file in serve's settings, since the settings
// setup prints then lack it; the App is kept all the same, its key kept. The error
// never contains the secret.
func (s Setup) keepWebhookSecret(ctx context.Context, app *App, key *rsa.PrivateKey, secret string) {
	switch {
	case secret == "":
		b := make([]byte, webhookSecretBytes)
		rand.Read(b)
		secret = hex.EncodeToString(b)
		if err := s.setWebhookSecret(ctx, app.ID, key, secret); err != nil {
			app.WebhookSecretErr = fmt.Errorf("GitHub did not confirm the App's webhook secret, so no webhook secret file is written: %v; set a webhook secret at %s, write the same secret to %s, 0600, and name that file as webhook_secret_file in qory-github-server serve's settings: until then serve takes none of the App's deliveries", err, s.keysURL(app.Slug), s.WebhookSecretFile)
			return
		}
	case len(secret) < MinWebhookSecret || len(secret)+1 > MaxWebhookSecretFile || strings.ContainsFunc(secret, func(r rune) bool { return r <= ' ' || r >= 0x7f }):
		app.WebhookSecretErr = fmt.Errorf("the App's webhook secret was not kept: GitHub's answer holds a webhook secret qory-github-server serve cannot use; set a webhook secret at %s, write the same secret to %s, 0600, and name that file as webhook_secret_file in qory-github-server serve's settings", s.keysURL(app.Slug), s.WebhookSecretFile)
		return
	}
	if err := writeOwnerFile(s.WebhookSecretFile, "the webhook secret file", []byte(secret+"\n")); err != nil {
		app.WebhookSecretErr = fmt.Errorf("the App's webhook secret was not kept: %v; set a new webhook secret at %s, write the same secret to a file only you may read, and name that file as webhook_secret_file in qory-github-server serve's settings", err, s.keysURL(app.Slug))
		return
	}
	app.WebhookSecretFile = s.WebhookSecretFile
}

// setWebhookSecret sets secret on the App's webhook, PATCH /app/hook/config,
// authenticated as the App appID with key, within [afterApprovalTimeout]. GitHub's 200
// is enough: its body is not read. The error never contains the secret.
func (s Setup) setWebhookSecret(ctx context.Context, appID int64, key *rsa.PrivateKey, secret string) error {
	const what = "setting the App's webhook secret"
	now := time.Now
	if s.Client.Now != nil {
		now = s.Client.Now
	}
	jwt, err := AppJWT(strconv.FormatInt(appID, 10), key, now())
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	ctx, cancel := context.WithTimeout(ctx, afterApprovalTimeout)
	defer cancel()
	if err := s.Client.call(ctx, what, http.MethodPatch, "/app/hook/config", jwt, map[string]string{"secret": secret}, http.StatusOK, nil); err != nil {
		if strings.Contains(err.Error(), secret) {
			return errors.New(strings.ReplaceAll(err.Error(), secret, "[the secret]"))
		}
		return err
	}
	return nil
}

// keysURL is the App's settings page on GitHub, where a private key is generated.
func (s Setup) keysURL(slug string) string {
	web := webBase(s.Web)
	if s.Org != "" {
		return web + "/organizations/" + url.PathEscape(s.Org) + "/settings/apps/" + url.PathEscape(slug)
	}
	return web + "/settings/apps/" + url.PathEscape(slug)
}

// IDString is the App's numeric id as a command line takes it.
func (a App) IDString() string { return strconv.FormatInt(a.ID, 10) }
