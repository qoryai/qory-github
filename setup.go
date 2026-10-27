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
	return webBase(web) + "/apps/" + url.PathEscape(a.Slug) + "/installations/new"
}

// Manifest is the App Setup requests from GitHub: private, with no webhook, allowed to
// read and write repository contents and pull requests and to read metadata, which is
// the most a run's token can then be granted. [ServeManifest] changes it to the App
// serve needs.
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

// WebhookPath is where serve receives the App's webhook deliveries: the App's webhook
// URL is serve's public URL, an origin, followed by this path.
const WebhookPath = "/v1/events"

// The bounds of a webhook secret serve's receiver takes, which serve's setup page keeps
// to: MinWebhookSecret is the shortest secret, in bytes, and MaxWebhookSecretFile the
// most its file may hold, the secret and a line break.
const (
	MinWebhookSecret     = 16
	MaxWebhookSecretFile = 4 << 10
)

// serveManifest changes the manifest m to the App serve needs, under serve's public
// URL publicURL: public when public is set, so any GitHub account can install it, and
// otherwise private, so GitHub lets only the account that owns the App install it, and
// Connect links only that account's installation, which a self-hosted organisation
// wants; what Connect needs, see [ConnectManifest]; a webhook, active, at
// [WebhookPath], for the events issues, issue_comment, repository, workflow_run,
// pull_request and push; and, in place of those [Manifest] sets, the permissions
// metadata read, issues write, members read, contents write, pull_requests write,
// actions write, checks write and administration read, which an installation approves
// once, when it is made. Each installation token serve mints is narrowed to its step
// all the same, see [Client.MintListingToken] and [Client.MintInstallationToken].
func serveManifest(m map[string]any, publicURL string, public bool) {
	ConnectManifest(m, publicURL)
	m["public"] = public
	m["hook_attributes"] = map[string]any{"url": publicURL + WebhookPath, "active": true}
	m["default_events"] = []string{"issues", "issue_comment", "repository", "workflow_run", "pull_request", "push"}
	m["default_permissions"] = map[string]string{
		"metadata": "read", "issues": "write", "members": "read", "contents": "write",
		"pull_requests": "write", "actions": "write", "checks": "write", "administration": "read",
	}
}

// ServeManifest is the App serve's App setup requests from GitHub: [Manifest] named
// name, with GitHub's redirect to redirect, changed to the App serve needs under its
// public URL publicURL, see [serveManifest]: public only when public is set, which the
// instance admin picks on the setup page. Without active, its webhook is inactive at
// the address [Manifest] gives a webhook, since GitHub cannot reach publicURL: GitHub
// then sends the App no deliveries until a person sets the webhook's address and turns
// it on, on the App's settings page; the API cannot turn it on. An empty name leaves
// the member name out, and GitHub's page then opens with its name field empty.
func ServeManifest(name, redirect, publicURL string, public, active bool) map[string]any {
	m := Manifest(name, redirect)
	serveManifest(m, publicURL, public)
	if !active {
		m["hook_attributes"] = Manifest(name, redirect)["hook_attributes"]
	}
	if name == "" {
		delete(m, "name")
	}
	return m
}

// ManifestAction is where the page of the manifest flow posts the manifest, on GitHub's
// website web, which [CheckWebURL] takes, with state, which GitHub's redirect returns:
// the App settings of the person signed in on GitHub, or the organisation org's when
// org is set.
func ManifestAction(web, org, state string) string {
	if org != "" {
		return webBase(web) + "/organizations/" + url.PathEscape(org) + "/settings/apps/new?state=" + state
	}
	return webBase(web) + "/settings/apps/new?state=" + state
}

// SubmitScript is the one script of the page of the manifest flow, which posts its form,
// the element f, as soon as the page loads; the form's button posts it where the script
// does not run. A page that allows scripts by their hash allows this one by its SHA-256.
const SubmitScript = `document.getElementById("f").submit()`

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
<script>` + SubmitScript + `</script>
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
	manifest, _ := json.Marshal(Manifest(s.Name, local+"/callback"))
	action := ManifestAction(web, s.Org, state)
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
// refuses, and no key file or one that exists. It creates, listens on and opens
// nothing.
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
	return nil
}

// afterApprovalTimeout is how long each call setup makes once the person has approved
// the App may take, the exchange of the code: 30 seconds, as long as the API client
// gives one request, so a slow answer fails rather than leaving setup waiting, and an
// approval near the end of the wait still leaves each call the whole of it. A test
// shortens it.
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
// identifies the App and where to generate another key. Neither contains the key. The
// exchange has [afterApprovalTimeout] within ctx.
func (s Setup) exchange(ctx context.Context, code string) (*App, error) {
	exchanging, cancel := context.WithTimeout(ctx, afterApprovalTimeout)
	defer cancel()
	got, err := s.Client.ConvertManifest(exchanging, code)
	if err != nil {
		return nil, err
	}
	app := &App{ID: got.ID, Slug: got.Slug, ClientID: got.ClientID, KeyFile: s.KeyFile}
	if _, err := ParseKey([]byte(got.PEM)); err != nil {
		return nil, fmt.Errorf("the App %d (%s) is created, but its key: %w; generate a private key at %s", got.ID, got.Slug, err, s.keysURL(got.Slug))
	}
	err = writeKeyFile(s.KeyFile, []byte(got.PEM))
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

// Conversion is the App GitHub created in the manifest flow, as GitHub's answer to the
// exchange of the redirect's code says it: its id, slug, client id, page on GitHub,
// private key in PEM, client secret and webhook secret, which is empty when GitHub
// answered null, as for an App that has none, and the account that owns it, its login
// and kind, as GitHub names them.
type Conversion struct {
	ID            int64  `json:"id"`
	Slug          string `json:"slug"`
	ClientID      string `json:"client_id"`
	HTMLURL       string `json:"html_url"`
	PEM           string `json:"pem"`
	ClientSecret  string `json:"client_secret"`
	WebhookSecret string `json:"webhook_secret"`
	Owner         struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"owner"`
}

// ConvertManifest exchanges the code of GitHub's redirect in the manifest flow for the
// App GitHub created, POST /app-manifests/{code}/conversions, within ctx, and returns it
// as GitHub's answer says it. GitHub hands the App's private key and secrets out in
// this answer alone, and the code is good once. GitHub does not redirect the exchange:
// a redirect is refused, and the code is sent nowhere else. An answer without the App's
// id or slug is refused. An error never says the code, even when GitHub's message
// quotes it.
func (c Client) ConvertManifest(ctx context.Context, code string) (Conversion, error) {
	var got Conversion
	if err := c.call(ctx, "exchanging the code for the App", http.MethodPost, "/app-manifests/"+url.PathEscape(code)+"/conversions", "", nil, http.StatusCreated, &got); err != nil {
		// GitHub does not redirect the exchange; should it, the code is not sent on.
		var answered *answerError
		if errors.As(err, &answered) && answered.redirect() {
			return Conversion{}, errors.New("exchanging the code for the App: GitHub answered with a redirect, which setup never follows, so the code is sent nowhere else")
		}
		if code != "" && strings.Contains(err.Error(), code) {
			return Conversion{}, errors.New(strings.ReplaceAll(err.Error(), code, "[the code]"))
		}
		return Conversion{}, err
	}
	if got.ID == 0 || got.Slug == "" {
		return Conversion{}, errors.New("exchanging the code for the App: GitHub answered without the App")
	}
	return got, nil
}

// webhookSecretBytes is how many random bytes a webhook secret that serve's setup page
// makes holds; it is written as their hex, 64 digits, which serve's receiver takes as it
// is.
const webhookSecretBytes = 32

// NewWebhookSecret is a new webhook secret, [webhookSecretBytes] random bytes from
// crypto/rand in hex, for an App GitHub created without one.
func NewWebhookSecret() string {
	b := make([]byte, webhookSecretBytes)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// SetAppWebhookSecret sets secret on the webhook of the App appID, PATCH
// /app/hook/config, authenticated as the App with key, within ctx. GitHub's 200 is
// enough: its body is not read. The error never contains the secret.
func (c Client) SetAppWebhookSecret(ctx context.Context, appID int64, key *rsa.PrivateKey, secret string) error {
	const what = "setting the App's webhook secret"
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	jwt, err := AppJWT(strconv.FormatInt(appID, 10), key, now())
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if err := c.call(ctx, what, http.MethodPatch, "/app/hook/config", jwt, map[string]string{"secret": secret}, http.StatusOK, nil); err != nil {
		if strings.Contains(err.Error(), secret) {
			return errors.New(strings.ReplaceAll(err.Error(), secret, "[the secret]"))
		}
		return err
	}
	return nil
}

// AppIdentity is which App GitHub answers that the App's token is, see [Client.App]:
// its numeric id, 0 when the answer names no id that is a positive integer, and its
// slug as the answer names it, empty when the answer names none as a string; whether
// the slug is one is [CheckSlug]'s to say.
type AppIdentity struct {
	ID   int64
	Slug string
}

// App asks GitHub which App the App appID is, GET /app, authenticated as the App with
// key, within ctx, and wants a 200. Any other answer is an error as every request's
// is, which [Unauthorized] tells a 401 by; a redirect is an answer like another, never
// followed. A 200 whose body is not a JSON object names neither an id nor a slug.
func (c Client) App(ctx context.Context, appID string, key *rsa.PrivateKey) (AppIdentity, error) {
	const what = "reading the App"
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	jwt, err := AppJWT(appID, key, now())
	if err != nil {
		return AppIdentity{}, fmt.Errorf("%s: %w", what, err)
	}
	var got struct {
		ID   json.RawMessage `json:"id"`
		Slug json.RawMessage `json:"slug"`
	}
	err = c.call(ctx, what, http.MethodGet, "/app", jwt, nil, http.StatusOK, &got)
	var syntax *json.SyntaxError
	var shape *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntax) || errors.As(err, &shape):
		return AppIdentity{}, nil
	case err != nil:
		return AppIdentity{}, err
	}
	var a AppIdentity
	if id, err := strconv.ParseInt(string(got.ID), 10, 64); err == nil && id > 0 {
		a.ID = id
	}
	json.Unmarshal(got.Slug, &a.Slug)
	return a, nil
}

// keysURL is the App's settings page on GitHub, where a private key is generated.
func (s Setup) keysURL(slug string) string { return AppSettingsURL(s.Web, s.Org, slug) }

// AppSettingsURL is the settings page on GitHub's website web of the App slug, where a
// private key and a client secret are generated, the webhook is set, and the App is
// deleted: an App of the person signed in on GitHub, or of the organisation org when
// org is set.
func AppSettingsURL(web, org, slug string) string {
	return AppsURL(web, org) + "/" + url.PathEscape(slug)
}

// AppsURL is the list of the Apps on GitHub's website web that the person signed in on
// GitHub owns, or the organisation org owns when org is set, each linked to its
// settings page.
func AppsURL(web, org string) string {
	if org != "" {
		return webBase(web) + "/organizations/" + url.PathEscape(org) + "/settings/apps"
	}
	return webBase(web) + "/settings/apps"
}

// IDString is the App's numeric id as a command line takes it.
func (a App) IDString() string { return strconv.FormatInt(a.ID, 10) }
