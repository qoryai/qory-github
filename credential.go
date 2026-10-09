package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The hosts a token is for: git over HTTPS on GitHub and its REST and GraphQL API.
// GitHub Enterprise Server is not among them.
const (
	GitHost = "github.com"
	APIHost = "api.github.com"
	// APIURL is where the App's own requests go, the installation lookup and the mint.
	APIURL = "https://api.github.com"
)

// Placeholders are the variables Forager sets in the enclosure to a value that is
// no credential, so the GitHub command and the programs that read them start.
var Placeholders = []string{"GH_TOKEN", "GITHUB_TOKEN"}

// DefaultPermissions are what a run's token gets when the settings define none: it
// reads and writes the repositories' contents and their pull requests. GitHub adds
// metadata read to every token.
var DefaultPermissions = map[string]string{"contents": "write", "pull_requests": "write"}

// RunPermissions are the permissions a run's token may be granted, by GitHub's name: the
// repositories' code, their pull requests and issues, and what their checks and
// workflows do. Every other is refused, administration, secrets, environments, webhooks
// and every organisation's and member's permission among them, since each reaches past
// the repositories' code: their settings, their secrets, the organisation and its
// people. A permission is read or write, never admin.
var RunPermissions = []string{"actions", "checks", "contents", "deployments", "issues", "metadata", "pages", "pull_requests", "statuses", "workflows"}

// Repository is one repository a run works on.
type Repository struct {
	Owner, Name string
}

// String is owner/name.
func (r Repository) String() string { return r.Owner + "/" + r.Name }

var (
	ownerShape = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	nameShape  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
	appIDShape = regexp.MustCompile(`^[A-Za-z0-9.]{1,64}$`)
)

// ParseRepositories reads the argument the gateway passes, owner/name[,owner/name...].
// Every repository has the same owner, because an installation token is one account's;
// a repository listed twice, a name GitHub refuses, and a name that is a dot
// segment are refused.
func ParseRepositories(arg string) ([]Repository, error) {
	var out []Repository
	for _, part := range strings.Split(arg, ",") {
		owner, name, ok := strings.Cut(part, "/")
		if !ok || !ownerShape.MatchString(owner) || !nameShape.MatchString(name) || name == "." || name == ".." || strings.HasSuffix(name, ".git") {
			return nil, fmt.Errorf("%q is not owner/name", part)
		}
		r := Repository{Owner: owner, Name: name}
		if slices.ContainsFunc(out, func(o Repository) bool { return strings.EqualFold(o.String(), r.String()) }) {
			return nil, fmt.Errorf("the repository %s is listed twice", r)
		}
		if len(out) > 0 && !strings.EqualFold(out[0].Owner, owner) {
			return nil, fmt.Errorf("the repositories belong to %s and %s; a token is one account's, so one run's repositories share an owner", out[0].Owner, owner)
		}
		out = append(out, r)
	}
	return out, nil
}

// Answer is the credential adapter's answer, the gateway's credential.schema.json,
// version 1: the token, when it expires, and where it goes.
type Answer struct {
	Version      int      `json:"version"`
	Token        string   `json:"token"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	Apply        []Apply  `json:"apply"`
	Placeholders []string `json:"placeholders,omitempty"`
}

// Apply is one entry of an [Answer]: hosts, how the token is set on them, and the
// paths of theirs the run may request.
type Apply struct {
	Hosts    []string `json:"hosts"`
	Scheme   string   `json:"scheme"`
	Username string   `json:"username,omitempty"`
	Paths    []string `json:"paths"`
}

// Uses are where a token for the repositories goes, the same for the same repositories
// every time, since the gateway refuses an answer whose hosts, schemes or paths change
// under a run:
//
//   - github.com, with basic and the username x-access-token: /owner/name.git/* and
//     /owner/name/*, git over HTTPS with and without the suffix, which is info/refs,
//     git-upload-pack for a fetch, git-receive-pack for a push, and Git LFS's batch
//     endpoint under info/lfs;
//   - api.github.com, with bearer: /repos/owner/name and what is under it, and /graphql,
//     which has no repository in its path: the token's scope limits it to these.
func Uses(repos []Repository) []Apply {
	var git, api []string
	for _, r := range repos {
		git = append(git, "/"+r.String()+".git/*", "/"+r.String()+"/*")
		api = append(api, "/repos/"+r.String(), "/repos/"+r.String()+"/*")
	}
	api = append(api, "/graphql")
	return []Apply{
		{Hosts: []string{GitHost}, Scheme: "basic", Username: "x-access-token", Paths: git},
		{Hosts: []string{APIHost}, Scheme: "bearer", Paths: api},
	}
}

// Client is how the package reaches GitHub's API.
type Client struct {
	// API is the API's base URL, which [CheckAPIURL] takes; empty is [APIURL].
	API string
	// HTTP is the client; nil is one with a thirty-second timeout. Whichever it is, no
	// redirect is followed.
	HTTP *http.Client
	// Now is the clock the App's token is issued by; nil is time.Now.
	Now func() time.Time
}

// Request is what one token is minted for.
type Request struct {
	// AppID is the App's numeric id or its client id.
	AppID string
	// Key is the App's private key, used to sign and never sent.
	Key *rsa.PrivateKey
	// InstallationID is the App's installation on the repositories' owner, which Mint
	// checks with GitHub before it mints; zero looks it up by the repositories, which
	// must all have the same one.
	InstallationID int64
	// Repositories are what the token covers, one owner's.
	Repositories []Repository
	// Permissions are what the token may do; nil is [DefaultPermissions].
	Permissions map[string]string
}

// Mint requests from GitHub an installation token that covers the request's repositories,
// with its permissions and no more, and returns the answer the gateway reads. It refuses
// an API [CheckAPIURL] refuses before anything else, so the App's own token goes to
// GitHub's API alone. An installation the request names is minted with only once GitHub
// says it is the App's installation on the repositories' owner, so a token is never one
// of another account's. It keeps nothing: the gateway runs the adapter again before the
// token expires.
func (c Client) Mint(ctx context.Context, req Request) (*Answer, error) {
	if err := CheckAPIURL(c.base()); err != nil {
		return nil, err
	}
	if !appIDShape.MatchString(req.AppID) {
		return nil, errors.New("the App id is not an id, 1 to 64 letters, digits or dots")
	}
	if req.Key == nil {
		return nil, errors.New("no private key")
	}
	if len(req.Repositories) == 0 {
		return nil, errors.New("no repository")
	}
	perms := req.Permissions
	if perms == nil {
		perms = DefaultPermissions
	}
	if len(perms) == 0 {
		return nil, errors.New("no permission is set, which GitHub reads as every permission the installation has; set one, or leave them out for the default")
	}
	for name, level := range perms {
		if !slices.Contains(RunPermissions, name) {
			return nil, fmt.Errorf("%q is not a permission a run's token may be granted; those are %s", name, strings.Join(RunPermissions, ", "))
		}
		if level != "read" && level != "write" {
			return nil, fmt.Errorf("the permission %s is neither read nor write; a run's token reads or writes, never more", name)
		}
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	jwt, err := AppJWT(req.AppID, req.Key, now())
	if err != nil {
		return nil, err
	}
	id := req.InstallationID
	if id != 0 {
		if err := c.checkInstallation(ctx, jwt, id, req.Repositories); err != nil {
			return nil, err
		}
	}
	if id == 0 {
		for _, r := range req.Repositories {
			var got struct {
				ID int64 `json:"id"`
			}
			if err := c.call(ctx, "finding the App's installation on "+r.String(), http.MethodGet, "/repos/"+r.String()+"/installation", jwt, nil, http.StatusOK, &got); err != nil {
				return nil, moved(err)
			}
			if id != 0 && got.ID != id {
				return nil, errors.New("the repositories are in different installations of the App; a token is one installation's")
			}
			id = got.ID
		}
	}
	names := make([]string, len(req.Repositories))
	for i, r := range req.Repositories {
		names[i] = r.Name
	}
	var got struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	body := map[string]any{"repositories": names, "permissions": perms}
	const minting = "minting the installation token"
	if err := c.call(ctx, minting, http.MethodPost, "/app/installations/"+strconv.FormatInt(id, 10)+"/access_tokens", jwt, body, http.StatusCreated, &got); err != nil {
		var answered *answerError
		if errors.As(err, &answered) && answered.redirect() {
			return nil, errMintRedirected
		}
		return nil, err
	}
	if got.Token == "" {
		return nil, errors.New(minting + ": GitHub answered without a token")
	}
	expires, err := time.Parse(time.RFC3339, got.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("%s: the expiry %q is not a time", minting, got.ExpiresAt)
	}
	return &Answer{Version: 1, Token: got.Token, ExpiresAt: expires.UTC().Format(time.RFC3339), Apply: Uses(req.Repositories), Placeholders: Placeholders}, nil
}

// errNotTheOwners refuses an installation that is not the App's on the repositories'
// owner. It says neither the installation's id nor the account GitHub has it on.
var errNotTheOwners = errors.New("installation_id is not the App's installation on the repositories' owner; set that owner's installation, or leave installation_id out")

// errMoved refuses a redirect GitHub answers the lookup of a repository's installation
// with, GET /repos/{owner}/{repo}/installation, as it answers a request for a repository
// that moved or was renamed. The redirect is never followed, so the App's token goes
// nowhere but where the request was sent.
var errMoved = errors.New("GitHub answered with a redirect; the repository may have moved or been renamed, so name its new owner/name in the policy's credential argument")

// errCheckRedirected refuses a redirect GitHub answers the installation's check with,
// which names no repository, so it is not [errMoved]. It is never followed either.
var errCheckRedirected = errors.New("checking installation_id: GitHub answered with a redirect, which is never followed")

// errMintRedirected refuses a redirect GitHub answers the mint with, which names no
// repository, so it is not [errMoved]. It is never followed either, so neither the App's
// token nor the mint's body goes on.
var errMintRedirected = errors.New("minting the installation token: GitHub answered with a redirect, which is never followed")

// moved is err, or [errMoved] when err is GitHub's redirect.
func moved(err error) error {
	var answered *answerError
	if errors.As(err, &answered) && answered.redirect() {
		return errMoved
	}
	return err
}

// checkInstallation refuses the installation id unless GitHub says it is the App's
// installation on the account that owns the repositories. The account's login must be
// one GitHub gives, ASCII letters, digits and hyphens, and is compared with the owner's
// in either case of ASCII alone, as GitHub compares logins: compared as Unicode folds
// case, the Kelvin sign, U+212A, would be a k. An installation GitHub does not know of
// the App, a 404, is refused the same way, and a redirect in a line of its own.
func (c Client) checkInstallation(ctx context.Context, jwt string, id int64, repos []Repository) error {
	var got struct {
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
	}
	err := c.call(ctx, "checking installation_id", http.MethodGet, "/app/installations/"+strconv.FormatInt(id, 10), jwt, nil, http.StatusOK, &got)
	var answered *answerError
	switch {
	case errors.As(err, &answered) && answered.redirect():
		return errCheckRedirected
	case errors.As(err, &answered) && answered.status == http.StatusNotFound:
		return errNotTheOwners
	case err != nil:
		return err
	}
	if !ownerShape.MatchString(got.Account.Login) {
		return errNotTheOwners
	}
	for _, r := range repos {
		// Both are ASCII, so EqualFold folds ASCII's cases alone.
		if !ownerShape.MatchString(r.Owner) || !strings.EqualFold(got.Account.Login, r.Owner) {
			return errNotTheOwners
		}
	}
	return nil
}

// apiURLShape is the API a token is minted through: the settings schema's pattern for
// api_url itself, so the schema and [CheckAPIURL] take the same URLs.
var apiURLShape = sync.OnceValue(func() *regexp.Regexp {
	var s struct {
		Properties struct {
			APIURL struct {
				Pattern string `json:"pattern"`
			} `json:"api_url"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(Describe("").Settings, &s); err != nil {
		panic(err)
	}
	return regexp.MustCompile(s.Properties.APIURL.Pattern)
})

// CheckAPIURL takes the API the App's own token goes to, which can mint a token for
// every installation of the App: GitHub's, https://api.github.com, with or without a
// trailing slash or the port 443, and for a test http or https on a loopback host,
// 127.0.0.0/8, [::1] or localhost, with any port. Nothing else is taken: no other host,
// GitHub Enterprise Server among them, no path, user, query or fragment, and only in
// lower case. The error names the rule, never the URL.
func CheckAPIURL(api string) error {
	if !apiURLShape().MatchString(api) {
		return errors.New("the API is neither https://api.github.com nor, for a test, http or https on a loopback host; GitHub Enterprise Server is not supported")
	}
	return nil
}

// base is the API's base URL, [APIURL] when none is set.
func (c Client) base() string {
	if c.API == "" {
		return APIURL
	}
	return c.API
}

// call makes one request to the API, the one what names, such as "minting the
// installation token", and decodes the answer. It refuses an API [CheckAPIURL] refuses
// before anything is sent, so every request, a mint's and setup's, goes to GitHub's API
// alone. It follows no redirect, whatever client it is handed, so neither the App's token
// nor setup's code goes on to where one points: a redirect is an answer like another,
// whose status a caller reads. An error begins with what, and says the status and
// GitHub's message, or why the API could not be reached. It never says what was sent: no
// URL, no path, which carries the code setup exchanges and an installation's id, no
// header and no body.
func (c Client) call(ctx context.Context, what, method, path, jwt string, body any, want int, out any) error {
	base := c.base()
	if err := CheckAPIURL(base); err != nil {
		return err
	}
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(base, "/")+path, r)
	if err != nil {
		return fmt.Errorf("%s: the request could not be made: %w", what, unsent(err, path))
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "qory-github")
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := http.Client{Timeout: 30 * time.Second}
	if c.HTTP != nil {
		hc = *c.HTTP
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s: GitHub's API could not be reached: %w", what, unsent(err, path))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != want {
		var e struct {
			Message string `json:"message"`
		}
		json.Unmarshal(b, &e)
		if e.Message == "" {
			e.Message = http.StatusText(resp.StatusCode)
		}
		return &answerError{what: what, status: resp.StatusCode, message: e.Message}
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s: GitHub's answer: %w", what, err)
	}
	return nil
}

// answerError is GitHub's answer when its status is not the one a request wants: the
// request it answers, as call names it, the status, and GitHub's message.
type answerError struct {
	what    string
	status  int
	message string
}

func (e *answerError) Error() string {
	return fmt.Sprintf("%s: GitHub answered %d: %s", e.what, e.status, e.message)
}

// redirect is whether the answer is a redirect, a 3xx.
func (e *answerError) redirect() bool { return e.status >= 300 && e.status < 400 }

// errRequestLeftOut stands for an error that says the request it failed, which a
// request's error never says.
var errRequestLeftOut = errors.New("its error is left out, since it says the request")

// unsent is the error a request failed with, without the request. A *url.Error says the
// URL, and with it the path, so what it wraps is kept alone: why the API could not be
// reached, which may name its host and port, never a path. Should that say the path all
// the same, it is left out.
func unsent(err error, path string) error {
	var u *url.Error
	if errors.As(err, &u) {
		err = u.Err
	}
	if err == nil || strings.Contains(err.Error(), path) {
		return errRequestLeftOut
	}
	return err
}
