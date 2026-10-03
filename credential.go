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

// Placeholders are the variables the runner sets in the enclosure to a value that is
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

// ParseRepositories reads the argument the runner passes, owner/name[,owner/name...].
// Every repository has the same owner, because an installation token is one account's;
// an empty argument, a repository listed twice, a name GitHub refuses, and a name that
// is a dot segment are refused.
func ParseRepositories(arg string) ([]Repository, error) {
	if arg == "" {
		return nil, errors.New("the argument is empty; want owner/name[,owner/name...]")
	}
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

// Answer is the credential adapter's answer, the runner's credential.schema.json,
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
// every time, since the runner refuses an answer whose hosts, schemes or paths change
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
	// API is the API's base URL; empty is [APIURL].
	API string
	// HTTP is the client; nil is one with a thirty-second timeout.
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
	// InstallationID is the App's installation on the repositories' owner; zero looks
	// it up by the repositories, which must all have the same one.
	InstallationID int64
	// Repositories are what the token covers, one owner's.
	Repositories []Repository
	// Permissions are what the token may do; nil is [DefaultPermissions].
	Permissions map[string]string
}

// Mint requests from GitHub an installation token that covers the request's repositories,
// with its permissions and no more, and returns the answer the runner reads. It keeps
// nothing: the runner runs the adapter again before the token expires.
func (c Client) Mint(ctx context.Context, req Request) (*Answer, error) {
	if !appIDShape.MatchString(req.AppID) {
		return nil, fmt.Errorf("the App id %q is not an id", req.AppID)
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
			return nil, fmt.Errorf("the permission %s is %q; a run's token reads or writes, never more", name, level)
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
	if id == 0 {
		for _, r := range req.Repositories {
			var got struct {
				ID int64 `json:"id"`
			}
			if err := c.call(ctx, http.MethodGet, "/repos/"+r.String()+"/installation", jwt, nil, http.StatusOK, &got); err != nil {
				return nil, fmt.Errorf("the App's installation on %s: %w", r, err)
			}
			if id != 0 && got.ID != id {
				return nil, fmt.Errorf("the repositories are in different installations of the App, %d and %d", id, got.ID)
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
	if err := c.call(ctx, http.MethodPost, "/app/installations/"+strconv.FormatInt(id, 10)+"/access_tokens", jwt, body, http.StatusCreated, &got); err != nil {
		return nil, fmt.Errorf("the installation token: %w", err)
	}
	if got.Token == "" {
		return nil, errors.New("the installation token: GitHub answered without a token")
	}
	expires, err := time.Parse(time.RFC3339, got.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("the installation token: the expiry %q is not a time", got.ExpiresAt)
	}
	return &Answer{Version: 1, Token: got.Token, ExpiresAt: expires.UTC().Format(time.RFC3339), Apply: Uses(req.Repositories), Placeholders: Placeholders}, nil
}

// CheckAPIURL takes the API the App's token goes to when it is https, and when it is
// http to loopback alone, 127.0.0.1, ::1 or localhost, for a test, since over http the
// token crosses the network in the clear. A URL with a user in it is refused.
func CheckAPIURL(api string) error {
	u, err := url.Parse(api)
	if err != nil || u.Host == "" || u.User != nil {
		return fmt.Errorf("the API %q is not a URL of a host", api)
	}
	switch h := u.Hostname(); {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && (h == "127.0.0.1" || h == "::1" || h == "localhost"):
		return nil
	}
	return fmt.Errorf("the API %s is not https; http is for loopback alone, since over http the token crosses the network in the clear", api)
}

// call makes one request to the API as the App and decodes the answer. It refuses an
// API [CheckAPIURL] refuses before anything is sent. An error contains the status and
// GitHub's message, never what was sent.
func (c Client) call(ctx context.Context, method, path, jwt string, body any, want int, out any) error {
	base := c.API
	if base == "" {
		base = APIURL
	}
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
		return err
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
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
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
		return fmt.Errorf("GitHub answered %d: %s", resp.StatusCode, e.Message)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("GitHub's answer: %w", err)
	}
	return nil
}
