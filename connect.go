package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Connect is how a person links an installation of the App to Qory Apiary, which only
// serve does, where QORY_FEATURES names factory. GitHub sends the person back to serve
// twice: after the installation, to the App's Setup URL, and after GitHub's sign-in, to
// the App's callback URL. Both are under serve's public URL.
const (
	// ConnectReturnPath is the App's Setup URL under serve's public URL.
	ConnectReturnPath = "/v1/connect/return"
	// ConnectAuthorizedPath is the App's callback URL under serve's public URL, where
	// GitHub's sign-in sends the person with a code.
	ConnectAuthorizedPath = "/v1/connect/authorized"
)

// ErrPublicURL is the refusal of a public URL [CheckPublicURL] does not take.
var ErrPublicURL = errors.New("is not an https URL of a host, an optional port and an optional path, without a user, a query or a fragment")

// CheckPublicURL takes where serve is reached from outside: https, a host, a port from
// 1 to 65535 or none, and a path or none, without a user, a query or a fragment, an
// empty one among them, and without white space or a control character. It returns
// the URL with its scheme and host in lower case and with no slash at its end, however
// many it had, so a path joined to it, as /v1/connect, follows one slash alone. setup
// and serve both check it so.
// The error, [ErrPublicURL], names the rule, never the URL.
func CheckPublicURL(s string) (string, error) {
	if strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f }) || strings.ContainsAny(s, "#?") {
		return "", ErrPublicURL
	}
	u, err := url.Parse(s)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", ErrPublicURL
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return "", ErrPublicURL
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return "", ErrPublicURL
	}
	return strings.TrimRight("https://"+strings.ToLower(u.Host)+u.EscapedPath(), "/"), nil
}

// ConnectManifest adds to the manifest m what Connect needs of the App, under serve's
// public URL publicURL: the Setup URL, which GitHub opens after an installation and
// after its change, and the callback URL of GitHub's sign-in, which GitHub does not
// start at the installation, since serve starts it.
func ConnectManifest(m map[string]any, publicURL string) {
	m["setup_url"] = publicURL + ConnectReturnPath
	m["setup_on_update"] = true
	m["callback_urls"] = []string{publicURL + ConnectAuthorizedPath}
	m["request_oauth_on_install"] = false
}

// Web is GitHub's website for the API the client reaches: https://github.com for
// GitHub's API, and otherwise the API's scheme and host, as a test's loopback server
// serves both. [CheckAPIURL] takes no other API.
func (c Client) Web() string {
	u, err := url.Parse(c.base())
	if err != nil || u.Hostname() == APIHost {
		return WebURL
	}
	return u.Scheme + "://" + u.Host
}

// maxUserInstallationPages is the most pages the listing of a person's installations
// reads.
const maxUserInstallationPages = 100

// maxTokenAnswer is the most GitHub's answer to a code's exchange may hold.
const maxTokenAnswer = 64 << 10

// oauthErrorShape is the error GitHub's answer to a code's exchange names, which an
// error says when it has this shape.
var oauthErrorShape = regexp.MustCompile(`^[a-z_]{1,64}$`)

// UserToken exchanges the code GitHub's sign-in sent back for the person's token, with
// the App's client id and secret: POST /login/oauth/access_token on GitHub's website,
// [Client.Web]. redirectURI is the callback URL the sign-in was started with. An answer
// that names an error is one, even with a token. The token
// is the person's: the caller uses it for the checks it makes and drops it. It follows
// no redirect. An error says GitHub's error code or the status, never the code, the
// secret or a token.
func (c Client) UserToken(ctx context.Context, clientID string, clientSecret []byte, code, redirectURI string) (string, error) {
	const what = "exchanging the sign-in's code"
	if err := CheckAPIURL(c.base()); err != nil {
		return "", err
	}
	form := url.Values{"client_id": {clientID}, "client_secret": {string(clientSecret)}, "code": {code}, "redirect_uri": {redirectURI}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Web()+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%s: the request could not be made", what)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.userAgent())
	hc := http.Client{Timeout: 30 * time.Second}
	if c.HTTP != nil {
		hc = *c.HTTP
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s: GitHub could not be reached: %w", what, unsent(err, "/login/oauth/access_token"))
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenAnswer+1))
	if err != nil || len(b) > maxTokenAnswer {
		return "", fmt.Errorf("%s: GitHub's answer could not be read", what)
	}
	var got struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	json.Unmarshal(b, &got)
	switch {
	case resp.StatusCode != http.StatusOK:
		return "", &codeRefused{fmt.Errorf("%s: GitHub answered %d", what, resp.StatusCode)}
	case got.Error != "" && oauthErrorShape.MatchString(got.Error):
		return "", &codeRefused{fmt.Errorf("%s: GitHub answered %s", what, got.Error)}
	case got.Error != "":
		return "", &codeRefused{fmt.Errorf("%s: GitHub answered an error", what)}
	case got.AccessToken == "" || strings.ContainsFunc(got.AccessToken, func(r rune) bool { return r <= ' ' || r >= 0x7f }):
		return "", &codeRefused{fmt.Errorf("%s: GitHub answered without a token", what)}
	}
	return got.AccessToken, nil
}

// codeRefused is GitHub's answer to a code's exchange that gives no token, as opposed
// to GitHub out of reach or its answer unread.
type codeRefused struct{ err error }

func (e *codeRefused) Error() string { return e.err.Error() }
func (e *codeRefused) Unwrap() error { return e.err }

// CodeRefused is whether err, an error of [Client.UserToken], is GitHub's answer that
// gives no token, rather than GitHub out of reach or its answer unread.
func CodeRefused(err error) bool {
	var e *codeRefused
	return errors.As(err, &e)
}

// UserInstallation is one of the App's installations a person reaches, as GET
// /user/installations lists it: its id, the account it is installed on, whether GitHub
// has suspended it, and the permissions it grants the App.
type UserInstallation struct {
	ID          int64
	Account     Account
	Suspended   bool
	Permissions map[string]string
}

// Account is a GitHub account: its login, its id, and its type, Organization or User.
type Account struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Type  string `json:"type"`
}

// UserInstallations are the App's installations the person whose token token is can
// reach, GET /user/installations, every page of it, 100 pages at most. An error never
// says the token.
func (c Client) UserInstallations(ctx context.Context, token string) ([]UserInstallation, error) {
	const what = "listing the installations the person reaches"
	read := pages{what: what, max: maxUserInstallationPages}
	p := &Pacer{}
	var out []UserInstallation
	for path := "/user/installations?per_page=100"; path != ""; {
		if err := read.read(path); err != nil {
			return nil, err
		}
		var page struct {
			Installations []struct {
				ID          int64             `json:"id"`
				Account     *Account          `json:"account"`
				SuspendedAt *string           `json:"suspended_at"`
				Permissions map[string]string `json:"permissions"`
			} `json:"installations"`
		}
		next, err := c.get(ctx, p, false, what, path, token, &page)
		if err != nil {
			return nil, err
		}
		for _, in := range page.Installations {
			u := UserInstallation{ID: in.ID, Suspended: in.SuspendedAt != nil, Permissions: in.Permissions}
			if in.Account != nil {
				u.Account = *in.Account
			}
			out = append(out, u)
		}
		path = next
	}
	return out, nil
}

// User is the account of the person whose token token is, GET /user. An error never
// says the token.
func (c Client) User(ctx context.Context, token string) (Account, error) {
	const what = "reading the person's account"
	var a Account
	if _, err := c.get(ctx, &Pacer{}, false, what, "/user", token, &a); err != nil {
		return Account{}, err
	}
	return a, nil
}

// Membership is a person's membership of an organisation, as GET
// /user/memberships/orgs/{org} says it: its state, active or pending, its role, admin or
// member, and the ids of the organisation and of the person.
type Membership struct {
	State, Role          string
	Organization, Person int64
}

// loginShape is a GitHub login: letters, digits and hyphens, 39 at most.
var loginShape = regexp.MustCompile(`^[A-Za-z0-9-]{1,39}$`)

// OrgMembership is the membership of the organisation org of the person whose token
// token is, GET /user/memberships/orgs/{org}. GitHub answers 404 when the person is
// not a member, which [Gone] says, and 403 when the App may not read it. An error never
// says the token.
func (c Client) OrgMembership(ctx context.Context, token, org string) (Membership, error) {
	const what = "reading the person's membership of the organisation"
	if !loginShape.MatchString(org) {
		return Membership{}, errors.New(what + ": the organisation's login is not one")
	}
	var m struct {
		State        string  `json:"state"`
		Role         string  `json:"role"`
		Organization Account `json:"organization"`
		User         Account `json:"user"`
	}
	if _, err := c.get(ctx, &Pacer{}, false, what, "/user/memberships/orgs/"+org, token, &m); err != nil {
		return Membership{}, err
	}
	return Membership{State: m.State, Role: m.Role, Organization: m.Organization.ID, Person: m.User.ID}, nil
}

// Refused is whether err, or an error it wraps, is GitHub's 403: the token may not do
// what was asked.
func Refused(err error) bool {
	var e *answerError
	return errors.As(err, &e) && e.status == http.StatusForbidden
}
