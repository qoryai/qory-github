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

// The most pages the listings of a person's installations and of the repositories one
// of them gives the person reads.
const (
	maxUserInstallationPages = 100
	maxUserRepositoryPages   = maxRepositoryPages
)

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
	req.Header.Set("User-Agent", "qory-github")
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
		return "", fmt.Errorf("%s: GitHub answered %d", what, resp.StatusCode)
	case got.Error != "" && oauthErrorShape.MatchString(got.Error):
		return "", fmt.Errorf("%s: GitHub answered %s", what, got.Error)
	case got.Error != "":
		return "", fmt.Errorf("%s: GitHub answered an error", what)
	case got.AccessToken == "" || strings.ContainsFunc(got.AccessToken, func(r rune) bool { return r <= ' ' || r >= 0x7f }):
		return "", fmt.Errorf("%s: GitHub answered without a token", what)
	}
	return got.AccessToken, nil
}

// UserInstallations are the ids of the App's installations the person whose token
// token is can reach, GET /user/installations, every page of it, 100 pages at most.
// An error never says the token.
func (c Client) UserInstallations(ctx context.Context, token string) ([]int64, error) {
	const what = "listing the installations the person reaches"
	read := pages{what: what, max: maxUserInstallationPages}
	p := &Pacer{}
	var ids []int64
	for path := "/user/installations?per_page=100"; path != ""; {
		if err := read.read(path); err != nil {
			return nil, err
		}
		var page struct {
			Installations []struct {
				ID int64 `json:"id"`
			} `json:"installations"`
		}
		next, err := c.get(ctx, p, false, what, path, token, &page)
		if err != nil {
			return nil, err
		}
		for _, in := range page.Installations {
			ids = append(ids, in.ID)
		}
		path = next
	}
	return ids, nil
}

// UserRepositories are the full names, owner/name, of the repositories of the
// installation the person whose token token is can read, GET
// /user/installations/{id}/repositories, every page of it, 1,000 pages at most. An
// error never says the token.
func (c Client) UserRepositories(ctx context.Context, token string, installation int64) ([]string, error) {
	const what = "listing the installation's repositories the person reads"
	if installation <= 0 {
		return nil, errors.New(what + ": an installation's id is positive")
	}
	read := pages{what: what, max: maxUserRepositoryPages}
	p := &Pacer{}
	var names []string
	for path := "/user/installations/" + strconv.FormatInt(installation, 10) + "/repositories?per_page=100"; path != ""; {
		if err := read.read(path); err != nil {
			return nil, err
		}
		var page struct {
			Repositories []ghRepo `json:"repositories"`
		}
		next, err := c.get(ctx, p, false, what, path, token, &page)
		if err != nil {
			return nil, err
		}
		for _, r := range page.Repositories {
			names = append(names, r.FullName)
		}
		path = next
	}
	return names, nil
}
