package github

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// The hosts a public read reaches, each without a credential: git over HTTPS for a
// repository's refs, the raw file host for a file at a commit, and the REST API for a
// commit's check. They are hosts of the adapter, not hosts of a run.
const (
	PublicGitURL = "https://github.com"
	PublicRawURL = "https://raw.githubusercontent.com"
	PublicAPIURL = APIURL
)

// publicTimeout bounds each request of a public read, its body included.
const publicTimeout = 20 * time.Second

// maxAdvertisement is the most bytes of a repository's ref list that [Public.Refs]
// reads. GitHub lists every branch, tag and pull request's ref, so a repository with
// many pull requests has a list of several MiB.
const maxAdvertisement = 32 << 20

// maxPktLine is the largest pkt-line, its four length digits included, as git writes
// them.
const maxPktLine = 65520

// advertisementType is the media type of git's ref list over HTTP for a fetch.
const advertisementType = "application/x-git-upload-pack-advertisement"

// ErrRateLimited is the error of a public read when GitHub returns 429, or 403 with
// Retry-After or with X-RateLimit-Remaining set to 0: a rate limit, which no request
// sent at once changes.
var ErrRateLimited = errors.New("GitHub returned its rate limit to a request without a credential")

// Public reads public repositories on GitHub as a request without a credential reads
// them. No method takes a token, and no request has an Authorization header or a
// cookie, so no installation's token and none of the App's credentials reach these
// hosts. Each request follows a redirect only on the same scheme and host, to a path
// that differs from the request's in letter case alone, at most twice; a redirect to
// another owner/name, such as a renamed or moved repository's, is returned as it is.
type Public struct {
	// Git, Raw and API are the base URLs of git over HTTPS, of the raw file host and of
	// the REST API: empty is [PublicGitURL], [PublicRawURL] and [PublicAPIURL]. Any other
	// value must be http or https on a loopback host, for a test, with no path, user,
	// query or fragment; else no request is sent.
	Git, Raw, API string
	// UserAgent is the User-Agent of every request; empty is qory-github.
	UserAgent string
}

// CommitID is whether s is a full commit id as GitHub writes one: 40 lower-case
// hexadecimal digits, or 64 in a repository that uses SHA-256.
func CommitID(s string) bool { return shaShape.MatchString(s) }

// PublicRef is the resource_ref of a public repository: github.com/owner/name in lower
// case.
func PublicRef(repo Repository) string {
	return strings.ToLower(GitHost + "/" + repo.String())
}

// ParsePublicRef is the repository of a resource_ref that [PublicRef] writes, or false
// for any other string: a ref in another case, with .git, with more or fewer parts, or
// with a name GitHub does not take.
func ParsePublicRef(ref string) (Repository, bool) {
	rest, ok := strings.CutPrefix(ref, GitHost+"/")
	if !ok || ref != strings.ToLower(ref) {
		return Repository{}, false
	}
	owner, name, ok := strings.Cut(rest, "/")
	if !ok || !validRepository(Repository{Owner: owner, Name: name}) {
		return Repository{}, false
	}
	return Repository{Owner: owner, Name: name}, true
}

// validRepository is whether repo is an owner and a name GitHub takes, with a name that
// is not a dot segment and does not end with .git.
func validRepository(repo Repository) bool {
	return ownerShape.MatchString(repo.Owner) && nameShape.MatchString(repo.Name) && repo.Name != "." && repo.Name != ".." && !strings.HasSuffix(repo.Name, ".git")
}

// Refs is what [Public.Refs] read of a repository's ref list.
type Refs struct {
	// Public is whether GitHub returned the list to a request without a credential.
	Public bool
	// Commit is the commit that the name asked for points to, and Found whether the list
	// has that name. Both are empty when Public is false or no name was asked for.
	Commit string
	Found  bool
}

// Refs reads the ref list of the repository as git over HTTPS returns it to a request
// without a credential: GET /owner/name.git/info/refs?service=git-upload-pack on
// [Public.Git].
//
//   - 200 with git's media type: the repository is public. With name set, Refs reads the
//     list, at most [maxAdvertisement] bytes of strict pkt-lines, and returns the commit
//     of name: HEAD for HEAD; for a name that starts with refs/, that ref alone; else
//     the branch name, then the tag name. A tag is peeled to its commit.
//   - 401, 404, 410, 451, a 403 that is not a rate limit, and a redirect: the repository
//     is not public at this owner/name. GitHub returns 401 for a private repository and
//     for one that does not exist.
//   - [ErrRateLimited] for a rate limit, and an error for every other status, for a list
//     that breaks the format, and when GitHub cannot be reached.
func (p Public) Refs(ctx context.Context, repo Repository, name string) (Refs, error) {
	const what = "reading a repository's refs without a credential"
	if !validRepository(repo) {
		return Refs{}, errors.New(what + ": the repository is not owner/name")
	}
	resp, err := p.get(ctx, what, p.Git, PublicGitURL, []string{repo.Owner, repo.Name + ".git", "info", "refs"}, "service=git-upload-pack", "")
	if err != nil {
		return Refs{}, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case publicRateLimited(resp):
		return Refs{}, fmt.Errorf("%s: %w", what, ErrRateLimited)
	case resp.StatusCode >= 300 && resp.StatusCode < 400,
		resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden,
		resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusGone,
		resp.StatusCode == http.StatusUnavailableForLegalReasons:
		return Refs{}, nil
	default:
		return Refs{}, fmt.Errorf("%s: GitHub returned %d", what, resp.StatusCode)
	}
	if t, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || t != advertisementType {
		return Refs{}, fmt.Errorf("%s: GitHub returned 200 without git's media type", what)
	}
	if name == "" {
		return Refs{Public: true}, nil
	}
	commit, found, err := findRef(resp.Body, name, maxAdvertisement)
	if err != nil {
		return Refs{}, fmt.Errorf("%s: %w", what, err)
	}
	return Refs{Public: true, Commit: commit, Found: found}, nil
}

// RawFile reads the file at path in the repository at the commit as the raw file host
// returns it to a request without a credential: GET /owner/name/commit/path on
// [Public.Raw], each part of path escaped. It returns the file's text, or false for a
// 404, which the host returns for a path the commit has no file at, a directory among
// them, and for a commit the repository does not have. A file larger than max bytes,
// not UTF-8 or with a NUL is [ErrNotText]. A rate limit is [ErrRateLimited]; every other
// status, a redirect among them, is an error.
func (p Public) RawFile(ctx context.Context, repo Repository, commit, path string, max int) (string, bool, error) {
	const what = "reading a public file at a commit"
	if !validRepository(repo) || !CommitID(commit) {
		return "", false, errors.New(what + ": the repository is not owner/name, or the commit's id is not one")
	}
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsRune(part, 0) {
			return "", false, errors.New(what + ": the path has an empty part, a part . or .., or a NUL")
		}
	}
	resp, err := p.get(ctx, what, p.Raw, PublicRawURL, append([]string{repo.Owner, repo.Name, commit}, parts...), "", "")
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusNotFound:
		return "", false, nil
	case publicRateLimited(resp):
		return "", false, fmt.Errorf("%s: %w", what, ErrRateLimited)
	default:
		return "", false, fmt.Errorf("%s: GitHub returned %d", what, resp.StatusCode)
	}
	if resp.ContentLength > int64(max) {
		return "", false, ErrNotText
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
	if err != nil {
		return "", false, fmt.Errorf("%s: the file could not be read: %w", what, unsentURL(err))
	}
	if len(b) > max || !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return "", false, ErrNotText
	}
	return string(b), true, nil
}

// CommitExists checks the commit in the repository with one REST request without a
// credential: GET /repos/owner/name/git/commits/commit on [Public.API]. It returns true
// for 200, and false for 404, 409, as for an empty repository, and 422. A rate limit is
// [ErrRateLimited]; every other status, a redirect among them, is an error. GitHub
// allows 60 such requests an hour for each IP address.
func (p Public) CommitExists(ctx context.Context, repo Repository, commit string) (bool, error) {
	const what = "checking a public commit"
	if !validRepository(repo) || !CommitID(commit) {
		return false, errors.New(what + ": the repository is not owner/name, or the commit's id is not one")
	}
	resp, err := p.get(ctx, what, p.API, PublicAPIURL, []string{"repos", repo.Owner, repo.Name, "git", "commits", commit}, "", "application/vnd.github+json")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode == http.StatusOK:
		return true, nil
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusConflict, resp.StatusCode == http.StatusUnprocessableEntity:
		return false, nil
	case publicRateLimited(resp):
		return false, fmt.Errorf("%s: %w", what, ErrRateLimited)
	}
	return false, fmt.Errorf("%s: GitHub returned %d", what, resp.StatusCode)
}

// get sends a GET without a credential to base, or def when base is empty, followed by
// segments, each escaped, and query. An error begins with what and never contains the
// URL.
func (p Public) get(ctx context.Context, what, base, def string, segments []string, query, accept string) (*http.Response, error) {
	if base == "" {
		base = def
	}
	b, err := publicBase(base, def)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	escaped := make([]string, len(segments))
	for i, s := range segments {
		escaped[i] = url.PathEscape(s)
	}
	target := &url.URL{Scheme: b.Scheme, Host: b.Host, Path: "/" + strings.Join(segments, "/"), RawPath: "/" + strings.Join(escaped, "/"), RawQuery: query}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil || req.URL.Host != b.Host || req.URL.Scheme != b.Scheme {
		return nil, errors.New(what + ": the request could not be made")
	}
	ua := p.UserAgent
	if ua == "" {
		ua = "qory-github"
	}
	req.Header.Set("User-Agent", ua)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	hc := http.Client{Timeout: publicTimeout, CheckRedirect: caseRedirect}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: GitHub could not be reached: %w", what, unsentURL(err))
	}
	return resp, nil
}

// caseRedirect follows a redirect only on the request's scheme and host, with its
// query, to a path that differs from the first request's in letter case alone, and at
// most twice. Every other redirect is returned as the answer.
func caseRedirect(req *http.Request, via []*http.Request) error {
	first := via[0].URL
	if len(via) > 2 || req.URL.Scheme != first.Scheme || req.URL.Host != first.Host || req.URL.User != nil ||
		req.URL.RawQuery != first.RawQuery || !strings.EqualFold(req.URL.EscapedPath(), first.EscapedPath()) {
		return http.ErrUseLastResponse
	}
	return nil
}

// CheckPublicBase is nil for a base URL [Public] takes for a test in place of one of
// GitHub's hosts: http or https on a loopback host, 127.0.0.0/8, [::1] or localhost,
// with any port and no path, user, query or fragment. An empty base and GitHub's hosts
// are errors, and so is a # or a ? anywhere, an empty fragment or query among them,
// which publicBase does not check: url.Parse leaves an empty fragment no trace and
// marks an empty query only in ForceQuery. The error is the rule and never contains
// the URL.
func CheckPublicBase(base string) error {
	if _, err := publicBase(base, ""); base == "" || err != nil || strings.ContainsAny(base, "#?") {
		return errors.New("the base URL is not http or https on a loopback host with no path, user, query or fragment")
	}
	return nil
}

// publicBase is base as a URL when it is def, or http or https on a loopback host,
// 127.0.0.0/8, [::1] or localhost, with no path, user, query or fragment.
func publicBase(base, def string) (*url.URL, error) {
	u, err := url.Parse(base)
	if err == nil && base == def {
		return u, nil
	}
	bad := errors.New("the base URL is neither GitHub's nor, for a test, http or https on a loopback host")
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, bad
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, bad
	}
	return u, nil
}

// publicRateLimited is whether resp is GitHub's rate limit: 429, or 403 with Retry-After or
// with X-RateLimit-Remaining set to 0.
func publicRateLimited(resp *http.Response) bool {
	return resp.StatusCode == http.StatusTooManyRequests ||
		(resp.StatusCode == http.StatusForbidden && (resp.Header.Get("Retry-After") != "" || resp.Header.Get("X-RateLimit-Remaining") == "0"))
}

// unsentURL is err without the URL a *url.Error adds.
func unsentURL(err error) error {
	var u *url.Error
	if errors.As(err, &u) && u.Err != nil {
		return u.Err
	}
	return err
}

// findRef reads git's ref list for a fetch over HTTP from r, at most limit bytes of
// strict pkt-lines, and returns the commit of name: HEAD for HEAD; for a name that
// starts with refs/, that ref alone; else the branch name, then the tag name. A tag is
// peeled to its commit when the list has the peeled line. The list is a service line,
// "# service=git-upload-pack", a flush, the refs, the first with the capabilities after
// a NUL, and a flush, with nothing after it; an empty repository lists the one ref
// capabilities^{} with the zero id. Reading stops at a branch or HEAD that matches,
// since nothing later in the list changes that commit. A list longer than limit bytes,
// a length that is not four lower-case hexadecimal digits, a pkt-line shorter than 5 or
// longer than [maxPktLine] bytes, an id that is not a commit id, a ref name with a
// space or a control character, and anything after the last flush are errors.
func findRef(r io.Reader, name string, limit int64) (string, bool, error) {
	lr := &io.LimitedReader{R: r, N: limit + 1}
	br := bufio.NewReaderSize(lr, 64<<10)
	tooLong := errors.New("the ref list is longer than its limit")
	next := func() ([]byte, bool, error) {
		line, flush, err := readPktLine(br)
		if err != nil && lr.N <= 0 {
			err = tooLong
		}
		return line, flush, err
	}
	line, flush, err := next()
	if err != nil {
		return "", false, err
	}
	if flush || strings.TrimSuffix(string(line), "\n") != "# service=git-upload-pack" {
		return "", false, errors.New("the ref list does not start with git-upload-pack's service line")
	}
	if _, flush, err := next(); err != nil || !flush {
		return "", false, errors.New("the ref list has no flush after its service line")
	}
	var branch, tag, tagPeeled, exact, exactPeeled string
	// A name that starts with refs/ is looked up as that ref alone; git tries that ref
	// first too.
	full := strings.HasPrefix(name, "refs/")
	first := true
	for {
		line, flush, err := next()
		if err != nil {
			return "", false, err
		}
		if flush {
			if first {
				return "", false, errors.New("the ref list has no ref")
			}
			break
		}
		id, ref, err := refLine(line, first)
		if err != nil {
			return "", false, err
		}
		if first && ref == "capabilities^{}" && strings.Trim(id, "0") == "" {
			first = false
			continue
		}
		first = false
		switch {
		case name == "HEAD" && ref == "HEAD":
			return id, true, nil
		case name == "HEAD":
		case full && ref == name && strings.HasPrefix(name, "refs/heads/"):
			return id, true, nil
		case full && ref == name:
			exact = id
		case full && ref == name+"^{}":
			exactPeeled = id
		case full:
		case ref == "refs/heads/"+name:
			branch = id
		case ref == "refs/tags/"+name:
			tag = id
		case ref == "refs/tags/"+name+"^{}":
			tagPeeled = id
		}
		if branch != "" {
			return branch, true, nil
		}
	}
	if lr.N <= 0 {
		return "", false, tooLong
	}
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		return "", false, errors.New("the ref list has data after its last flush")
	}
	switch {
	case tagPeeled != "":
		return tagPeeled, true, nil
	case tag != "":
		return tag, true, nil
	case exactPeeled != "":
		return exactPeeled, true, nil
	case exact != "":
		return exact, true, nil
	}
	return "", false, nil
}

// readPktLine reads one pkt-line: its payload, or flush for 0000.
func readPktLine(br *bufio.Reader) ([]byte, bool, error) {
	var head [4]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return nil, false, errors.New("the ref list ends inside a pkt-line's length")
	}
	for _, c := range head {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, false, errors.New("a pkt-line's length is not four lower-case hexadecimal digits")
		}
	}
	n, _ := strconv.ParseUint(string(head[:]), 16, 32)
	switch {
	case n == 0:
		return nil, true, nil
	case n <= 4 || n > maxPktLine:
		return nil, false, errors.New("a pkt-line's length is outside 5 to 65520")
	}
	line := make([]byte, n-4)
	if _, err := io.ReadFull(br, line); err != nil {
		return nil, false, errors.New("the ref list ends inside a pkt-line")
	}
	return line, false, nil
}

// refLine is the id and the ref name of one line of the ref list: "<id> <name>", one
// LF at its end or none, with "\x00<capabilities>" after the name on the first line
// alone.
func refLine(line []byte, first bool) (string, string, error) {
	s := strings.TrimSuffix(string(line), "\n")
	if first {
		var ok bool
		if s, _, ok = strings.Cut(s, "\x00"); !ok {
			return "", "", errors.New("the first ref has no capabilities")
		}
	}
	id, ref, ok := strings.Cut(s, " ")
	if !ok || !CommitID(id) || ref == "" {
		return "", "", errors.New("a ref line is not an id, a space and a name")
	}
	for _, c := range ref {
		if c <= ' ' || c == 0x7f {
			return "", "", errors.New("a ref name has a space or a control character")
		}
	}
	return id, ref, nil
}
