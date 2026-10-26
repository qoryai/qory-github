package github

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const (
	commitA = "1111111111111111111111111111111111111111"
	commitB = "2222222222222222222222222222222222222222"
	tagObj  = "3333333333333333333333333333333333333333"
	zeroID  = "0000000000000000000000000000000000000000"
)

// pkt is s as one pkt-line.
func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

// advertisement is git's ref list for a fetch over HTTP with the ref lines given, the
// first of which gets the capabilities.
func advertisement(lines ...string) string {
	var b strings.Builder
	b.WriteString(pkt("# service=git-upload-pack\n") + "0000")
	for i, l := range lines {
		if i == 0 {
			l += "\x00multi_ack symref=HEAD:refs/heads/main agent=git/github-test"
		}
		b.WriteString(pkt(l + "\n"))
	}
	b.WriteString("0000")
	return b.String()
}

// refList is a repository's ref list: HEAD and main at commitA, a branch and a tag both
// named both at different commits, a branch named refs/tags/v1.0 at commitB, an
// annotated tag v1.0 peeled to commitA, a lightweight tag light at commitB, and a pull
// request's ref.
var refList = advertisement(
	commitA+" HEAD",
	commitB+" refs/heads/both",
	commitA+" refs/heads/main",
	commitB+" refs/heads/refs/tags/v1.0",
	commitB+" refs/pull/1/head",
	commitA+" refs/tags/both",
	commitB+" refs/tags/light",
	tagObj+" refs/tags/v1.0",
	commitA+" refs/tags/v1.0^{}",
)

// TestFindRefReadsTheRefList pins the names a ref list resolves: HEAD, a branch before
// a tag of the same name, an annotated tag peeled to its commit, a lightweight tag, a
// full ref name as that ref alone, never as a branch whose name starts with refs/, and
// a name the list does not have, as in an empty repository.
func TestFindRefReadsTheRefList(t *testing.T) {
	for name, want := range map[string]string{
		"HEAD":             commitA,
		"main":             commitA,
		"both":             commitB,
		"v1.0":             commitA,
		"light":            commitB,
		"refs/heads/main":  commitA,
		"refs/tags/v1.0":   commitA,
		"refs/pull/1/head": commitB,
		"missing":          "",
		"pull/1/head":      "",
		"refs/heads":       "",
	} {
		got, found, err := findRef(strings.NewReader(refList), name, maxAdvertisement)
		if err != nil || got != want || found != (want != "") {
			t.Errorf("%s: %q, %v, %v; want %q", name, got, found, err, want)
		}
	}
	empty := advertisement(zeroID + " capabilities^{}")
	for _, name := range []string{"HEAD", "main"} {
		if got, found, err := findRef(strings.NewReader(empty), name, maxAdvertisement); err != nil || found || got != "" {
			t.Errorf("an empty repository, %s: %q, %v, %v", name, got, found, err)
		}
	}
	// A pkt-line without its LF reads the same.
	noLF := pkt("# service=git-upload-pack") + "0000" + pkt(commitA+" HEAD\x00caps") + pkt(commitA+" refs/tags/x") + "0000"
	if got, found, err := findRef(strings.NewReader(noLF), "x", maxAdvertisement); err != nil || !found || got != commitA {
		t.Errorf("lines without LF: %q, %v, %v", got, found, err)
	}
}

// TestFindRefFailsOnAListThatBreaksTheFormat pins the strict reading of a ref list, its
// limit included.
func TestFindRefFailsOnAListThatBreaksTheFormat(t *testing.T) {
	head := pkt("# service=git-upload-pack\n") + "0000"
	first := pkt(commitA + " HEAD\x00caps\n")
	for what, list := range map[string]string{
		"empty":                        "",
		"no service line":              "0000" + first + "0000",
		"another service":              pkt("# service=git-receive-pack\n") + "0000" + first + "0000",
		"no flush after the service":   pkt("# service=git-upload-pack\n") + first + "0000",
		"no ref":                       head + "0000",
		"no last flush":                head + first,
		"upper-case length":            head + "003A" + commitA + " HEAD\x00capsxxx\n" + "0000",
		"length not hexadecimal":       head + "00g1" + "0000",
		"delimiter 0001":               head + first + "0001" + "0000",
		"length 0003":                  head + first + "0003" + "0000",
		"empty pkt-line 0004":          head + first + "0004" + "0000",
		"length past 65520":            head + first + "fff1" + strings.Repeat("a", 0xfff1-4) + "0000",
		"cut inside a length":          head + first + "00",
		"cut inside a pkt-line":        head + first + "0040" + commitA,
		"first ref without a NUL":      head + pkt(commitA+" HEAD\n") + "0000",
		"a short id":                   head + pkt("abc HEAD\x00caps\n") + "0000",
		"an upper-case id":             head + pkt(strings.ToUpper("abcdefabcdefabcdefabcdefabcdefabcdefabcd")+" HEAD\x00caps\n") + "0000",
		"no name":                      head + pkt(commitA+" \x00caps\n") + "0000",
		"a name with a space":          head + first + pkt(commitA+" refs/heads/a b\n") + "0000",
		"a name with a control":        head + first + pkt(commitA+" refs/heads/a\x01b\n") + "0000",
		"a NUL on a later line":        head + first + pkt(commitA+" refs/heads/a\x00b\n") + "0000",
		"data after the last flush":    head + first + "0000" + "x",
		"a pkt-line after the flush":   head + first + "0000" + pkt(commitA+" refs/heads/x\n"),
		"protocol v2's version line":   head + pkt("version 2\n") + "0000",
		"an id and no space and name":  head + pkt(commitA+"\x00caps\n") + "0000",
		"a smart list without refs":    head,
		"a dumb list of refs":          commitA + "\trefs/heads/main\n",
		"an HTML page":                 "<!DOCTYPE html><html></html>",
		"a capabilities line too late": head + first + pkt(zeroID+" capabilities^{}\x00caps\n") + "0000",
	} {
		if got, found, err := findRef(strings.NewReader(list), "missing", maxAdvertisement); err == nil {
			t.Errorf("%s: %q, %v, no error", what, got, found)
		}
	}
	// A list past the limit is an error, and so is one past it by one byte; a list of
	// exactly the limit reads.
	if _, _, err := findRef(strings.NewReader(refList), "missing", int64(len(refList)-1)); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("a list one byte past the limit: %v", err)
	}
	if _, found, err := findRef(strings.NewReader(refList), "light", int64(len(refList))); err != nil || !found {
		t.Errorf("a list of exactly the limit: %v, %v", found, err)
	}
	big := head + first + strings.Repeat(pkt(commitB+" refs/pull/"+strings.Repeat("9", 60)+"/head\n"), 2000) + "0000"
	if _, _, err := findRef(strings.NewReader(big), "missing", 64<<10); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("a list far past the limit: %v", err)
	}
	// A branch that matches ends the reading: what follows it is not read.
	if got, found, err := findRef(strings.NewReader(head+first+pkt(commitB+" refs/heads/main\n")+"zzzz"), "main", maxAdvertisement); err != nil || !found || got != commitB {
		t.Errorf("a branch before a broken tail: %q, %v, %v", got, found, err)
	}
}

// publicFake is GitHub's three hosts for a public read, each an httptest server, and
// what each request to them had.
type publicFake struct {
	git, raw, api *httptest.Server
	mu            sync.Mutex
	seen          []string
	headers       []http.Header
	handle        func(host string, w http.ResponseWriter, r *http.Request)
}

func newPublicFake(t *testing.T, handle func(host string, w http.ResponseWriter, r *http.Request)) *publicFake {
	t.Helper()
	f := &publicFake{handle: handle}
	serve := func(host string) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			f.seen = append(f.seen, host+" "+r.URL.EscapedPath()+"?"+r.URL.RawQuery)
			f.headers = append(f.headers, r.Header.Clone())
			f.mu.Unlock()
			f.handle(host, w, r)
		}))
		t.Cleanup(s.Close)
		return s
	}
	f.git, f.raw, f.api = serve("git"), serve("raw"), serve("api")
	return f
}

func (f *publicFake) client() Public { return Public{Git: f.git.URL, Raw: f.raw.URL, API: f.api.URL} }

// checkAnonymous reports a request to the fake with a credential.
func (f *publicFake) checkAnonymous(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, h := range f.headers {
		if h.Get("Authorization") != "" || h.Get("Cookie") != "" {
			t.Errorf("the request %s has a credential", f.seen[i])
		}
	}
}

// TestPublicRefsReadsTheStatus pins what each status of the anonymous ref list means:
// 200 with git's media type is public, and its list is read; 401, 404, 410, 451, a 403
// that is not a rate limit and a redirect to another repository are not public; 429 and
// a 403 with Retry-After or X-RateLimit-Remaining: 0 are ErrRateLimited; every other
// status and a 200 of another media type are errors. No request has a credential, and
// no error contains the URL.
func TestPublicRefsReadsTheStatus(t *testing.T) {
	var status int
	var header http.Header
	var body string
	f := newPublicFake(t, func(_ string, w http.ResponseWriter, r *http.Request) {
		for k, v := range header {
			w.Header()[k] = v
		}
		if status == http.StatusMovedPermanently {
			w.Header().Set("Location", "/acme/renamed.git/info/refs?service=git-upload-pack")
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	})
	p := f.client()
	repo := Repository{Owner: "acme", Name: "widgets"}
	gitType := http.Header{"Content-Type": {advertisementType}}
	for _, c := range []struct {
		status int
		header http.Header
		body   string
		name   string
		want   Refs
		err    error
	}{
		{200, gitType, refList, "", Refs{Public: true}, nil},
		{200, gitType, refList, "v1.0", Refs{Public: true, Commit: commitA, Found: true}, nil},
		{200, gitType, refList, "missing", Refs{Public: true}, nil},
		{200, gitType, "broken", "main", Refs{}, errors.New("")},
		{200, http.Header{"Content-Type": {"text/html; charset=utf-8"}}, "<html>", "", Refs{}, errors.New("")},
		{200, nil, refList, "", Refs{}, errors.New("")},
		{401, nil, "", "main", Refs{}, nil},
		{403, nil, "", "main", Refs{}, nil},
		{404, nil, "", "main", Refs{}, nil},
		{410, nil, "", "main", Refs{}, nil},
		{451, nil, "", "main", Refs{}, nil},
		{301, nil, "", "main", Refs{}, nil},
		{429, nil, "", "main", Refs{}, ErrRateLimited},
		{403, http.Header{"Retry-After": {"60"}}, "", "main", Refs{}, ErrRateLimited},
		{403, http.Header{"X-Ratelimit-Remaining": {"0"}}, "", "main", Refs{}, ErrRateLimited},
		{500, nil, "", "main", Refs{}, errors.New("")},
		{502, nil, "", "main", Refs{}, errors.New("")},
		{400, nil, "", "main", Refs{}, errors.New("")},
	} {
		status, header, body = c.status, c.header, c.body
		got, err := p.Refs(context.Background(), repo, c.name)
		switch {
		case c.err == nil && err != nil, c.err != nil && err == nil:
			t.Errorf("%d %v: error %v, want %v", c.status, c.header, err, c.err)
		case errors.Is(c.err, ErrRateLimited) && !errors.Is(err, ErrRateLimited):
			t.Errorf("%d %v: error %v, want ErrRateLimited", c.status, c.header, err)
		case got != c.want:
			t.Errorf("%d %v %q: %+v, want %+v", c.status, c.header, c.name, got, c.want)
		}
		if err != nil && strings.Contains(err.Error(), f.git.URL) {
			t.Errorf("the error %q contains the URL", err)
		}
	}
	f.mu.Lock()
	if want := "git /acme/widgets.git/info/refs?service=git-upload-pack"; f.seen[0] != want {
		t.Errorf("requested %s, want %s", f.seen[0], want)
	}
	f.mu.Unlock()
	f.checkAnonymous(t)
}

// TestPublicFollowsOnlyACaseRedirect pins the redirect rule: a redirect on the same host
// to the same path in another letter case is followed, at most twice; one to another
// repository, to another host or with another query is returned as it is, which for the
// ref list is not public.
func TestPublicFollowsOnlyACaseRedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("a redirect to another host was followed: %s", r.URL)
	}))
	defer other.Close()
	var to string
	f := newPublicFake(t, func(_ string, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/acme/widgets.git/info/refs":
			w.Header().Set("Content-Type", advertisementType)
			io.WriteString(w, refList)
		case r.URL.Path == "/ACME/loop.git/info/refs":
			http.Redirect(w, r, "/acme/LOOP.git/info/refs?"+r.URL.RawQuery, http.StatusMovedPermanently)
		case r.URL.Path == "/acme/LOOP.git/info/refs":
			http.Redirect(w, r, "/ACME/loop.git/info/refs?"+r.URL.RawQuery, http.StatusMovedPermanently)
		default:
			http.Redirect(w, r, to, http.StatusMovedPermanently)
		}
	})
	p := f.client()
	for target, public := range map[string]bool{
		"/acme/widgets.git/info/refs?service=git-upload-pack":                                                   true,
		"/acme/other.git/info/refs?service=git-upload-pack":                                                     false,
		"/acme/widgets.git/info/refs?service=git-receive-pack":                                                  false,
		"/acme/widgets.git/info/refs":                                                                           false,
		other.URL + "/acme/widgets.git/info/refs?service=git-upload-pack":                                       false,
		"//" + strings.TrimPrefix(other.URL, "http://") + "/acme/widgets.git/info/refs?service=git-upload-pack": false,
	} {
		to = target
		got, err := p.Refs(context.Background(), Repository{Owner: "Acme", Name: "Widgets"}, "main")
		if err != nil || got.Public != public {
			t.Errorf("a redirect to %s: %+v, %v; want public %v", target, got, err, public)
		}
	}
	if got, err := p.Refs(context.Background(), Repository{Owner: "ACME", Name: "loop"}, ""); err != nil || got.Public {
		t.Errorf("a loop of case redirects: %+v, %v; want not public", got, err)
	}
	f.checkAnonymous(t)
}

// TestPublicRawFileReadsAFile pins the raw file read: the text of a 200; false for a
// 404; ErrNotText past the limit, with or without Content-Length, for a NUL and for
// bytes that are not UTF-8; ErrRateLimited for 429; an error for a redirect and a 5xx;
// each part of the path escaped; and a path with an empty part, . or .. sent nowhere.
func TestPublicRawFileReadsAFile(t *testing.T) {
	f := newPublicFake(t, func(_ string, w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.EscapedPath(), "/acme/widgets/"+commitA+"/") {
		case "README.md":
			io.WriteString(w, "# Widgets\n")
		case "docs/a%20b%23c%3Fd%25e.md":
			io.WriteString(w, "escaped")
		case "big.txt":
			io.WriteString(w, strings.Repeat("a", 11))
		case "chunked.txt":
			w.(http.Flusher).Flush()
			io.WriteString(w, strings.Repeat("a", 11))
		case "exact.txt":
			io.WriteString(w, strings.Repeat("a", 10))
		case "nul.txt":
			io.WriteString(w, "a\x00b")
		case "latin1.txt":
			io.WriteString(w, "caf\xe9")
		case "limited":
			w.WriteHeader(429)
		case "moved":
			http.Redirect(w, r, "/acme/other/"+commitA+"/moved", http.StatusMovedPermanently)
		case "broken":
			w.WriteHeader(503)
		default:
			w.WriteHeader(404)
		}
	})
	p := f.client()
	repo := Repository{Owner: "acme", Name: "widgets"}
	read := func(path string) (string, bool, error) {
		return p.RawFile(context.Background(), repo, commitA, path, 10)
	}
	if got, found, err := read("README.md"); err != nil || !found || got != "# Widgets\n" {
		t.Errorf("README.md: %q, %v, %v", got, found, err)
	}
	if got, found, err := read("docs/a b#c?d%e.md"); err != nil || !found || got != "escaped" {
		t.Errorf("a path to escape: %q, %v, %v", got, found, err)
	}
	if got, found, err := read("exact.txt"); err != nil || !found || len(got) != 10 {
		t.Errorf("a file of exactly the limit: %q, %v, %v", got, found, err)
	}
	if _, found, err := read("missing.md"); err != nil || found {
		t.Errorf("a missing file: %v, %v", found, err)
	}
	for _, path := range []string{"big.txt", "chunked.txt", "nul.txt", "latin1.txt"} {
		if _, _, err := read(path); !errors.Is(err, ErrNotText) {
			t.Errorf("%s: %v, want ErrNotText", path, err)
		}
	}
	if _, _, err := read("limited"); !errors.Is(err, ErrRateLimited) {
		t.Errorf("a 429: %v, want ErrRateLimited", err)
	}
	for _, path := range []string{"moved", "broken"} {
		if _, _, err := read(path); err == nil || errors.Is(err, ErrNotText) || errors.Is(err, ErrRateLimited) {
			t.Errorf("%s: %v, want an error", path, err)
		}
	}
	f.mu.Lock()
	sent := len(f.seen)
	f.mu.Unlock()
	for _, path := range []string{"../x", "a/../b", "./a", "a//b", "a/", "/a", "a\x00b"} {
		if _, _, err := read(path); err == nil {
			t.Errorf("%q: no error", path)
		}
	}
	if _, _, err := p.RawFile(context.Background(), repo, "main", "README.md", 10); err == nil {
		t.Error("a commit that is not an id: no error")
	}
	if _, _, err := p.RawFile(context.Background(), Repository{Owner: "acme", Name: ".."}, commitA, "README.md", 10); err == nil {
		t.Error("a name ..: no error")
	}
	f.mu.Lock()
	if len(f.seen) != sent {
		t.Errorf("a path or a repository that breaks the rules was sent: %q", f.seen[sent:])
	}
	f.mu.Unlock()
	f.checkAnonymous(t)
}

// TestPublicCommitExistsChecksOneCommit pins the anonymous REST check of a commit.
func TestPublicCommitExistsChecksOneCommit(t *testing.T) {
	var status int
	var header http.Header
	f := newPublicFake(t, func(_ string, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/widgets/git/commits/"+commitA || r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("requested %s with Accept %q", r.URL, r.Header.Get("Accept"))
		}
		for k, v := range header {
			w.Header()[k] = v
		}
		w.WriteHeader(status)
	})
	p := f.client()
	for _, c := range []struct {
		status int
		header http.Header
		exists bool
		err    error
	}{
		{200, nil, true, nil},
		{404, nil, false, nil},
		{409, nil, false, nil},
		{422, nil, false, nil},
		{429, nil, false, ErrRateLimited},
		{403, http.Header{"X-Ratelimit-Remaining": {"0"}}, false, ErrRateLimited},
		{403, nil, false, errors.New("")},
		{301, http.Header{"Location": {"/repositories/1/git/commits/" + commitA}}, false, errors.New("")},
		{500, nil, false, errors.New("")},
	} {
		status, header = c.status, c.header
		exists, err := p.CommitExists(context.Background(), Repository{Owner: "acme", Name: "widgets"}, commitA)
		switch {
		case exists != c.exists, (err == nil) != (c.err == nil):
			t.Errorf("%d: %v, %v; want %v, %v", c.status, exists, err, c.exists, c.err)
		case errors.Is(c.err, ErrRateLimited) && !errors.Is(err, ErrRateLimited):
			t.Errorf("%d: %v, want ErrRateLimited", c.status, err)
		}
	}
	f.checkAnonymous(t)
}

// TestPublicSendsToGitHubOrALoopbackHostAlone pins the base URLs a public read takes,
// and the refs it reads and writes.
func TestPublicSendsToGitHubOrALoopbackHostAlone(t *testing.T) {
	for _, base := range []string{"https://example.com", "http://github.com", "https://github.com/", "http://127.0.0.1:1/path", "http://user@127.0.0.1:1", "http://127.0.0.1:1?x=1", "ftp://127.0.0.1", "http://10.0.0.1"} {
		p := Public{Git: base}
		if _, err := p.Refs(context.Background(), Repository{Owner: "acme", Name: "widgets"}, ""); err == nil || !strings.Contains(err.Error(), "base URL") {
			t.Errorf("%s: %v, want the base URL's error", base, err)
		}
	}
	for _, repo := range []Repository{{"acme", "a.git"}, {"acme", "."}, {"-acme", "a"}, {"acme", "a/b"}, {"acme", "a%2Fb"}, {"acme", "a?b"}, {"ac/me", "a"}, {"", "a"}} {
		if _, err := (Public{Git: "http://127.0.0.1:1"}).Refs(context.Background(), repo, ""); err == nil || !strings.Contains(err.Error(), "owner/name") {
			t.Errorf("%+v: %v, want the repository's error", repo, err)
		}
	}
	if got := PublicRef(Repository{Owner: "Acme", Name: "Widgets.Go"}); got != "github.com/acme/widgets.go" {
		t.Errorf("PublicRef: %s", got)
	}
	for ref, ok := range map[string]bool{
		"github.com/acme/widgets":      true,
		"github.com/acme/widgets.go":   true,
		"github.com/Acme/widgets":      false,
		"github.com/acme/widgets.git":  false,
		"github.com/acme":              false,
		"github.com/acme/widgets/x":    false,
		"github.com/acme/..":           false,
		"gitlab.com/acme/widgets":      false,
		"github.com.evil/acme/widgets": false,
		"1296269":                      false,
		"https://github.com/acme/a":    false,
	} {
		if repo, got := ParsePublicRef(ref); got != ok || (ok && PublicRef(repo) != ref) {
			t.Errorf("%s: %+v, %v; want %v", ref, repo, got, ok)
		}
	}
}

// TestCheckPublicBaseTakesALoopbackHostAlone pins the base URLs CheckPublicBase takes:
// http or https on a loopback host with any port; GitHub's hosts, another host, an
// empty base, a path, a user, a query, a fragment and another scheme are errors that
// quote nothing.
func TestCheckPublicBaseTakesALoopbackHostAlone(t *testing.T) {
	for _, base := range []string{"http://127.0.0.1", "http://127.0.0.1:8080", "https://127.0.0.2:1", "http://[::1]:9", "https://localhost", "http://localhost:65535/"} {
		if err := CheckPublicBase(base); err != nil {
			t.Errorf("%s: %v", base, err)
		}
	}
	for _, base := range []string{"", PublicGitURL, PublicRawURL, PublicAPIURL, "https://github.com.example.com", "http://10.0.0.1", "http://[::2]", "http://127.0.0.1:1/path",
		"http://secret@127.0.0.1:1", "http://127.0.0.1:1?secret", "http://127.0.0.1:1#secret", "http://127.0.0.1:1/#", "http://127.0.0.1:1?", "ftp://127.0.0.1", "127.0.0.1:1", "http:secret"} {
		err := CheckPublicBase(base)
		if err == nil || strings.Contains(err.Error(), "secret") || (base != "" && strings.Contains(err.Error(), base)) {
			t.Errorf("%q: %v, want the rule's error", base, err)
		}
	}
}
