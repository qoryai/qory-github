package serve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
)

const (
	// devCommit is the commit of the branch dev in [publicGitHub], and tagObject the
	// annotated tag v1.0, which peels to widgetsCommit.
	devCommit = "89abcdef0123456789abcdef0123456789abcdef"
	tagObject = "fedcba9876543210fedcba9876543210fedcba98"
	// missingCommit is a commit id no repository of [publicGitHub] has.
	missingCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// publicGitHub is GitHub's three hosts as a public read reaches them, without a
// credential, each an httptest server: git over HTTPS, the raw file host and the REST
// API. The repositories in public list HEAD, main and v1.0 at widgetsCommit and dev at
// devCommit; every other returns 401, as GitHub does for a private repository, except
// acme/renamed, which redirects to acme/new, and acme/gone, which returns 404. The raw
// host has, at widgetsCommit: README.md, docs/a b.md, docs, a directory, big.txt, past
// the read's limit, and bin, with a NUL; at devCommit: README.md. The REST API has
// widgetsCommit and devCommit.
type publicGitHub struct {
	git, raw, api *httptest.Server

	mu       sync.Mutex
	public   map[string]bool
	requests []string
	headers  []http.Header
	// gitStatus, rawStatus and apiStatus, when set, are the status that host returns to
	// every request, with the header given.
	gitStatus, rawStatus, apiStatus int
	header                          http.Header
}

func newPublicGitHub(t *testing.T) *publicGitHub {
	t.Helper()
	p := &publicGitHub{public: map[string]bool{}}
	serve := func(host string, h func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.mu.Lock()
			p.requests = append(p.requests, host+" "+r.URL.EscapedPath())
			p.headers = append(p.headers, r.Header.Clone())
			p.mu.Unlock()
			h(w, r)
		}))
		t.Cleanup(s.Close)
		return s
	}
	p.git = serve("git", p.serveGit)
	p.raw = serve("raw", p.serveRaw)
	p.api = serve("api", p.serveAPI)
	return p
}

func (p *publicGitHub) client() github.Public {
	return github.Public{Git: p.git.URL, Raw: p.raw.URL, API: p.api.URL}
}

// override writes the status set for a host, with the header, and is whether it did.
func (p *publicGitHub) override(w http.ResponseWriter, status int) bool {
	if status == 0 {
		return false
	}
	for k, v := range p.header {
		w.Header()[k] = v
	}
	w.WriteHeader(status)
	return true
}

func pktLine(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

func (p *publicGitHub) serveGit(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.override(w, p.gitStatus) {
		return
	}
	repo, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".git/info/refs")
	switch {
	case !ok || r.URL.RawQuery != "service=git-upload-pack":
		w.WriteHeader(http.StatusBadRequest)
	case strings.ToLower(repo) == "acme/renamed":
		http.Redirect(w, r, "/acme/new.git/info/refs?service=git-upload-pack", http.StatusMovedPermanently)
	case strings.ToLower(repo) == "acme/gone":
		w.WriteHeader(http.StatusNotFound)
	case !p.public[strings.ToLower(repo)]:
		w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
		w.WriteHeader(http.StatusUnauthorized)
	default:
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		io.WriteString(w, pktLine("# service=git-upload-pack\n")+"0000"+
			pktLine(widgetsCommit+" HEAD\x00multi_ack symref=HEAD:refs/heads/main\n")+
			pktLine(devCommit+" refs/heads/dev\n")+
			pktLine(widgetsCommit+" refs/heads/main\n")+
			pktLine(tagObject+" refs/tags/v1.0\n")+
			pktLine(widgetsCommit+" refs/tags/v1.0^{}\n")+"0000")
	}
}

func (p *publicGitHub) serveRaw(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.override(w, p.rawStatus) {
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.EscapedPath(), "/"), "/", 4)
	if len(parts) != 4 || !p.public[strings.ToLower(parts[0]+"/"+parts[1])] {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch parts[2] + " " + parts[3] {
	case widgetsCommit + " README.md":
		io.WriteString(w, "# Tools\n")
	case widgetsCommit + " docs/a%20b.md":
		io.WriteString(w, "spaced")
	case widgetsCommit + " big.txt":
		io.WriteString(w, strings.Repeat("a", contracts.ReadContentMaxBytes+1))
	case widgetsCommit + " bin":
		io.WriteString(w, "a\x00b")
	case devCommit + " README.md":
		io.WriteString(w, "# Dev\n")
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (p *publicGitHub) serveAPI(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.override(w, p.apiStatus) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	for _, c := range []string{widgetsCommit, devCommit} {
		if r.URL.Path == "/repos/acme/tools/git/commits/"+c {
			io.WriteString(w, `{"sha":"`+c+`"}`)
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	io.WriteString(w, `{"message":"Not Found"}`)
}

// set changes the fake under its lock.
func (p *publicGitHub) set(f func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f()
}

// count is how many requests so far start with prefix.
func (p *publicGitHub) count(prefix string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, r := range p.requests {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

// checkAnonymous reports a request to the public hosts with an Authorization header, a
// cookie or the token the fake GitHub mints anywhere in its headers.
func (p *publicGitHub) checkAnonymous(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, h := range p.headers {
		b, _ := json.Marshal(h)
		if h.Get("Authorization") != "" || h.Get("Cookie") != "" || strings.Contains(string(b), ghToken) {
			t.Errorf("the request %s has a credential", p.requests[i])
		}
	}
}

// readPublic is a read-public call's members.
func readPublic(resource, path, at string) string {
	return `"resource_ref":"` + resource + `","path":"` + path + `","at":"` + at + `"`
}

// TestResolveAddsPublicFromTheAnonymousCheck pins public in resolve: a repository an
// installation covers keeps grant_ref and resource_ref and gets public: true and the
// public_ref github.com/owner/name in lower case when the anonymous check finds it
// public; one no grant covers is public: true with that ref as resource_ref and
// public_ref, and no grant_ref; one neither covered nor public is covered: false. A
// result without public has no public_ref. When the anonymous check fails, each result
// is as without public. No request to the public hosts has a credential.
func TestResolveAddsPublicFromTheAnonymousCheck(t *testing.T) {
	rig := newCallsRig(t)
	rig.pub.set(func() {
		rig.pub.public = map[string]bool{"acme/widgets": true, "acme/tools": true, "octo-org/tools": true}
	})
	addresses := []string{
		"https://github.com/acme/widgets",
		"https://github.com/ACME/Tools.git",
		"https://github.com/acme/gadgets",
		"https://github.com/acme/secret",
		"https://github.com/acme/renamed",
		"git@github.com:acme/tools.git",
		"https://github.com/octo-org/tools",
	}
	resolve := func() []contracts.Resolved {
		t.Helper()
		b, _ := json.Marshal(addresses)
		got := rig.send(t, signedCall{path: contracts.ResolvePath}, rig.callBody(`"addresses":`+string(b)))
		checkAnswer(t, got, 200, "resolve-answer.schema.json", "")
		var ans contracts.ResolveAnswer
		json.Unmarshal(got.body, &ans)
		if len(ans.Results) != len(addresses) {
			t.Fatalf("answered %s", shown(got.body))
		}
		// Each result has the member public_ref exactly when it has public.
		var raw struct {
			Results []map[string]json.RawMessage `json:"results"`
		}
		json.Unmarshal(got.body, &raw)
		for i, r := range raw.Results {
			_, public := r["public"]
			if _, ref := r["public_ref"]; ref != public {
				t.Errorf("%s: public %v, public_ref %v; want both or neither", addresses[i], public, ref)
			}
		}
		return ans.Results
	}
	no := false
	want := []contracts.Resolved{
		{Address: addresses[0], GrantRef: "42", ResourceRef: widgetsRef, Public: true, PublicRef: "github.com/acme/widgets"},
		{Address: addresses[1], ResourceRef: "github.com/acme/tools", Public: true, PublicRef: "github.com/acme/tools"},
		{Address: addresses[2], GrantRef: "42", ResourceRef: gadgetsRef},
		{Address: addresses[3], Covered: &no},
		{Address: addresses[4], Covered: &no},
		{Address: addresses[5], Covered: &no},
		{Address: addresses[6], ResourceRef: "github.com/octo-org/tools", Public: true, PublicRef: "github.com/octo-org/tools"},
	}
	same := func(a, b contracts.Resolved) bool {
		return a.Address == b.Address && a.GrantRef == b.GrantRef && a.ResourceRef == b.ResourceRef && a.Public == b.Public && a.PublicRef == b.PublicRef && (a.Covered == nil) == (b.Covered == nil)
	}
	for i, r := range resolve() {
		if !same(r, want[i]) {
			t.Errorf("%s: %+v, want %+v", addresses[i], r, want[i])
		}
	}
	// The check failing is the covered result alone, without public.
	rig.calls.publicMu.Lock()
	clear(rig.calls.publicSeen)
	rig.calls.publicMu.Unlock()
	rig.pub.set(func() { rig.pub.gitStatus = http.StatusBadGateway })
	for i, r := range resolve() {
		w := want[i]
		w.Public, w.PublicRef = false, ""
		if w.GrantRef == "" {
			w.ResourceRef, w.Covered = "", &no
		}
		if !same(r, w) {
			t.Errorf("the check failing, %s: %+v, want %+v", addresses[i], r, w)
		}
	}
	if !strings.Contains(rig.log.String(), "checking whether a repository to resolve is public") {
		t.Errorf("no line for the failed check: %s", rig.log.String())
	}
	if rig.pub.count("git ") == 0 {
		t.Error("no anonymous check was sent")
	}
	if rig.pub.count("raw ")+rig.pub.count("api ") != 0 {
		t.Error("resolve read a file or a commit")
	}
	rig.pub.checkAnonymous(t)
}

// TestReadPublicReadsAPublicFile pins read-public: the file's text at the commit HEAD, a
// branch, a tag or a commit id names, with that commit as resolved_at; found: false for
// a path the commit has no file at, a directory among them, with no REST request for a
// name and one for a commit id; 404 version_not_found for a name the ref list does not
// have and for a commit id the REST check does not find; 409 document_not_text; and
// 400 invalid_request for a path that breaks the schema. No request has a credential.
func TestReadPublicReadsAPublicFile(t *testing.T) {
	rig := newCallsRig(t)
	rig.pub.set(func() { rig.pub.public = map[string]bool{"acme/tools": true} })
	send := func(members string) callAnswer {
		return rig.send(t, signedCall{path: contracts.ReadPublicPath}, rig.callBody(members))
	}
	const tools = "github.com/acme/tools"
	for at, want := range map[string]string{
		"HEAD":           `{"version":1,"revision":1,"content":"# Tools\n","resolved_at":"` + widgetsCommit + `"}`,
		"main":           `{"version":1,"revision":1,"content":"# Tools\n","resolved_at":"` + widgetsCommit + `"}`,
		"v1.0":           `{"version":1,"revision":1,"content":"# Tools\n","resolved_at":"` + widgetsCommit + `"}`,
		"refs/tags/v1.0": `{"version":1,"revision":1,"content":"# Tools\n","resolved_at":"` + widgetsCommit + `"}`,
		widgetsCommit:    `{"version":1,"revision":1,"content":"# Tools\n","resolved_at":"` + widgetsCommit + `"}`,
		"dev":            `{"version":1,"revision":1,"content":"# Dev\n","resolved_at":"` + devCommit + `"}`,
	} {
		got := send(readPublic(tools, "README.md", at))
		checkAnswer(t, got, 200, "read-answer.schema.json", "")
		if string(got.body) != want {
			t.Errorf("at %s: answered %s, want %s", at, got.body, want)
		}
	}
	got := send(readPublic(tools, "docs/a b.md", "main"))
	if checkAnswer(t, got, 200, "read-answer.schema.json", ""); !strings.Contains(string(got.body), `"content":"spaced"`) {
		t.Errorf("a path with a space: %s", got.body)
	}
	for _, path := range []string{"missing.md", "docs"} {
		got := send(readPublic(tools, path, "main"))
		checkAnswer(t, got, 200, "read-answer.schema.json", "")
		if want := `{"version":1,"revision":1,"found":false,"resolved_at":"` + widgetsCommit + `"}`; string(got.body) != want {
			t.Errorf("%s at main: answered %s, want %s", path, got.body, want)
		}
	}
	if n := rig.pub.count("api "); n != 0 {
		t.Errorf("a missing file at a branch sent %d REST requests, want none", n)
	}
	got = send(readPublic(tools, "missing.md", devCommit))
	checkAnswer(t, got, 200, "read-answer.schema.json", "")
	if want := `{"version":1,"revision":1,"found":false,"resolved_at":"` + devCommit + `"}`; string(got.body) != want {
		t.Errorf("a missing file at a commit: answered %s, want %s", got.body, want)
	}
	if n := rig.pub.count("api /repos/acme/tools/git/commits/" + devCommit); n != 1 {
		t.Errorf("a missing file at a commit sent %d REST checks, want 1", n)
	}
	checkAnswer(t, send(readPublic(tools, "README.md", "nothing")), http.StatusNotFound, "refusal.schema.json", codeVersionNotFound)
	checkAnswer(t, send(readPublic(tools, "README.md", missingCommit)), http.StatusNotFound, "refusal.schema.json", codeVersionNotFound)
	checkAnswer(t, send(readPublic(tools, "README.md", "refs/heads/nothing")), http.StatusNotFound, "refusal.schema.json", codeVersionNotFound)
	for _, path := range []string{"big.txt", "bin"} {
		checkAnswer(t, send(readPublic(tools, path, "main")), http.StatusConflict, "refusal.schema.json", codeDocumentNotText)
	}
	for _, path := range []string{"../README.md", "/README.md", "docs/", "a//b", "a/./b"} {
		checkAnswer(t, send(readPublic(tools, path, "main")), http.StatusBadRequest, "refusal.schema.json", codeInvalidRequest)
	}
	for _, at := range []string{"main?x=1", "main#x", "a b", "%2e%2e"} {
		checkAnswer(t, send(readPublic(tools, "README.md", at)), http.StatusBadRequest, "refusal.schema.json", codeInvalidRequest)
	}
	// A body with grant_ref breaks read-public's schema.
	checkAnswer(t, send(`"grant_ref":"42",`+readPublic(tools, "README.md", "main")), http.StatusBadRequest, "refusal.schema.json", codeInvalidRequest)
	rig.pub.checkAnonymous(t)
	if rig.gh.mintsSoFar() != nil {
		t.Errorf("read-public minted %q", rig.gh.mintsSoFar())
	}
}

// TestReadPublicReturnsTheRefusalsInTheContractsOrder pins read-public's refusals: 403
// resource_not_public for a private repository, one that does not exist, one that
// moved, and a resource_ref of another form, before 404 version_not_found; and 503
// source_unavailable for a failing source and a rate limit on each host.
func TestReadPublicReturnsTheRefusalsInTheContractsOrder(t *testing.T) {
	rig := newCallsRig(t)
	rig.pub.set(func() { rig.pub.public = map[string]bool{"acme/tools": true, "acme/widgets": true} })
	send := func(members string) callAnswer {
		return rig.send(t, signedCall{path: contracts.ReadPublicPath}, rig.callBody(members))
	}
	for _, ref := range []string{
		"github.com/acme/secret", "github.com/acme/gone", "github.com/acme/renamed",
		widgetsRef, "github.com/Acme/tools", "github.com/acme/tools.git", "github.com/acme/tools/x",
		"gitlab.com/acme/tools", "github.com.example.com/acme/tools", "github.com/acme/..",
	} {
		for _, at := range []string{"main", "nothing", missingCommit} {
			checkAnswer(t, send(readPublic(ref, "README.md", at)), http.StatusForbidden, "refusal.schema.json", codeResourceNotPublic)
		}
	}
	if n := rig.pub.count("raw ") + rig.pub.count("api "); n != 0 {
		t.Errorf("a resource that is not public sent %d file or commit requests", n)
	}
	for _, c := range []struct {
		host   string
		status int
		header http.Header
		at     string
	}{
		{"git", http.StatusInternalServerError, nil, "main"},
		{"git", http.StatusTooManyRequests, nil, "main"},
		{"git", http.StatusForbidden, http.Header{"Retry-After": {"30"}}, "main"},
		{"raw", http.StatusTooManyRequests, nil, "main"},
		{"raw", http.StatusForbidden, nil, "main"},
		{"raw", http.StatusBadGateway, nil, "main"},
		{"api", http.StatusForbidden, http.Header{"X-Ratelimit-Remaining": {"0"}}, missingCommit},
		{"api", http.StatusTooManyRequests, nil, missingCommit},
		{"api", http.StatusInternalServerError, nil, missingCommit},
	} {
		rig.calls.publicMu.Lock()
		clear(rig.calls.publicSeen)
		rig.calls.publicMu.Unlock()
		rig.pub.set(func() {
			rig.pub.gitStatus, rig.pub.rawStatus, rig.pub.apiStatus, rig.pub.header = 0, 0, 0, c.header
			switch c.host {
			case "git":
				rig.pub.gitStatus = c.status
			case "raw":
				rig.pub.rawStatus = c.status
			case "api":
				rig.pub.apiStatus = c.status
			}
		})
		if got := send(readPublic("github.com/acme/tools", "README.md", c.at)); got.status != http.StatusServiceUnavailable {
			t.Errorf("%s %d %v: answered %d %s, want 503", c.host, c.status, c.header, got.status, got.body)
		} else {
			checkAnswer(t, got, http.StatusServiceUnavailable, "refusal.schema.json", codeSourceUnavailable)
		}
	}
	if !strings.Contains(rig.log.String(), "a request to GitHub for a read-public call failed") {
		t.Errorf("no line for a failed read: %s", rig.log.String())
	}
	rig.pub.checkAnonymous(t)
}

// TestReadPublicKeepsTheAnonymousCheckForAMinute pins the cache of the anonymous ref
// list: within 60 seconds, a read at a name read before and a read at a commit id send
// no ref list request, and a repository that turned private reads as public; a new name
// sends one; past 60 seconds, the list is read again. A repository that was not public
// stays so within 60 seconds.
func TestReadPublicKeepsTheAnonymousCheckForAMinute(t *testing.T) {
	rig := newCallsRig(t)
	var offset atomic.Int64
	rig.calls.now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	rig.pub.set(func() { rig.pub.public = map[string]bool{"acme/tools": true} })
	send := func(ref, at string) callAnswer {
		return rig.send(t, signedCall{path: contracts.ReadPublicPath}, rig.callBody(readPublic(ref, "README.md", at)))
	}
	refsRequests := func() int { return rig.pub.count("git /acme/tools.git/info/refs") }
	checkAnswer(t, send("github.com/acme/tools", "main"), 200, "read-answer.schema.json", "")
	checkAnswer(t, send("github.com/acme/tools", "main"), 200, "read-answer.schema.json", "")
	checkAnswer(t, send("github.com/acme/tools", widgetsCommit), 200, "read-answer.schema.json", "")
	if n := refsRequests(); n != 1 {
		t.Errorf("three reads within a minute sent %d ref list requests, want 1", n)
	}
	checkAnswer(t, send("github.com/acme/tools", "v1.0"), 200, "read-answer.schema.json", "")
	if n := refsRequests(); n != 2 {
		t.Errorf("a new name sent %d ref list requests in all, want 2", n)
	}
	rig.pub.set(func() { rig.pub.public = map[string]bool{} })
	offset.Store(int64(59 * time.Second))
	if got := send("github.com/acme/tools", "main"); got.status != 200 {
		t.Errorf("within a minute, a repository that turned private: %d %s, want the kept 200", got.status, got.body)
	}
	offset.Store(int64(61 * time.Second))
	checkAnswer(t, send("github.com/acme/tools", "main"), http.StatusForbidden, "refusal.schema.json", codeResourceNotPublic)
	if n := refsRequests(); n != 3 {
		t.Errorf("past a minute: %d ref list requests in all, want 3", n)
	}
	// Not public is kept too.
	rig.pub.set(func() { rig.pub.public = map[string]bool{"acme/tools": true} })
	checkAnswer(t, send("github.com/acme/tools", "main"), http.StatusForbidden, "refusal.schema.json", codeResourceNotPublic)
	offset.Store(int64(122 * time.Second))
	checkAnswer(t, send("github.com/acme/tools", "main"), 200, "read-answer.schema.json", "")
	// An error is never kept.
	rig.pub.set(func() { rig.pub.gitStatus = http.StatusBadGateway })
	offset.Store(int64(183 * time.Second))
	checkAnswer(t, send("github.com/acme/tools", "main"), http.StatusServiceUnavailable, "refusal.schema.json", codeSourceUnavailable)
	rig.pub.set(func() { rig.pub.gitStatus = 0 })
	checkAnswer(t, send("github.com/acme/tools", "main"), 200, "read-answer.schema.json", "")
	// The cache keeps maxPublicSeen repositories at most.
	rig.calls.publicMu.Lock()
	for i := range maxPublicSeen + 10 {
		rig.calls.publicSeen[fmt.Sprintf("github.com/acme/r%d", i)] = publicEntry{read: rig.calls.clock()}
	}
	rig.calls.publicMu.Unlock()
	checkAnswer(t, send("github.com/acme/other", "main"), http.StatusForbidden, "refusal.schema.json", codeResourceNotPublic)
	rig.calls.publicMu.Lock()
	if n := len(rig.calls.publicSeen); n > maxPublicSeen+10 || n == 0 {
		t.Errorf("the cache has %d entries", n)
	}
	rig.calls.publicMu.Unlock()
}

// TestReadPublicIsCheckedAsEveryCall pins the call checks for read-public: an unsigned
// call and a replay get the unsigned 401, and the answer is signed.
func TestReadPublicIsCheckedAsEveryCall(t *testing.T) {
	rig := newCallsRig(t)
	rig.pub.set(func() { rig.pub.public = map[string]bool{"acme/tools": true} })
	body := rig.callBody(readPublic("github.com/acme/tools", "README.md", "main"))
	checkUnsigned(t, "signed by another key", rig.send(t, signedCall{path: contracts.ReadPublicPath, signer: newKey(t)}, body), http.StatusUnauthorized, codeUnauthorized)
	checkAnswer(t, rig.send(t, signedCall{path: contracts.ReadPublicPath}, body), 200, "read-answer.schema.json", "")
	checkUnsigned(t, "a replay", rig.send(t, signedCall{path: contracts.ReadPublicPath}, body), http.StatusUnauthorized, codeUnauthorized)
	old := callBodyAt(time.Now().Add(-301*time.Second), readPublic("github.com/acme/tools", "README.md", "main"))
	checkUnsigned(t, "an old call", rig.send(t, signedCall{path: contracts.ReadPublicPath}, old), http.StatusUnauthorized, codeUnauthorized)
	if !strings.Contains(rig.log.String(), `"call":"read-public"`) {
		t.Errorf("no line names the call read-public: %s", rig.log.String())
	}
}
