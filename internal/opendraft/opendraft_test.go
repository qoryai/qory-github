package opendraft

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	password = "pw-7f3a9c-never-printed"
	ref      = "qory/wi_01HZX"
	// repoA has 21 characters, the length the stderr lines are kept within 100 for.
	repoA = "acme-corp/widgets-app"
	repoB = "acme-corp/gadgets"
)

// Commit ids of the submissions: the base, the two commits in commits[], and the head.
var (
	baseCommit = strings.Repeat("a", 40)
	midCommit  = strings.Repeat("b", 40)
	fixCommit  = strings.Repeat("d", 40)
	headCommit = strings.Repeat("c", 40)
)

func script(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not on PATH; CI has it")
	}
	p, err := filepath.Abs("../../modules/github/bin/open-draft")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// call is one request that the stand-in GitHub received.
type call struct {
	Method string
	Path   string
	Query  string
	Body   map[string]any
}

// pull is an open pull request of the stand-in GitHub. HeadRepo is the full name of the
// head's repository: empty is the pull request's repository, and "-" is null, a
// deleted fork.
type pull struct {
	Number   int
	Title    string
	Body     string
	Head     string
	HeadRepo string
	Base     string
	Draft    bool
}

// response is a status, headers and a body that the stand-in GitHub returns as they are.
type response struct {
	status int
	body   string
	header map[string]string
}

// github is a stand-in for api.github.com: pull requests per repository, and responses
// to return for a method on a repository in place of the stand-in's.
type github struct {
	mu    sync.Mutex
	calls []call
	pulls map[string][]*pull
	// fixed are the responses by "METHOD owner/name", such as "POST acme-corp/gadgets".
	fixed  map[string]response
	badURL bool
}

func (g *github) setPulls(repo string, pulls ...*pull) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pulls[repo] = pulls
}

func (g *github) pullsOf(repo string) []pull {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []pull
	for _, p := range g.pulls[repo] {
		out = append(out, *p)
	}
	return out
}

func (g *github) markReady(repo string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, p := range g.pulls[repo] {
		p.Draft = false
	}
}

func (g *github) fix(key string, status int, body string) {
	g.fixHeader(key, status, body, nil)
}

func (g *github) fixHeader(key string, status int, body string, header map[string]string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fixed[key] = response{status, body, header}
}

var pullsPath = regexp.MustCompile(`^/repos/([^/]+/[^/]+)/pulls(?:/(\d+))?$`)

func (g *github) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c := call{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery}
	if r.Body != nil {
		raw, _ := io.ReadAll(r.Body)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &c.Body); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
		}
	}
	g.calls = append(g.calls, c)
	for h, want := range map[string]string{
		"Accept": "application/vnd.github+json", "X-Github-Api-Version": "2022-11-28",
		"User-Agent": "qory-github-open-draft",
	} {
		if r.Header.Get(h) != want {
			http.Error(w, "header "+h, http.StatusBadRequest)
			return
		}
	}
	if r.Header.Get("Authorization") != "" {
		http.Error(w, "the program sent a token", http.StatusBadRequest)
		return
	}
	m := pullsPath.FindStringSubmatch(r.URL.Path)
	if m == nil {
		http.NotFound(w, r)
		return
	}
	repo := m[1]
	if f, ok := g.fixed[r.Method+" "+repo]; ok {
		w.Header().Set("Content-Type", "application/json")
		for k, v := range f.header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, f.body)
		return
	}
	render := func(p *pull) map[string]any {
		u := "https://github.com/" + repo + "/pull/" + strconv.Itoa(p.Number)
		if g.badURL {
			u = "https://github.com/someone/else/pull/" + strconv.Itoa(p.Number)
		}
		var headRepo any = map[string]any{"full_name": repo}
		switch p.HeadRepo {
		case "":
		case "-":
			headRepo = nil
		default:
			headRepo = map[string]any{"full_name": p.HeadRepo}
		}
		return map[string]any{
			"number": p.Number, "html_url": u, "title": p.Title, "body": p.Body, "draft": p.Draft, "state": "open",
			"head": map[string]any{"ref": p.Head, "repo": headRepo}, "base": map[string]any{"ref": p.Base},
		}
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && m[2] == "":
		// Every open pull request, whatever the head parameter: the program filters.
		out := []map[string]any{}
		for _, p := range g.pulls[repo] {
			out = append(out, render(p))
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodPost && m[2] == "":
		n := 34
		for _, p := range g.pulls[repo] {
			n = max(n, p.Number+1)
		}
		p := &pull{Number: n, Title: c.Body["title"].(string),
			Body: c.Body["body"].(string), Head: c.Body["head"].(string), Base: c.Body["base"].(string),
			Draft: c.Body["draft"] == true}
		g.pulls[repo] = append(g.pulls[repo], p)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(render(p))
	case r.Method == http.MethodPatch && m[2] != "":
		n, _ := strconv.Atoi(m[2])
		for _, p := range g.pulls[repo] {
			if p.Number == n {
				p.Title, p.Body = c.Body["title"].(string), c.Body["body"].(string)
				_ = json.NewEncoder(w).Encode(render(p))
				return
			}
		}
		http.NotFound(w, r)
	default:
		http.Error(w, "unexpected", http.StatusMethodNotAllowed)
	}
}

func (g *github) recorded() []call {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]call(nil), g.calls...)
}

// env is a stand-in GitHub behind a stand-in proxy, and the files of one run.
type env struct {
	gh     *github
	dir    string
	socket string
	caFile string
	mu     sync.Mutex
	// tunnels counts the connections the proxy accepted; connectStatus, when set, is
	// the status the proxy returns to every CONNECT. connectReply, when set, is written
	// in one write in place of the proxy's response; with closeAfter, the proxy then
	// closes the connection, and without it, waits for the program to close it.
	tunnels       int
	connectStatus int
	// cert is the stand-in GitHub's certificate, see [env.issue].
	cert         *tls.Certificate
	connectReply string
	closeAfter   bool
	// vars are environment variables that run adds after the others.
	vars []string
}

func (e *env) tunnelCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tunnels
}

// newEnv starts the stand-in GitHub with a certificate for api.github.com from a CA in
// caFile, and a CONNECT proxy on a unix socket that requires the user qory and password.
func newEnv(t *testing.T) *env {
	t.Helper()
	dir, err := os.MkdirTemp("", "od")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	e := &env{gh: &github{pulls: map[string][]*pull{}, fixed: map[string]response{}}, dir: dir,
		socket: filepath.Join(dir, "p.sock"), caFile: filepath.Join(dir, "ca.pem")}

	e.issue(x509.KeyUsageCertSign)
	srv := httptest.NewUnstartedServer(e.gh)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.cert, nil
	}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	ln, err := net.Listen("unix", e.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	upstream := srv.Listener.Addr().String()
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("qory:"+password))
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			e.mu.Lock()
			e.tunnels++
			e.mu.Unlock()
			go e.proxy(c, upstream, auth)
		}
	}()
	return e
}

func (e *env) proxy(c net.Conn, upstream, auth string) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect || req.Host != "api.github.com:443" {
		_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		return
	}
	e.mu.Lock()
	status, reply, closeAfter := e.connectStatus, e.connectReply, e.closeAfter
	e.mu.Unlock()
	if reply != "" {
		_, _ = io.WriteString(c, reply)
		if !closeAfter {
			_, _ = io.Copy(io.Discard, br)
		}
		return
	}
	if status != 0 {
		_, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status))
		return
	}
	if req.Header.Get("Proxy-Authorization") != auth {
		_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		return
	}
	up, err := net.Dial("tcp", upstream)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer func() { _ = up.Close() }()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// issue makes a CA whose certificate has the key usage caUsage, writes it to caFile,
// and sets the stand-in GitHub's certificate to one for api.github.com that the CA
// signed.
func (e *env) issue(caUsage x509.KeyUsage) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "stand-in CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: caUsage}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		panic(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "api.github.com"},
		DNSNames: []string{"api.github.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(e.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		panic(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cert = &tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

// otherCA is the PEM of a CA that did not sign the stand-in's certificate.
func otherCA() []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "other CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// result is one run of the program.
type result struct {
	code           int
	stdout, stderr string
}

// run runs the program with the submission and bases files in the env's folder. A nil
// bases leaves the bases file out; the extra variables override the defaults.
func (e *env) run(t *testing.T, submission any, bases any, extra ...string) (result, map[string]any) {
	t.Helper()
	file := filepath.Join(e.dir, "submission.json")
	writeJSON(t, file, submission)
	vars := []string{"PATH=" + os.Getenv("PATH"), "QORY_SUBMISSION_FILE=" + file,
		"QORY_PROXY_SOCKET=" + e.socket, "QORY_PROXY_PASSWORD=" + password, "SSL_CERT_FILE=" + e.caFile}
	if bases != nil {
		bf := filepath.Join(e.dir, "bases.json")
		writeJSON(t, bf, bases)
		vars = append(vars, "QORY_SUBMIT_BASES="+bf)
	}
	return e.runRaw(t, file, append(append(vars, extra...), e.vars...))
}

func (e *env) runRaw(t *testing.T, file string, vars []string) (result, map[string]any) {
	t.Helper()
	cmd := exec.Command(script(t))
	cmd.Env = vars
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	r := result{stdout: out.String(), stderr: errOut.String()}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		r.code = exit.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	t.Logf("exit %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	if strings.Contains(r.stdout+r.stderr, password) {
		t.Errorf("the output contains the proxy password:\n%s%s", r.stdout, r.stderr)
	}
	for _, line := range strings.Split(strings.TrimSpace(r.stderr), "\n") {
		// A line with a file path may pass 100 characters; the fix stays at the front.
		if utf8.RuneCountInString(line) > 100 && !strings.Contains(line, e.dir) {
			t.Errorf("stderr line is %d characters, over 100: %s", len(line), line)
		}
	}
	var got map[string]any
	if raw, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(raw, &got)
	}
	if _, err := os.Lstat(file + ".tmp"); err == nil {
		t.Errorf("%s.tmp is left behind", file)
	}
	return r, got
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	var raw []byte
	if s, ok := v.(string); ok {
		raw = []byte(s)
	} else {
		var err error
		if raw, err = json.MarshalIndent(v, "", "  "); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func repo(path, system string) map[string]any {
	return map[string]any{"system": system, "path": path, "commit": headCommit,
		"base":    map[string]any{"commit": baseCommit},
		"commits": []any{map[string]any{"commit": midCommit, "step": "deliverable:d-1"}, map[string]any{"commit": fixCommit, "step": "fix:f1"}},
		"draft":   map[string]any{"none": "not-passed"}}
}

func submission(verdict, title string, repos ...map[string]any) map[string]any {
	list := make([]any, len(repos))
	for i, r := range repos {
		list[i] = r
	}
	s := map[string]any{"ref": ref, "verdict": verdict, "repositories": list}
	if title != "" {
		s["text"] = map[string]any{"title": title, "description": "What changed and why."}
	}
	return s
}

func bases(paths ...string) []any {
	out := []any{}
	for _, p := range paths {
		out = append(out, map[string]any{"system": "github.com", "path": p, "base": "main"})
	}
	return out
}

func entry(s map[string]any, i int) map[string]any {
	return s["repositories"].([]any)[i].(map[string]any)
}

func link(path, commit string) string {
	return "https://github.com/" + path + "/commit/" + commit
}

// checkLinks checks the four commit links of a github.com entry made by repo.
func checkLinks(t *testing.T, r map[string]any, path string) {
	t.Helper()
	if r["commit_url"] != link(path, headCommit) {
		t.Errorf("commit_url = %v", r["commit_url"])
	}
	if b := r["base"].(map[string]any); b["commit_url"] != link(path, baseCommit) {
		t.Errorf("base.commit_url = %v", b["commit_url"])
	}
	for i, want := range []string{midCommit, fixCommit} {
		c := r["commits"].([]any)[i].(map[string]any)
		if c["commit_url"] != link(path, want) {
			t.Errorf("commits[%d].commit_url = %v", i, c["commit_url"])
		}
	}
}

func TestManifestDeclaresTheProgram(t *testing.T) {
	raw, err := os.ReadFile("../../modules/github/qory-module.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		APIVersion    string `yaml:"apiVersion"`
		Name          string `yaml:"name"`
		SubmitProgram struct {
			Command []string `yaml:"command"`
		} `yaml:"submit_program"`
	}
	if err := yaml.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.APIVersion != "qory.dev/v1alpha1" || m.Name != "github" ||
		!reflect.DeepEqual(m.SubmitProgram.Command, []string{"bin/open-draft"}) {
		t.Fatalf("manifest = %+v", m)
	}
	fi, err := os.Stat("../../modules/github/bin/open-draft")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o111 != 0o111 {
		t.Errorf("bin/open-draft mode = %v, want executable", fi.Mode())
	}
}

func TestFirstPassedRunOpensDraft(t *testing.T) {
	e := newEnv(t)
	r, got := e.run(t, submission("passed", "Add the widget", repo(repoA, "github.com")), bases(repoA))
	if r.code != 0 {
		t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
	}
	calls := e.gh.recorded()
	if len(calls) != 2 || calls[0].Method != "GET" || calls[1].Method != "POST" {
		t.Fatalf("calls = %+v", calls)
	}
	if calls[0].Path != "/repos/"+repoA+"/pulls" || calls[0].Query != "head=acme-corp%3Aqory%2Fwi_01HZX&state=open&per_page=100" {
		t.Errorf("GET = %+v", calls[0])
	}
	want := map[string]any{"title": "Add the widget", "body": "What changed and why.", "head": ref, "base": "main", "draft": true}
	if !reflect.DeepEqual(calls[1].Body, want) {
		t.Errorf("POST body = %v, want %v", calls[1].Body, want)
	}
	url := "https://github.com/" + repoA + "/pull/34"
	wantDraft := map[string]any{"number": 34.0, "url": url, "title": "Add the widget", "state": "draft", "action": "opened"}
	if d := entry(got, 0)["draft"]; !reflect.DeepEqual(d, wantDraft) {
		t.Errorf("draft = %v, want %v", d, wantDraft)
	}
	checkLinks(t, entry(got, 0), repoA)
	if r.stdout != url+" opened\n" {
		t.Errorf("stdout = %q", r.stdout)
	}
}

func TestLaterPassedRunUpdatesSameDraft(t *testing.T) {
	e := newEnv(t)
	if r, _ := e.run(t, submission("passed", "First title", repo(repoA, "github.com")), bases(repoA)); r.code != 0 {
		t.Fatalf("first run: exit %d, stderr %q", r.code, r.stderr)
	}
	// A member marks the draft ready for review between the runs.
	e.gh.markReady(repoA)
	r, got := e.run(t, submission("passed", "Second title", repo(repoA, "github.com")), bases(repoA))
	if r.code != 0 {
		t.Fatalf("second run: exit %d, stderr %q", r.code, r.stderr)
	}
	calls := e.gh.recorded()[2:]
	if len(calls) != 2 || calls[1].Method != "PATCH" || calls[1].Path != "/repos/"+repoA+"/pulls/34" {
		t.Fatalf("calls = %+v", calls)
	}
	if want := map[string]any{"title": "Second title", "body": "What changed and why."}; !reflect.DeepEqual(calls[1].Body, want) {
		t.Errorf("PATCH body = %v, want only title and body", calls[1].Body)
	}
	url := "https://github.com/" + repoA + "/pull/34"
	wantDraft := map[string]any{"number": 34.0, "url": url, "title": "Second title", "state": "open", "action": "updated"}
	if d := entry(got, 0)["draft"]; !reflect.DeepEqual(d, wantDraft) {
		t.Errorf("draft = %v, want %v", d, wantDraft)
	}
	if n := len(e.gh.pullsOf(repoA)); n != 1 {
		t.Errorf("%d pull requests, want 1", n)
	}
	if r.stdout != url+" updated\n" {
		t.Errorf("stdout = %q", r.stdout)
	}
}

// others are open pull requests that the program must not update: another branch's,
// one into another base, one from a fork with the same branch name, and one from a
// deleted fork.
func others() []*pull {
	return []*pull{
		{Number: 41, Head: "qory/wi_OTHER", Base: "main"},
		{Number: 43, Head: ref, Base: "dev"},
		{Number: 44, Head: ref, HeadRepo: "fork-owner/widgets-app", Base: "main"},
		{Number: 45, Head: ref, HeadRepo: "-", Base: "main"},
	}
}

func TestOnlyTheRunsPullRequestIsUpdated(t *testing.T) {
	for _, tc := range []struct {
		name   string
		pulls  []*pull
		method string
		path   string
	}{
		{"the run's among others", append(others(), &pull{Number: 42, Head: ref, HeadRepo: "ACME-Corp/Widgets-App", Base: "main"}),
			"PATCH", "/repos/" + repoA + "/pulls/42"},
		{"only others", others(), "POST", "/repos/" + repoA + "/pulls"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			for _, p := range tc.pulls {
				p.Title, p.Body, p.Draft = "Old", "Old", true
			}
			e.gh.setPulls(repoA, tc.pulls...)
			r, _ := e.run(t, submission("passed", "Add the widget", repo(repoA, "github.com")), bases(repoA))
			if r.code != 0 {
				t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
			}
			calls := e.gh.recorded()
			if len(calls) != 2 || calls[1].Method != tc.method || calls[1].Path != tc.path {
				t.Fatalf("calls = %+v, want %s %s", calls, tc.method, tc.path)
			}
		})
	}
}

func TestTwoOfTheRunsPullRequests(t *testing.T) {
	e := newEnv(t)
	e.gh.setPulls(repoA, append(others(),
		&pull{Number: 42, Head: ref, Base: "main", Title: "Old", Body: "Old"},
		&pull{Number: 47, Head: ref, Base: "main", Title: "Old", Body: "Old"})...)
	r, got := e.run(t, submission("passed", "Add the widget", repo(repoA, "github.com")), bases(repoA))
	want := "Close all but one of the run's open pull requests on " + repoA + ": GET pulls listed 2\n"
	if r.code != 1 || r.stderr != want {
		t.Fatalf("exit %d, stderr %q; want 1 and %q", r.code, r.stderr, want)
	}
	if calls := e.gh.recorded(); len(calls) != 1 {
		t.Errorf("calls = %+v, want the GET alone", calls)
	}
	checkLinks(t, entry(got, 0), repoA)
}

func TestLinkInAnotherCase(t *testing.T) {
	e := newEnv(t)
	e.gh.fix("POST "+repoA, 201, `{"number":34,"html_url":"https://github.com/ACME-Corp/Widgets-App/pull/34","title":"Add the widget","draft":true,"state":"open"}`)
	r, got := e.run(t, submission("passed", "Add the widget", repo(repoA, "github.com")), bases(repoA))
	url := "https://github.com/" + repoA + "/pull/34"
	if r.code != 0 || r.stdout != url+" opened\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
	if d := entry(got, 0)["draft"].(map[string]any); d["url"] != url {
		t.Errorf("draft url = %v, want %s", d["url"], url)
	}
}

func TestTitleOf256CodePoints(t *testing.T) {
	e := newEnv(t)
	title := strings.Repeat("\U0001F600", 256)
	r, got := e.run(t, submission("passed", title, repo(repoA, "github.com")), bases(repoA))
	if r.code != 0 {
		t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
	}
	if d := entry(got, 0)["draft"].(map[string]any); d["title"] != title {
		t.Errorf("draft title = %v", d["title"])
	}
}

func TestFailedWriteLeavesNoTmp(t *testing.T) {
	e := newEnv(t)
	file := filepath.Join(e.dir, "submission.json")
	// A submission.json.tmp that links to a missing folder makes the write fail, also for
	// root; the program removes the link.
	if err := os.Symlink(filepath.Join(e.dir, "missing", "x"), file+".tmp"); err != nil {
		t.Fatal(err)
	}
	s := submission("changes-requested", "Add the widget", repo(repoA, "github.com"))
	r, _ := e.run(t, s, nil)
	want := "Make the folder of QORY_SUBMISSION_FILE writable: writing " + file + " failed (ENOENT)\n"
	if r.code != 1 || r.stderr != want {
		t.Errorf("exit %d, stderr %q; want 1 and %q", r.code, r.stderr, want)
	}
	before, _ := json.MarshalIndent(s, "", "  ")
	if after, _ := os.ReadFile(file); !bytes.Equal(before, after) {
		t.Errorf("the file changed:\n%s", after)
	}
}

// TestFourCommitsGetLinks runs a submission with four commits, the base, two in commits[]
// and the head, for every verdict: each commit gets its link, and only the passed round
// calls GitHub.
func TestFourCommitsGetLinks(t *testing.T) {
	for _, verdict := range []string{"passed", "changes-requested", "escalate", "none"} {
		t.Run(verdict, func(t *testing.T) {
			e := newEnv(t)
			r, got := e.run(t, submission(verdict, "Add the widget", repo(repoA, "github.com")), bases(repoA))
			if r.code != 0 {
				t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
			}
			checkLinks(t, entry(got, 0), repoA)
			if verdict == "passed" {
				if e.tunnelCount() == 0 || len(e.gh.recorded()) != 2 {
					t.Errorf("%d tunnels and %d calls after a passed round, want the GET and the POST", e.tunnelCount(), len(e.gh.recorded()))
				}
				return
			}
			if n := e.tunnelCount(); n != 0 || len(e.gh.recorded()) != 0 {
				t.Errorf("%d tunnels and %d calls after a round that did not pass, want none", n, len(e.gh.recorded()))
			}
			if d := entry(got, 0)["draft"]; !reflect.DeepEqual(d, map[string]any{"none": "not-passed"}) {
				t.Errorf("draft = %v, want it unchanged", d)
			}
			if r.stdout != "" || r.stderr != "" {
				t.Errorf("output %q %q, want none", r.stdout, r.stderr)
			}
		})
	}
}

func TestPassedRunWithNoTextOpensNoDraft(t *testing.T) {
	e := newEnv(t)
	r, got := e.run(t, submission("passed", "", repo(repoA, "github.com")), nil)
	if r.code != 0 || e.tunnelCount() != 0 {
		t.Fatalf("exit %d, %d tunnels, stderr %q", r.code, e.tunnelCount(), r.stderr)
	}
	checkLinks(t, entry(got, 0), repoA)
	if d := entry(got, 0)["draft"]; !reflect.DeepEqual(d, map[string]any{"none": "not-passed"}) {
		t.Errorf("draft = %v, want it unchanged", d)
	}
}

func TestOtherSystemsUntouched(t *testing.T) {
	e := newEnv(t)
	other := repo("group/sub/project", "git.example.org")
	r, got := e.run(t, submission("passed", "Add the widget", repo(repoA, "github.com"), other), bases(repoA))
	if r.code != 0 {
		t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
	}
	want, _ := json.Marshal(other)
	if g, _ := json.Marshal(entry(got, 1)); !bytes.Equal(g, want) {
		t.Errorf("other system's entry = %s, want %s", g, want)
	}
	for _, c := range e.gh.recorded() {
		if strings.Contains(c.Path, "group") {
			t.Errorf("call for the other system: %+v", c)
		}
	}
}

func TestForbiddenRepositoryKeepsOthers(t *testing.T) {
	e := newEnv(t)
	e.gh.fix("POST "+repoA, http.StatusForbidden, `{"message":"Resource not accessible by integration"}`)
	r, got := e.run(t, submission("passed", "Add the widget", repo(repoA, "github.com"), repo(repoB, "github.com")), bases(repoA, repoB))
	if r.code != 1 {
		t.Fatalf("exit %d, want 1; stderr %q", r.code, r.stderr)
	}
	wantErr := "Give the GitHub App pull_requests: write on acme-corp/widgets-app: POST pulls returned 403\n"
	if r.stderr != wantErr {
		t.Errorf("stderr = %q, want %q", r.stderr, wantErr)
	}
	if d := entry(got, 0)["draft"]; !reflect.DeepEqual(d, map[string]any{"none": "not-passed"}) {
		t.Errorf("failed repository's draft = %v, want it unchanged", d)
	}
	if d := entry(got, 1)["draft"].(map[string]any); d["action"] != "opened" || d["url"] != "https://github.com/"+repoB+"/pull/34" {
		t.Errorf("other repository's draft = %v", d)
	}
	checkLinks(t, entry(got, 0), repoA)
	checkLinks(t, entry(got, 1), repoB)
	if r.stdout != "https://github.com/"+repoB+"/pull/34 opened\n" {
		t.Errorf("stdout = %q", r.stdout)
	}
}

func TestFailedCalls(t *testing.T) {
	const r = repoA
	link := "https://github.com/" + r + "/pull/34"
	cases := []struct {
		name    string
		setup   func(e *env)
		extra   []string
		wantErr string
	}{
		{"wrong proxy password", nil, []string{"QORY_PROXY_PASSWORD=wrong"},
			"Set QORY_PROXY_PASSWORD to the proxy password: the proxy returned 407 for " + r},
		{"proxy status 502", func(e *env) { e.connectStatus = 502 }, nil,
			"Check the proxy at QORY_PROXY_SOCKET: CONNECT returned 502 for " + r},
		{"no proxy", nil, []string{"QORY_PROXY_SOCKET=/nonexistent/p.sock"},
			"Check the proxy at QORY_PROXY_SOCKET: connecting failed (ENOENT) for " + r},
		{"no CA", nil, []string{"SSL_CERT_FILE="},
			"Set SSL_CERT_FILE to the run's CA bundle: TLS failed (UNABLE_TO_VERIFY_LEAF_SIGNATURE)"},
		{"other CA", func(e *env) { _ = os.WriteFile(e.caFile, otherCA(), 0o600) }, nil,
			"Check the CA bundle in SSL_CERT_FILE: TLS failed (UNABLE_TO_VERIFY_LEAF_SIGNATURE)"},
		{"301", func(e *env) { e.gh.fix("GET "+r, 301, `{"message":"Moved Permanently"}`) }, nil,
			"Set the targets to the current name of " + r + ": GET pulls returned 301"},
		{"401", func(e *env) { e.gh.fix("GET "+r, 401, `{"message":"Bad credentials"}`) }, nil,
			"Check the token the proxy adds for " + r + ": GET pulls returned 401"},
		{"403 on GET", func(e *env) { e.gh.fix("GET "+r, 403, `{"message":"no"}`) }, nil,
			"Give the GitHub App pull_requests: read on " + r + ": GET pulls returned 403"},
		{"404", func(e *env) { e.gh.fix("GET "+r, 404, `{"message":"Not Found"}`) }, nil,
			"Install the GitHub App on " + r + ": GET pulls returned 404"},
		{"422", func(e *env) {
			e.gh.fix("POST "+r, 422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","code":"invalid","message":"head\ninvalid"}]}`)
		}, nil, "Check the head and base branches on " + r + ": POST pulls returned 422 (head invalid)"},
		{"422 no commits", func(e *env) {
			e.gh.fix("POST "+r, 422, `{"message":"Validation Failed","errors":[{"message":"No commits between main and qory/wi_01HZX, as the branches are the same"}]}`)
		}, nil, "Push the run's commits to " + r + ": POST pulls returned 422 (No commits between mai...)"},
		{"422 drafts", func(e *env) {
			e.gh.fix("POST "+r, 422, `{"message":"Draft pull requests are not supported in this repository."}`)
		}, nil, "Use a GitHub plan with draft pull requests for " + r + ": POST pulls returned 422"},
		{"429", func(e *env) { e.gh.fix("GET "+r, 429, `{"message":"Too many requests"}`) }, nil,
			"Wait for GitHub's rate limit to reset for " + r + ": GET pulls returned 429"},
		{"403 with no requests left", func(e *env) {
			e.gh.fixHeader("POST "+r, 403, `{"message":"Forbidden"}`, map[string]string{"X-RateLimit-Remaining": "0"})
		}, nil, "Wait for GitHub's rate limit to reset for " + r + ": POST pulls returned 403"},
		{"403 about the rate limit", func(e *env) {
			e.gh.fix("POST "+r, 403, `{"message":"You have exceeded a secondary rate limit."}`)
		}, nil, "Wait for GitHub's rate limit to reset for " + r + ": POST pulls returned 403"},
		{"past the deadline", func(e *env) {
			// Every Date.now after the first, the program's start, is 100 s later.
			late := filepath.Join(e.dir, "late.js")
			_ = os.WriteFile(late, []byte("const now = Date.now; let n = 0; Date.now = () => now() + (n++ ? 100000 : 0);\n"), 0o600)
			e.vars = append(e.vars, "NODE_OPTIONS=--require="+late)
		}, nil, "Retry with a later passed round for " + r + ": GET pulls timed out at 100 s"},
		{"503", func(e *env) { e.gh.fix("POST "+r, 503, `{"message":"unavailable"}`) }, nil,
			"Retry with a later passed round for " + r + ": POST pulls returned 503"},
		{"not JSON", func(e *env) { e.gh.fix("POST "+r, 201, `<html>`) }, nil,
			"Check the proxy for " + r + ": POST pulls returned no valid JSON"},
		{"GET returns no list", func(e *env) { e.gh.fix("GET "+r, 200, `{"message":"x"}`) }, nil,
			"Check the proxy for " + r + ": GET pulls returned no list of pull requests"},
		{"no pull request number", func(e *env) {
			e.gh.fix("POST "+r, 201, `{"html_url":"`+link+`","title":"Add the widget","draft":true}`)
		}, nil, "Check the proxy for " + r + ": POST pulls returned no pull request number"},
		{"unusable title", func(e *env) {
			e.gh.fix("POST "+r, 201, `{"number":34,"html_url":"`+link+`","title":"Add\u0007the widget","draft":true}`)
		}, nil, "Check the proxy for " + r + ": POST pulls returned an unusable title"},
		{"closed pull request", func(e *env) {
			e.gh.fix("POST "+r, 201, `{"number":34,"html_url":"`+link+`","title":"Add the widget","draft":true,"state":"closed"}`)
		}, nil, "Check the proxy for " + r + ": POST pulls returned no open pull request"},
		{"pull request closed before the PATCH", func(e *env) {
			e.gh.setPulls(r, &pull{Number: 12345, Head: ref, Base: "main", Title: "Old", Body: "Old", Draft: true})
			e.gh.fix("PATCH "+r, 200, `{"number":12345,"html_url":"https://github.com/`+r+`/pull/12345","title":"Add the widget","draft":true,"state":"closed"}`)
		}, nil, "Retry with a later passed round for " + r + ": PATCH pulls/12345 returned state closed"},
		{"CA without keyCertSign", func(e *env) { e.issue(x509.KeyUsageDigitalSignature) }, nil,
			"Check the CA bundle in SSL_CERT_FILE: TLS failed (UNSPECIFIED)"},
		{"proxy closes after 200", func(e *env) { e.connectReply, e.closeAfter = "HTTP/1.1 200 OK\r\n\r\n", true }, nil,
			"Retry with a later passed round for " + r + ": GET pulls failed (ECONNRESET)"},
		// The alert reaches TLS only through the bytes the program keeps after the head.
		{"TLS alert after 200", func(e *env) { e.connectReply = "HTTP/1.1 200 OK\r\n\r\n\x15\x03\x03\x00\x02\x02\x28" }, nil,
			"Check the proxy's tunnel to GitHub: TLS failed (ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE)"},
		{"another link", func(e *env) { e.gh.badURL = true }, nil,
			"Check that " + r + " is the repository's current name: pulls returned another link"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if tc.setup != nil {
				tc.setup(e)
			}
			start := time.Now()
			r, got := e.run(t, submission("passed", "Add the widget", repo(repoA, "github.com")), bases(repoA), tc.extra...)
			// A failed call ends at once, not at the 30 s time-out.
			if d := time.Since(start); d > 10*time.Second {
				t.Errorf("the run took %v", d)
			}
			if r.code != 1 || r.stderr != tc.wantErr+"\n" || r.stdout != "" {
				t.Fatalf("exit %d, stdout %q, stderr %q; want 1 and %q", r.code, r.stdout, r.stderr, tc.wantErr)
			}
			checkLinks(t, entry(got, 0), repoA)
			if d := entry(got, 0)["draft"]; !reflect.DeepEqual(d, map[string]any{"none": "not-passed"}) {
				t.Errorf("draft = %v, want it unchanged", d)
			}
			// Past the deadline, no call leaves the program.
			if tc.name == "past the deadline" && (e.tunnelCount() != 0 || len(e.gh.recorded()) != 0) {
				t.Errorf("%d tunnels and %d calls past the deadline, want none", e.tunnelCount(), len(e.gh.recorded()))
			}
		})
	}
}

// withLinks is submission s with the commit links of its github.com entries, as the
// program writes them.
func withLinks(t *testing.T, s any) any {
	t.Helper()
	raw, _ := json.Marshal(s)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	for _, r := range out["repositories"].([]any) {
		r := r.(map[string]any)
		if r["system"] != "github.com" {
			continue
		}
		path := r["path"].(string)
		r["commit_url"] = link(path, r["commit"].(string))
		b := r["base"].(map[string]any)
		b["commit_url"] = link(path, b["commit"].(string))
		for _, c := range r["commits"].([]any) {
			c := c.(map[string]any)
			c["commit_url"] = link(path, c["commit"].(string))
		}
	}
	return out
}

// TestBadInputExits2 runs wrong input. A wrong structure leaves the file unchanged; a
// wrong input of the drafts leaves only the commit links written.
func TestBadInputExits2(t *testing.T) {
	good := func() map[string]any { return submission("passed", "Add the widget", repo(repoA, "github.com")) }
	with := func(f func(s map[string]any)) map[string]any { s := good(); f(s); return s }
	cases := []struct {
		name       string
		submission any
		bases      any
		wantErr    string
		links      bool
	}{
		{"not JSON", "{", bases(repoA), "Write valid JSON to the file in QORY_SUBMISSION_FILE: %s does not parse", false},
		{"no ref", with(func(s map[string]any) { delete(s, "ref") }), bases(repoA),
			"Fix ref in the submission: it is not qory/wi_<id>", false},
		{"short commit", with(func(s map[string]any) { entry(s, 0)["commit"] = "abc" }), bases(repoA),
			"Fix repositories[0].commit in the submission: it is not a 40 or 64 hex commit id", false},
		{"no draft", with(func(s map[string]any) { delete(entry(s, 0), "draft") }), bases(repoA),
			"Fix repositories[0].draft in the submission: it is missing or not a JSON object", false},
		{"path not owner/name", with(func(s map[string]any) { entry(s, 0)["path"] = "acme/team/widgets" }), bases(repoA),
			"Fix repositories[0].path in the submission: it is not owner/name for github.com", false},
		{"dot-dot path", with(func(s map[string]any) { entry(s, 0)["path"] = "acme/.." }), bases(repoA),
			"Fix repositories[0].path in the submission: it has a ., .. or .git segment", false},
		{".git path", with(func(s map[string]any) { entry(s, 0)["path"] = "acme/.GIT" }), bases(repoA),
			"Fix repositories[0].path in the submission: it has a ., .. or .git segment", false},
		{"title with a control character", with(func(s map[string]any) { s["text"].(map[string]any)["title"] = "Add\tthe widget" }), bases(repoA),
			"Fix text.title in the submission: it is not 1 to 256 characters with no control character", true},
		{"title of 257 code points", with(func(s map[string]any) { s["text"].(map[string]any)["title"] = strings.Repeat("\U0001F600", 257) }), bases(repoA),
			"Fix text.title in the submission: it is not 1 to 256 characters with no control character", true},
		{"missing base", good(), bases(repoB),
			"Add acme-corp/widgets-app to the run documents' targets: no base branch for it in QORY_SUBMIT_BASES", true},
		{"bases entry without base", good(), []any{map[string]any{"system": "github.com", "path": repoA}},
			"Fix entry 0 of the file in QORY_SUBMIT_BASES: it is not {system, path, base} with a valid branch", true},
		{"no bases file", good(), nil, "Set QORY_SUBMIT_BASES: the variable is unset or empty", true},
		{"bases not a list", good(), map[string]any{"x": 1},
			"Write a list of {system, path, base} to the file in QORY_SUBMIT_BASES: it is not a list", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			file := filepath.Join(e.dir, "submission.json")
			r, _ := e.run(t, tc.submission, tc.bases)
			after, _ := os.ReadFile(file)
			var before []byte
			if s, ok := tc.submission.(string); ok {
				before = []byte(s)
			} else {
				before, _ = json.MarshalIndent(tc.submission, "", "  ")
			}
			if tc.links {
				var got any
				_ = json.Unmarshal(after, &got)
				if want := withLinks(t, tc.submission); !reflect.DeepEqual(got, want) {
					t.Errorf("the file is\n%s\nwant the submission with its commit links alone", after)
				}
			} else if !bytes.Equal(before, after) {
				t.Errorf("the file changed:\n%s", after)
			}
			wantErr := tc.wantErr
			if strings.Contains(wantErr, "%s") {
				wantErr = fmt.Sprintf(wantErr, file)
			}
			if r.code != 2 || r.stderr != wantErr+"\n" || r.stdout != "" {
				t.Errorf("exit %d, stdout %q, stderr %q; want 2 and %q", r.code, r.stdout, r.stderr, wantErr)
			}
			if e.tunnelCount() != 0 {
				t.Errorf("%d tunnels after bad input, want none", e.tunnelCount())
			}
		})
	}
}

func TestMissingSubmissionFile(t *testing.T) {
	e := newEnv(t)
	file := filepath.Join(e.dir, "missing.json")
	r, _ := e.runRaw(t, file, []string{"PATH=" + os.Getenv("PATH"), "QORY_SUBMISSION_FILE=" + file})
	want := "Set QORY_SUBMISSION_FILE to a readable file: reading " + file + " failed (ENOENT)\n"
	if r.code != 2 || r.stderr != want {
		t.Errorf("exit %d, stderr %q; want 2 and %q", r.code, r.stderr, want)
	}
	if _, err := os.Stat(file); err == nil {
		t.Error("the program created the file")
	}
}
