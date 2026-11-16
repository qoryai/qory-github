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

	"gopkg.in/yaml.v3"
)

const (
	password = "pw-7f3a9c-never-printed"
	ref      = "qory/wi_01HZX"
	repoA    = "acme/widgets"
	repoB    = "acme/gadgets"
)

// Commit ids of the submissions: the base, two commits in between, and the head.
var (
	baseCommit = strings.Repeat("a", 40)
	midCommit  = strings.Repeat("b", 40)
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

type pull struct {
	Number int
	Title  string
	Body   string
	Head   string
	Base   string
	Draft  bool
}

// github is a stand-in for api.github.com: pull requests per repository, and a status
// to return for a method on a repository.
type github struct {
	mu     sync.Mutex
	calls  []call
	pulls  map[string][]*pull
	fail   map[string]int // "POST acme/widgets" → status
	badURL bool
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
	if s, ok := g.fail[r.Method+" "+repo]; ok {
		http.Error(w, `{"message":"no"}`, s)
		return
	}
	render := func(p *pull) map[string]any {
		u := "https://github.com/" + repo + "/pull/" + strconv.Itoa(p.Number)
		if g.badURL {
			u = "https://github.com/someone/else/pull/" + strconv.Itoa(p.Number)
		}
		return map[string]any{
			"number": p.Number, "html_url": u, "title": p.Title, "body": p.Body,
			"draft": p.Draft, "head": map[string]any{"ref": p.Head}, "base": map[string]any{"ref": p.Base},
		}
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && m[2] == "":
		owner := strings.Split(repo, "/")[0]
		out := []map[string]any{}
		for _, p := range g.pulls[repo] {
			if r.URL.Query().Get("state") == "open" && r.URL.Query().Get("head") == owner+":"+p.Head {
				out = append(out, render(p))
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodPost && m[2] == "":
		p := &pull{Number: 33 + len(g.pulls[repo]) + 1, Title: c.Body["title"].(string),
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
	gh      *github
	dir     string
	socket  string
	caFile  string
	tunnels int
	mu      sync.Mutex
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
	e := &env{gh: &github{pulls: map[string][]*pull{}, fail: map[string]int{}}, dir: dir,
		socket: filepath.Join(dir, "p.sock"), caFile: filepath.Join(dir, "ca.pem")}

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "stand-in CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "api.github.com"},
		DNSNames: []string{"api.github.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(e.gh)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
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
	e.mu.Lock()
	e.tunnels++
	e.mu.Unlock()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
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
	return e.runRaw(t, file, append(vars, extra...))
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
		if len(line) > 100 && !strings.Contains(line, e.dir) {
			t.Errorf("stderr line is %d characters, over 100: %s", len(line), line)
		}
	}
	var got map[string]any
	if raw, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(raw, &got)
	}
	if _, err := os.Stat(file + ".tmp"); err == nil {
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
		"commits": []any{map[string]any{"commit": midCommit, "step": "deliverable:d-1"}, map[string]any{"commit": headCommit, "step": "fix:f1"}},
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
	for i, want := range []string{midCommit, headCommit} {
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
	if calls[0].Path != "/repos/"+repoA+"/pulls" || calls[0].Query != "head=acme%3Aqory%2Fwi_01HZX&state=open" {
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
	e.gh.pulls[repoA][0].Draft = false
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
	if len(e.gh.pulls[repoA]) != 1 {
		t.Errorf("%d pull requests, want 1", len(e.gh.pulls[repoA]))
	}
	if r.stdout != url+" updated\n" {
		t.Errorf("stdout = %q", r.stdout)
	}
}

func TestFourCommitsGetLinks(t *testing.T) {
	for _, verdict := range []string{"passed", "changes-requested"} {
		t.Run(verdict, func(t *testing.T) {
			e := newEnv(t)
			r, got := e.run(t, submission(verdict, "Add the widget", repo(repoA, "github.com")), bases(repoA))
			if r.code != 0 {
				t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
			}
			checkLinks(t, entry(got, 0), repoA)
			if verdict == "passed" {
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
	e.gh.fail["POST "+repoA] = http.StatusForbidden
	r, got := e.run(t, submission("passed", "Add the widget", repo(repoA, "github.com"), repo(repoB, "github.com")), bases(repoA, repoB))
	if r.code != 1 {
		t.Fatalf("exit %d, want 1; stderr %q", r.code, r.stderr)
	}
	wantErr := "Give the GitHub App pull_requests: write on acme/widgets: GitHub returned 403 for POST pulls\n"
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
	cases := []struct {
		name    string
		setup   func(e *env)
		extra   []string
		wantErr string
	}{
		{"wrong proxy password", nil, []string{"QORY_PROXY_PASSWORD=wrong"},
			"Set QORY_PROXY_PASSWORD to the proxy password: the proxy returned 407 for acme/widgets"},
		{"no proxy", nil, []string{"QORY_PROXY_SOCKET=/nonexistent/p.sock"},
			"Check the proxy at QORY_PROXY_SOCKET: connecting failed (ENOENT) for acme/widgets"},
		{"no CA", nil, []string{"SSL_CERT_FILE="},
			"Check the CA bundle in SSL_CERT_FILE for acme/widgets: TLS failed (UNABLE_TO_VERIFY_LEAF_SIGNATURE)"},
		{"404", func(e *env) { e.gh.fail["GET "+repoA] = 404 }, nil,
			"Install the GitHub App on acme/widgets: GitHub returned 404 for GET pulls"},
		{"422", func(e *env) { e.gh.fail["POST "+repoA] = 422 }, nil,
			"Check the head and base branches on acme/widgets: GitHub returned 422 for POST pulls"},
		{"unexpected link", func(e *env) { e.gh.badURL = true }, nil,
			"Check the proxy for acme/widgets: GitHub returned an unexpected link for POST pulls"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if tc.setup != nil {
				tc.setup(e)
			}
			r, got := e.run(t, submission("passed", "Add the widget", repo(repoA, "github.com")), bases(repoA), tc.extra...)
			if r.code != 1 || r.stderr != tc.wantErr+"\n" || r.stdout != "" {
				t.Fatalf("exit %d, stdout %q, stderr %q; want 1 and %q", r.code, r.stdout, r.stderr, tc.wantErr)
			}
			checkLinks(t, entry(got, 0), repoA)
			if d := entry(got, 0)["draft"]; !reflect.DeepEqual(d, map[string]any{"none": "not-passed"}) {
				t.Errorf("draft = %v, want it unchanged", d)
			}
		})
	}
}

func TestBadInputLeavesFileUnchanged(t *testing.T) {
	good := func() map[string]any { return submission("passed", "Add the widget", repo(repoA, "github.com")) }
	with := func(f func(s map[string]any)) map[string]any { s := good(); f(s); return s }
	cases := []struct {
		name       string
		submission any
		bases      any
		wantErr    string
	}{
		{"not JSON", "{", bases(repoA), "Write valid JSON to the file in QORY_SUBMISSION_FILE: %s does not parse"},
		{"no ref", with(func(s map[string]any) { delete(s, "ref") }), bases(repoA),
			"Fix ref in the submission: it is not qory/wi_<id>"},
		{"short commit", with(func(s map[string]any) { entry(s, 0)["commit"] = "abc" }), bases(repoA),
			"Fix repositories[0].commit in the submission: it is not a 40 or 64 hex commit id"},
		{"no draft", with(func(s map[string]any) { delete(entry(s, 0), "draft") }), bases(repoA),
			"Fix repositories[0].draft in the submission: it is missing or not a JSON object"},
		{"path not owner/name", with(func(s map[string]any) { entry(s, 0)["path"] = "acme/team/widgets" }), bases(repoA),
			"Fix repositories[0].path in the submission: github.com needs owner/name, not acme/team/widgets"},
		{"missing base", good(), bases(repoB),
			"Add acme/widgets to the run documents' targets: QORY_SUBMIT_BASES has no base branch for it"},
		{"no bases file", good(), nil, "Set QORY_SUBMIT_BASES: the variable is unset or empty"},
		{"bases not a list", good(), map[string]any{"x": 1},
			"Write a list of {system, path, base} to the file in QORY_SUBMIT_BASES: it is not a list"},
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
			if !bytes.Equal(before, after) {
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
