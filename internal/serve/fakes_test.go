package serve

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	testKeyID    = "ak_0123456789abcdef"
	testInstance = "i_AAAAAAAAAAAAAAAAAAAAAA"
	testSlug     = "qory-test"
	ghToken      = "ghs_a-token-that-must-not-leak"
)

// appKey is one RSA key for the App, made once, since making one is slow.
var appKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

// newKey is a new Ed25519 key.
func newKey(t *testing.T) *accesskey.Key {
	t.Helper()
	k, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// pinOf is the pin that lists k's public key.
func pinOf(k *accesskey.Key) accesskey.Pin {
	return accesskey.Pin{{Alg: "ed25519", PublicKey: k.PublicKey().String()}}
}

// apiaryRequest is one request the fake Qory Apiary received, its signature verified.
type apiaryRequest struct {
	method, target string
	instance       string
	body           map[string]any
	raw            []byte
	signature      string
}

// fakeApiary is Qory Apiary as the adapter reaches it. It verifies every request's
// signature under the adapter's public key and its headers, records it, and signs its
// answer under its server key: a refusal its refuse function chooses, or 200 {} for a
// POST and the page of its change feed after the cursor for a GET.
type fakeApiary struct {
	t       *testing.T
	srv     *httptest.Server
	adapter accesskey.PublicKey
	server  *accesskey.Key
	// signer signs the answers in place of server when set: a key the pin does not list.
	signer *accesskey.Key
	// refuse answers a POST, numbered from 1 among those to its route, when it returns a
	// status other than 0.
	refuse func(route string, n int) (int, string)
	// refuseGet answers a GET of the feed, numbered from 1, when it returns a status
	// other than 0. hold, when set, holds every GET of the feed until its request is
	// cancelled, as Qory Apiary holds a read while nothing follows the cursor.
	refuseGet func(n int) (int, string)
	hold      bool
	revision  *int

	mu       sync.Mutex
	requests []apiaryRequest
	changes  []contracts.Change
}

// bodySchemas are the contract's schemas of the bodies Qory Apiary takes, by route,
// compiled once: the fake checks every body it receives against its route's.
var bodySchemas = sync.OnceValue(func() map[string]*jsonschema.Schema {
	out := map[string]*jsonschema.Schema{}
	for route, name := range map[string]string{
		routeAdapter:     "adapter.schema.json",
		routeCollections: "source-collections.schema.json",
		routeItems:       "source-items.schema.json",
		routeComments:    "source-item-comments.schema.json",
		routeDisconnect:  "sources-disconnect.schema.json",
	} {
		s, err := contracts.Compile(name)
		if err != nil {
			panic(err)
		}
		out[route] = s
	}
	return out
})

// checkBody reports a body that breaks its route's schema in the contract.
func checkBody(t *testing.T, route string, b []byte) {
	t.Helper()
	s := bodySchemas()[route]
	if s == nil {
		t.Errorf("%s: no schema of the contract takes a body there", route)
		return
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err == nil {
		err = s.Validate(doc)
	}
	if err != nil {
		t.Errorf("%s: the body breaks the contract: %v", route, err)
	}
}

// widgetsItem is a request that sends one item of acme/widgets, as the contract takes it.
func widgetsItem() contracts.SourceItems {
	return contracts.SourceItems{Version: contracts.Version, CollectionRef: "acme/widgets", Items: []contracts.Item{{
		Ref: "acme/widgets#1", URL: "https://github.com/acme/widgets/issues/1", Type: "issue", Title: "Widget 1 is broken",
		BodyFormat: github.FormatMarkdown, FiledBy: contracts.Person{Name: "alice", Kind: github.KindPerson}, Labels: []string{},
		State: github.StateOpen, CreatedAt: "2026-01-02T03:04:05Z", UpdatedAt: "2026-01-03T03:04:05Z",
	}}}
}

// timeShape is a time as the contract writes it.
var timeShape = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

func newFakeApiary(t *testing.T, adapter *accesskey.Key) *fakeApiary {
	t.Helper()
	f := &fakeApiary{t: t, adapter: adapter.PublicKey(), server: newKey(t)}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeApiary) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	sig := r.Header.Get(accesskey.HeaderSignature)
	req := accesskey.Request{AccessKeyID: r.Header.Get(accesskey.HeaderAccessKeyID), InstanceID: r.Header.Get(accesskey.HeaderInstanceID), Method: r.Method, Target: r.URL.RequestURI()}
	if r.Method == http.MethodPost {
		req.Body = b
	} else {
		req.Timestamp = r.Header.Get(accesskey.HeaderTimestamp)
	}
	if !f.adapter.VerifyRequest(req, sig) || req.AccessKeyID != testKeyID || accesskey.CheckInstanceID(req.InstanceID) != nil || r.Header.Get("X-Qory-Contract-Version") != "1" {
		f.t.Errorf("%s %s: the request is not signed as the contract signs it", r.Method, r.URL.RequestURI())
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"unauthorized"}`)
		return
	}
	got := apiaryRequest{method: r.Method, target: r.URL.RequestURI(), instance: req.InstanceID, raw: b, signature: sig}
	if r.Method == http.MethodPost {
		if err := json.Unmarshal(b, &got.body); err != nil {
			f.t.Errorf("%s: the body is not JSON: %v", r.URL.Path, err)
		}
		if tm, _ := got.body["time"].(string); !timeShape.MatchString(tm) {
			f.t.Errorf("%s: the time is %q", r.URL.Path, tm)
		}
		checkBody(f.t, r.URL.Path, b)
	} else if req.Timestamp == "" {
		f.t.Errorf("%s: a GET without X-Qory-Timestamp", r.URL.Path)
	}
	f.mu.Lock()
	hold := f.hold
	f.mu.Unlock()
	if hold && r.Method == http.MethodGet {
		f.mu.Lock()
		f.requests = append(f.requests, got)
		f.mu.Unlock()
		<-r.Context().Done()
		return
	}
	f.mu.Lock()
	f.requests = append(f.requests, got)
	n := 0
	for _, x := range f.requests {
		if path, _, _ := strings.Cut(x.target, "?"); x.method == r.Method && path == r.URL.Path {
			n++
		}
	}
	status, body := http.StatusOK, `{}`
	if r.Method == http.MethodGet {
		body = f.page(r.URL.Query().Get("after"))
	}
	refuse, refuseGet := f.refuse, f.refuseGet
	f.mu.Unlock()
	if refuse != nil && r.Method == http.MethodPost {
		if s, b := refuse(r.URL.Path, n); s != 0 {
			status, body = s, b
		}
	}
	if refuseGet != nil && r.Method == http.MethodGet {
		if s, b := refuseGet(n); s != 0 {
			status, body = s, b
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if status != http.StatusUnauthorized {
		signer := f.server
		if f.signer != nil {
			signer = f.signer
		}
		w.Header().Set(accesskey.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: status, RequestSignature: sig, Body: []byte(body)}))
	}
	w.WriteHeader(status)
	io.WriteString(w, body)
}

// page is the feed after the cursor after, c_ and the number of entries before it. f.mu
// is held.
func (f *fakeApiary) page(after string) string {
	from := 0
	if after != "" {
		from, _ = strconv.Atoi(strings.TrimPrefix(after, "c_"))
	}
	from = min(from, len(f.changes))
	revision := contracts.Revision
	if f.revision != nil {
		revision = *f.revision
	}
	// An entry of a kind the contract does not define, which contracts.Change does not
	// write, is written as its kind and status.
	entries := []any{}
	for _, c := range f.changes[from:] {
		if _, err := json.Marshal(c); err != nil {
			entries = append(entries, map[string]any{"kind": c.Kind, "status": c.Status})
			continue
		}
		entries = append(entries, c)
	}
	b, _ := json.Marshal(map[string]any{"version": contracts.Version, "revision": revision, "cursor": "c_" + strconv.Itoa(len(f.changes)), "changes": entries})
	return string(b)
}

// add appends entries to the feed.
func (f *fakeApiary) add(chs ...contracts.Change) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.changes = append(f.changes, chs...)
}

// sent are the requests received on route, by POST, or by GET when route starts with
// GET .
func (f *fakeApiary) sent(route string) []apiaryRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	method := http.MethodPost
	if r, ok := strings.CutPrefix(route, "GET "); ok {
		method, route = http.MethodGet, r
	}
	var out []apiaryRequest
	for _, r := range f.requests {
		path, _, _ := strings.Cut(r.target, "?")
		if r.method == method && path == route {
			out = append(out, r)
		}
	}
	return out
}

// client is an [Apiary] client of the fake, with the adapter's key.
func (f *fakeApiary) client(key *accesskey.Key) *Apiary {
	return &Apiary{URL: f.srv.URL, KeyID: testKeyID, Key: key, Pin: pinOf(f.server), InstanceID: testInstance}
}

// fakeGitHub is GitHub's API as the adapter reaches it for the installation 42 of
// acme: the token mint, the listing of the installation's repositories, one page, and
// acme/widgets's issues and comments, and a take in's label and comment on issue 7.
type fakeGitHub struct {
	srv *httptest.Server

	mu       sync.Mutex
	repos    []string
	issues   []map[string]any
	comments map[int][]map[string]any
	labelled []string
	posted   []string
	mints    []string
	requests []string
	// unauthorized answers the listing of acme/widgets's issues 401, as GitHub answers
	// a token it no longer takes.
	unauthorized bool
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{repos: []string{"acme/widgets", "acme/gadgets"}, comments: map[int][]map[string]any{}}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

// ghIssue is an open issue of acme/widgets numbered n, with comments comments.
func ghIssue(n, comments int) map[string]any {
	return map[string]any{
		"number": n, "title": "Widget " + strconv.Itoa(n) + " is broken", "body": "It does not turn.", "state": "open",
		"html_url": "https://github.com/acme/widgets/issues/" + strconv.Itoa(n), "labels": []any{},
		"user": map[string]any{"login": "alice", "type": "User"}, "comments": comments,
		"created_at": "2026-01-02T03:04:05Z", "updated_at": "2026-01-03T03:04:05Z",
	}
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := io.ReadAll(r.Body)
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	w.Header().Set("Content-Type", "application/json")
	const widgets = "/repos/acme/widgets"
	switch {
	case r.Method == "GET" && r.URL.Path == "/app/installations/42":
		io.WriteString(w, `{"id":42,"account":{"login":"acme"}}`)
	case r.Method == "POST" && r.URL.Path == "/app/installations/42/access_tokens":
		f.mints = append(f.mints, string(b))
		w.WriteHeader(201)
		io.WriteString(w, `{"token":"`+ghToken+`","expires_at":"2099-01-01T00:00:00Z"}`)
	case r.Method == "GET" && r.URL.Path == "/installation/repositories":
		var repos []map[string]any
		for _, name := range f.repos {
			repos = append(repos, map[string]any{"full_name": name, "html_url": "https://github.com/" + name})
		}
		json.NewEncoder(w).Encode(map[string]any{"total_count": len(repos), "repositories": repos})
	case r.Method == "GET" && r.URL.Path == widgets:
		io.WriteString(w, `{"full_name":"acme/widgets","html_url":"https://github.com/acme/widgets"}`)
	case r.Method == "GET" && r.URL.Path == widgets+"/issues" && f.unauthorized:
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Bad credentials"}`)
	case r.Method == "GET" && r.URL.Path == widgets+"/issues":
		json.NewEncoder(w).Encode(append([]map[string]any{}, f.issues...))
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, widgets+"/issues/") && strings.HasSuffix(r.URL.Path, "/comments"):
		n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, widgets+"/issues/"), "/comments"))
		json.NewEncoder(w).Encode(append([]map[string]any{}, f.comments[n]...))
	case r.Method == "POST" && r.URL.Path == widgets+"/labels":
		w.WriteHeader(201)
		w.Write(b)
	case r.Method == "POST" && r.URL.Path == widgets+"/issues/7/labels":
		f.labelled = append(f.labelled, string(b))
		io.WriteString(w, `[{"name":"qory"}]`)
	case r.Method == "POST" && r.URL.Path == widgets+"/issues/7/comments":
		var c struct {
			Body string `json:"body"`
		}
		json.Unmarshal(b, &c)
		f.posted = append(f.posted, c.Body)
		f.comments[7] = append(f.comments[7], map[string]any{
			"id": 700 + len(f.posted), "html_url": "https://github.com/acme/widgets/issues/7#issuecomment-1", "body": c.Body,
			"user": map[string]any{"login": testSlug + "[bot]", "type": "Bot"}, "created_at": "2026-01-04T00:00:00Z", "updated_at": "2026-01-04T00:00:00Z",
		})
		w.WriteHeader(201)
		io.WriteString(w, `{"id":1}`)
	case strings.HasPrefix(r.URL.Path, "/repos/acme/moved/") || r.URL.Path == "/repos/acme/moved":
		// acme/moved was renamed: GitHub redirects every request for it.
		w.Header().Set("Location", "https://api.github.com/repositories/1"+strings.TrimPrefix(r.URL.Path, "/repos/acme/moved"))
		w.WriteHeader(301)
		io.WriteString(w, `{"message":"Moved Permanently"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

// postedComments are the comments posted on issue 7.
func (f *fakeGitHub) postedComments() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.posted...)
}

// settingsFiles writes the App's key, the webhook secret and the access key's secret
// in dir, and returns settings that name them, Qory Apiary at apiaryURL, under the pin.
func settingsFiles(t *testing.T, dir string, access *accesskey.Key, apiaryURL string, pin accesskey.Pin) Settings {
	t.Helper()
	keyFile := filepath.Join(dir, "app.pem")
	writeFile(t, keyFile, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(appKey())})), 0o600)
	secretFile := filepath.Join(dir, "secret")
	writeFile(t, secretFile, secret, 0o600)
	accessFile := filepath.Join(dir, "access-key")
	writeFile(t, accessFile, access.Secret()+"\n", 0o600)
	return Settings{
		AppID: "1", PrivateKeyFile: keyFile, WebhookSecretFile: secretFile, Listen: "127.0.0.1:0", StateDir: filepath.Join(dir, "state"),
		AppSlug: testSlug, APIURL: "https://api.github.com", ApiaryURL: apiaryURL, PublicURL: "https://qory-github.example.com",
		AccessKeyID: testKeyID, AccessKeySecretFile: accessFile, ApiaryPublicKey: pin,
	}
}
