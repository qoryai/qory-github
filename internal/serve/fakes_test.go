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
	"net/url"
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
	// The adapter's id, and the App's client id and client secret.
	testAdapterID = "na_0123456789abcdef"
	testClientID  = "Iv1.0123456789abcdef"
	clientSecret  = "a-client-secret-that-must-not-leak"
	// signInCode is the code GitHub's sign-in sends back, and userToken the person's
	// token GitHub exchanges it for.
	signInCode = "a-code-that-must-not-leak"
	userToken  = "ghu_a-user-token-that-must-not-leak"
	// testConnection and otherConnection are connections in Qory Apiary an installation
	// is linked to.
	testConnection  = "ac_0123456789abcdef"
	otherConnection = "ac_fedcba9876543210"
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
// answer under its server key: a refusal its refuse function chooses, or a 204 and no
// body for a POST and the page of its change feed after the cursor for a GET.
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

		routeConnectionsDisconnect: "connections-disconnect.schema.json",
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
		if r.URL.Path == routeCollections && !strings.Contains(string(b), `"collections":[`) {
			f.t.Errorf("%s: the collections are not an array: %s", r.URL.Path, b)
		}
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
	status, body := http.StatusNoContent, ``
	if r.Method == http.MethodGet {
		status = http.StatusOK
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
	if body != "" {
		w.Header().Set("Content-Type", "application/json")
	}
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

// count is how many requests the fake received.
func (f *fakeApiary) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
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
	// unauthorized answers the listings of acme/widgets's issues, by REST and by
	// GraphQL, 401, as GitHub answers a token it no longer takes; issuesDown answers
	// them 502. goneComments answers that issue's comments 404, as for an issue deleted
	// while it is listed. reposDown answers every request under /repos/, and GraphQL's,
	// 502.
	unauthorized, issuesDown, reposDown bool
	goneComments                        int
	// gqlFailOn answers that page of GraphQL's listing, counted from 1, as gqlFail
	// says: "errors", a 200 whose errors say the query failed; "limited", a 200 that
	// says GraphQL's rate limit, for that page and every try after it; or "502".
	// onPage, when set, is called with each page's number and request before the page
	// is answered, without f.mu held. gqlPages counts the pages asked for.
	gqlFailOn int
	gqlFail   string
	onPage    func(page int, r *http.Request)
	gqlPages  int
	// person is the person signed in with Connect; userInstallations are the
	// installations the person reaches, which GitHub lists one on each page; and
	// memberships are the person's memberships of organisations, by login. userDown
	// answers every request under /user 502. exchanges are the forms of the sign-in's
	// codes' exchanges.
	person            github.Account
	userInstallations []ghInstallation
	memberships       map[string]ghMembership
	userDown          bool
	exchanges         []url.Values
}

// ghInstallation is an installation of the App as GET /user/installations lists it.
type ghInstallation struct {
	id          int64
	account     github.Account
	suspended   bool
	permissions map[string]string
}

// ghMembership is a membership of an organisation as GET /user/memberships/orgs/{org}
// says it.
type ghMembership struct {
	state, role string
	org, person int64
	refused     bool
}

// The fake's accounts: the person, alice, and the organisations acme and octo-org.
var (
	alice   = github.Account{Login: "alice", ID: 1001, Type: "User"}
	acme    = github.Account{Login: "acme", ID: 500, Type: "Organization"}
	octoOrg = github.Account{Login: "octo-org", ID: 600, Type: "Organization"}
)

// allPermissions are the permissions an installation of the fake grants the App.
func allPermissions() map[string]string {
	return map[string]string{"metadata": "read", "issues": "write", "members": "read", "contents": "write"}
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{
		repos: []string{"acme/widgets", "acme/gadgets"}, comments: map[int][]map[string]any{}, person: alice,
		userInstallations: []ghInstallation{{id: 7, account: alice, permissions: allPermissions()}, {id: 42, account: acme, permissions: allPermissions()}},
		memberships:       map[string]ghMembership{"acme": {state: "active", role: "admin", org: acme.ID, person: alice.ID}},
	}
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
	case r.Method == "POST" && r.URL.Path == "/app/installations/42/access_tokens" && strings.Contains(string(b), `"old"`):
		// The installation no longer reaches acme/old.
		w.WriteHeader(422)
		io.WriteString(w, `{"message":"There is at least one repository that does not exist or is not accessible to the parent installation."}`)
	case r.Method == "POST" && (r.URL.Path == "/app/installations/42/access_tokens" || r.URL.Path == "/app/installations/9/access_tokens"):
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
	case r.Method == "POST" && r.URL.Path == "/graphql":
		f.graphql(w, r, b)
	case f.reposDown && strings.HasPrefix(r.URL.Path, "/repos/"):
		w.WriteHeader(502)
		io.WriteString(w, `{"message":"Bad Gateway"}`)
	case r.Method == "GET" && r.URL.Path == widgets+"/issues" && f.issuesDown:
		w.WriteHeader(502)
		io.WriteString(w, `{"message":"Bad Gateway"}`)
	case r.Method == "GET" && r.URL.Path == widgets+"/issues/"+strconv.Itoa(f.goneComments)+"/comments":
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found"}`)
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
	case r.Method == "POST" && r.URL.Path == "/login/oauth/access_token":
		form, _ := url.ParseQuery(string(b))
		f.exchanges = append(f.exchanges, form)
		if r.Header.Get("Accept") != "application/json" || form.Get("client_id") != testClientID || form.Get("client_secret") != clientSecret || form.Get("code") != signInCode {
			io.WriteString(w, `{"error":"bad_verification_code","error_description":"The code passed is incorrect or expired."}`)
			return
		}
		io.WriteString(w, `{"access_token":"`+userToken+`","token_type":"bearer","scope":""}`)
	case r.Method == "GET" && (r.URL.Path == "/user" || strings.HasPrefix(r.URL.Path, "/user/")) && r.Header.Get("Authorization") != "Bearer "+userToken:
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Bad credentials"}`)
	case r.Method == "GET" && (r.URL.Path == "/user" || strings.HasPrefix(r.URL.Path, "/user/")) && f.userDown:
		w.WriteHeader(502)
		io.WriteString(w, `{"message":"Bad Gateway"}`)
	case r.Method == "GET" && r.URL.Path == "/user":
		json.NewEncoder(w).Encode(map[string]any{"login": f.person.Login, "id": f.person.ID, "type": "User"})
	case r.Method == "GET" && r.URL.Path == "/user/installations":
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		page = max(page, 1)
		var ins []map[string]any
		if page <= len(f.userInstallations) {
			in := f.userInstallations[page-1]
			var suspended any
			if in.suspended {
				suspended = "2026-10-01T00:00:00Z"
			}
			ins = append(ins, map[string]any{
				"id": in.id, "account": map[string]any{"login": in.account.Login, "id": in.account.ID, "type": in.account.Type},
				"suspended_at": suspended, "permissions": in.permissions,
			})
		}
		if page < len(f.userInstallations) {
			w.Header().Set("Link", "<"+f.srv.URL+"/user/installations?per_page=100&page="+strconv.Itoa(page+1)+`>; rel="next"`)
		}
		json.NewEncoder(w).Encode(map[string]any{"total_count": len(f.userInstallations), "installations": append([]map[string]any{}, ins...)})
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/user/memberships/orgs/"):
		m, ok := f.memberships[strings.TrimPrefix(r.URL.Path, "/user/memberships/orgs/")]
		switch {
		case !ok:
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Not Found"}`)
		case m.refused:
			w.WriteHeader(403)
			io.WriteString(w, `{"message":"Resource not accessible by integration"}`)
		default:
			json.NewEncoder(w).Encode(map[string]any{"state": m.state, "role": m.role, "organization": map[string]any{"login": "x", "id": m.org}, "user": map[string]any{"login": "x", "id": m.person}})
		}
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

// graphql answers the listing of a repository's open issues by GraphQL's cursor:
// acme/widgets's issues, open ones alone, first to a page after the cursor, which is
// the issue's place in f.issues; acme/moved as GitHub names it since it was renamed;
// and any other repository as one GraphQL cannot resolve. f.mu is held.
func (f *fakeGitHub) graphql(w http.ResponseWriter, r *http.Request, b []byte) {
	var req struct {
		Variables struct {
			Owner string  `json:"owner"`
			Name  string  `json:"name"`
			First int     `json:"first"`
			After *string `json:"after"`
		} `json:"variables"`
	}
	if err := json.Unmarshal(b, &req); err != nil || req.Variables.First <= 0 {
		w.WriteHeader(400)
		io.WriteString(w, `{"message":"Problems parsing JSON"}`)
		return
	}
	v := req.Variables
	f.gqlPages++
	page := f.gqlPages
	if f.onPage != nil {
		on := f.onPage
		f.mu.Unlock()
		on(page, r)
		f.mu.Lock()
	}
	switch {
	case f.unauthorized:
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Bad credentials"}`)
		return
	case f.issuesDown || f.reposDown || f.gqlFailOn != 0 && page >= f.gqlFailOn && f.gqlFail == "502":
		w.WriteHeader(502)
		io.WriteString(w, `{"message":"Bad Gateway"}`)
		return
	case f.gqlFailOn != 0 && page >= f.gqlFailOn && f.gqlFail == "limited":
		io.WriteString(w, `{"data":null,"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}]}`)
		return
	case f.gqlFailOn != 0 && page == f.gqlFailOn && f.gqlFail == "errors":
		io.WriteString(w, `{"data":null,"errors":[{"type":"SERVICE_UNAVAILABLE","message":"Something went wrong while executing your query."}]}`)
		return
	}
	name := v.Owner + "/" + v.Name
	switch name {
	case "acme/widgets":
	case "acme/moved":
		name = "acme/renamed"
	default:
		io.WriteString(w, `{"data":{"repository":null},"errors":[{"type":"NOT_FOUND","path":["repository"],"message":"Could not resolve to a Repository with the name '`+name+`'."}]}`)
		return
	}
	from := 0
	if v.After != nil {
		from, _ = strconv.Atoi(strings.TrimPrefix(*v.After, "cursor:"))
	}
	nodes := []any{}
	more := false
	var end any
	if name == "acme/widgets" {
		for i, is := range f.issues {
			if i < from || is["state"] != "open" {
				continue
			}
			if len(nodes) == v.First {
				more = true
				break
			}
			nodes = append(nodes, gqlNode(is))
			end = "cursor:" + strconv.Itoa(i+1)
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"repository": map[string]any{
		"nameWithOwner": name,
		"url":           "https://github.com/" + name,
		"issues": map[string]any{
			"pageInfo": map[string]any{"hasNextPage": more, "endCursor": end},
			"nodes":    nodes,
		},
	}}})
}

// gqlNode is an issue as REST says it, as GraphQL says it.
func gqlNode(is map[string]any) map[string]any {
	n := map[string]any{
		"number": is["number"], "url": is["html_url"], "title": is["title"], "body": is["body"],
		"state": strings.ToUpper(is["state"].(string)), "stateReason": nil,
		"labels":    map[string]any{"nodes": is["labels"]},
		"createdAt": is["created_at"], "updatedAt": is["updated_at"],
		"comments": map[string]any{"totalCount": is["comments"]},
	}
	if n["body"] == nil {
		n["body"] = ""
	}
	if r, ok := is["state_reason"].(string); ok {
		n["stateReason"] = strings.ToUpper(r)
	}
	if u, ok := is["user"].(map[string]any); ok {
		login, _ := u["login"].(string)
		if u["type"] == "Bot" {
			login = strings.TrimSuffix(login, "[bot]")
		}
		n["author"] = map[string]any{"login": login, "__typename": u["type"]}
	}
	return n
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
	clientFile := filepath.Join(dir, "client-secret")
	writeFile(t, clientFile, clientSecret+"\n", 0o600)
	return Settings{
		AppID: "1", PrivateKeyFile: keyFile, WebhookSecretFile: secretFile, Listen: "127.0.0.1:0", StateDir: filepath.Join(dir, "state"),
		AppSlug: testSlug, APIURL: "https://api.github.com", ApiaryURL: apiaryURL, PublicURL: "https://qory-github.example.com",
		AccessKeyID: testKeyID, AccessKeySecretFile: accessFile, ApiaryPublicKey: pin,
		AdapterID: testAdapterID, ClientID: testClientID, ClientSecretFile: clientFile,
	}
}
