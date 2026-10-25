package serve

import (
	"bytes"
	"cmp"
	"crypto/hpke"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"hash/fnv"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
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
	// testVersion is the program's version serve runs with in a test: a build with no
	// version, as testdata/describe.json holds it.
	testVersion = "dev"
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
	// keyID is the access key id the request was signed with.
	keyID string
	// timestamp is a GET's X-Qory-Timestamp.
	timestamp string
}

// fakeApiary is Qory Apiary as the adapter reaches it. It verifies every request's
// signature under the adapter's public key and its headers, records it, and signs its
// answer under its server key: a refusal its refuse function chooses, or a 204 and no
// body for a POST and the page of its change feed after the cursor for a GET. A request
// the adapter gives up before its body arrives in full is no request to it.
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
	// unsigned, when set, sends a POST's answer, numbered as for refuse, with no
	// signature when it returns true.
	unsigned func(route string, n int) bool
	// refuseGet answers a GET of the feed, numbered from 1, when it returns a status
	// other than 0. hold, when set, holds every GET of the feed until its request is
	// cancelled, as Qory Apiary holds a read while nothing follows the cursor.
	refuseGet func(n int) (int, string)
	hold      bool
	revision  *int

	// enrolReply answers an enrolment, numbered from 1, see [fakeApiary.enrol]; nil
	// answers each with a 201.
	enrolReply func(n int) enrolAnswer

	// secrets are the secrets the fake stores for the adapter, [testApp] from the start,
	// which GET
	// /v1/adapter/secrets answers sealed to the access key that signed the request, and
	// each accepted upload replaces; uploads are the plaintexts of the uploads it
	// opened. sealing, when set, changes the answer's document before it is signed, as
	// a forged or a wrong answer would be: it is given the document and the access key
	// id the request was signed with.
	secrets []contracts.SecretEntry
	uploads []contracts.AdapterSecretsPlaintext
	sealing func(doc map[string]any, keyID string)
	// refusedUploads is how many uploads of secrets a test's refuse refuses first, for
	// the test to count the accepted one.
	refusedUploads int
	// described are the secret names the source role of each adapter record's latest
	// description lists, by the record's adapter id: an upload of a secret its
	// record's list does not contain is refused, 400 invalid_request.
	described map[string][]string
	// node is the adapter id of the last enrolment, which a seal of secrets binds to,
	// testAdapterID before any.
	node string
	// grants is the fake's copy of the adapter's grants, the connection of each by its
	// grant_ref, which GET /v1/grants returns, each report it takes adds to, and each
	// grant end it takes drops from.
	grants map[string]string

	mu       sync.Mutex
	requests []apiaryRequest
	changes  []contracts.Change
	// enrolments are the enrolment requests the fake received, their proofs verified.
	enrolments []accesskey.EnrolmentRequest
	// enrolHold, when set, holds each enrolment's answer until it is closed.
	enrolHold chan struct{}
	// enrolKeyIDs are the access key ids the 201s name, in turn; testKeyID once they
	// run out. keyIDs are the ids of the keys enrolled so far, by public key, which
	// the fake takes a request signed with besides the adapter's; revoked are the
	// keys whose requests it answers 401, as Qory Apiary answers a revoked key, and
	// unauthorized counts those answers.
	enrolKeyIDs  []string
	keyIDs       map[accesskey.PublicKey]string
	revoked      map[accesskey.PublicKey]bool
	unauthorized int
}

// revoke makes the fake answer 401 to every request signed with k.
func (f *fakeApiary) revoke(k accesskey.PublicKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revoked == nil {
		f.revoked = map[accesskey.PublicKey]bool{}
	}
	f.revoked[k] = true
}

// unauthorizedCount is how many requests the fake answered 401 for a revoked key.
func (f *fakeApiary) unauthorizedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.unauthorized
}

// enrolAnswer is how the fake answers an enrolment: a status, 201 for the key enrolled
// as testKeyID in the adapter testAdapterID, unsigned and empty for a 401, and for a
// 409 or a 429 a signed refusal with the code refusal; retryAfter, when set, is sent as
// Retry-After; drop closes the connection with no answer, as the network fails.
type enrolAnswer struct {
	status     int
	refusal    string
	retryAfter string
	drop       bool
	// kind and node, when set, are the 201's node_kind and node_id in place of adapter
	// and testAdapterID.
	kind, node string
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
		routeSecrets:               "adapter-secrets.schema.json",
		routeGrants:                "grant.schema.json",
		routeGrantsEnd:             "grant-end.schema.json",
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

// The ids of the fake's repositories, which the refs of their collections are: acme/widgets
// and acme/gadgets, which the installation 42 reaches, and acme/old, acme/moved and
// acme/gone, which the take-in and the fill reach for. [repoID] gives any other its id.
const (
	widgetsID  = 1296269
	widgetsRef = "1296269"
	gadgetsID  = 1296270
	gadgetsRef = "1296270"
	oldID      = 1296271
	movedID    = 1296272
)

// knownIDs are the fake's repositories' ids by owner/name, in lower case. acme/sprockets
// is acme/widgets renamed, and octo-org/widgets is acme/widgets on octo-org, before or
// after a transfer, each with acme/widgets's id.
var knownIDs = map[string]int64{"acme/widgets": widgetsID, "acme/gadgets": gadgetsID, "acme/old": oldID, "acme/moved": movedID, "acme/gone": 1296273, "acme/sprockets": widgetsID, "octo-org/widgets": widgetsID}

// repoID is the id the fake gives the repository name, owner/name, in any case: one of
// knownIDs, or else one made from the name, the same each time, past the known ones.
func repoID(name string) int64 {
	lower := strings.ToLower(name)
	id, ok := knownIDs[lower]
	if !ok {
		h := fnv.New32a()
		io.WriteString(h, lower)
		id = 2_000_000_000 + int64(h.Sum32())
	}
	return id
}

// refOf is the collection ref of the repository name, owner/name: its id, see [repoID].
func refOf(name string) string { return strconv.FormatInt(repoID(name), 10) }

// itemOf is the item ref of the issue n of the repository name.
func itemOf(name string, n int) string { return refOf(name) + "#" + strconv.Itoa(n) }

// widgetsItem is a request that sends one item of acme/widgets, as the contract takes it.
func widgetsItem() contracts.SourceItems {
	return contracts.SourceItems{Version: contracts.Version, CollectionRef: widgetsRef, Items: []contracts.Item{{
		Ref: widgetsRef + "#1", URL: "https://github.com/acme/widgets/issues/1", Key: "#1", Type: "issue", Title: "Widget 1 is broken",
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
	f.storeTestApp()
	return f
}

// noApp makes the fake store no secret and no description, as before the adapter's
// first start.
func (f *fakeApiary) noApp() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets = nil
	f.described = nil
}

func (f *fakeApiary) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == accesskey.EnrolmentPath {
		f.enrol(w, r)
		return
	}
	b, err := io.ReadAll(r.Body)
	if err != nil || r.Context().Err() != nil {
		// The adapter gave the request up before its body arrived in full, as a
		// request in flight when serve stops does. It reached Qory Apiary as no
		// request at all, so it is neither checked nor recorded.
		return
	}
	sig := r.Header.Get(accesskey.HeaderSignature)
	req := accesskey.Request{AccessKeyID: r.Header.Get(accesskey.HeaderAccessKeyID), InstanceID: r.Header.Get(accesskey.HeaderInstanceID), Method: r.Method, Target: r.URL.RequestURI()}
	if r.Method == http.MethodPost {
		req.Body = b
	} else {
		req.Timestamp = r.Header.Get(accesskey.HeaderTimestamp)
	}
	f.mu.Lock()
	signer, wantID := f.adapter, testKeyID
	if id, ok := f.keyIDs[f.adapter]; ok {
		wantID = id
	}
	for k, id := range f.keyIDs {
		if k.VerifyRequest(req, sig) {
			signer, wantID = k, id
		}
	}
	if f.revoked[signer] && signer.VerifyRequest(req, sig) {
		f.unauthorized++
		f.mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"unauthorized"}`)
		return
	}
	f.mu.Unlock()
	if !signer.VerifyRequest(req, sig) || req.AccessKeyID != wantID || accesskey.CheckInstanceID(req.InstanceID) != nil || r.Header.Get("X-Qory-Contract-Version") != "1" {
		f.t.Errorf("%s %s: the request is not signed as the contract signs it", r.Method, r.URL.RequestURI())
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"unauthorized"}`)
		return
	}
	got := apiaryRequest{method: r.Method, target: r.URL.RequestURI(), instance: req.InstanceID, raw: b, signature: sig, keyID: req.AccessKeyID, timestamp: req.Timestamp}
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
	if hold && r.Method == http.MethodGet && r.URL.Path == routeChanges {
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
	refuse, refuseGet, unsigned := f.refuse, f.refuseGet, f.unsigned
	f.mu.Unlock()
	// A start-up body's description counts once the body arrives, as Qory Apiary keeps
	// it before it answers; a refusal puts the one before back.
	var undescribe func()
	if r.URL.Path == routeAdapter && r.Method == http.MethodPost {
		undescribe = f.describe(b)
	}
	refused := false
	if refuse != nil && r.Method == http.MethodPost {
		if s, b := refuse(r.URL.Path, n); s != 0 {
			status, body, refused = s, b, true
		}
	}
	if undescribe != nil && (status < 200 || status > 299) {
		undescribe()
	}
	switch {
	case r.URL.Path == routeSecrets && r.Method == http.MethodGet:
		body = f.sealedSecrets(signer, req.AccessKeyID)
	case r.URL.Path == routeSecrets && !refused:
		if code := f.openUpload(b, req.AccessKeyID); code != "" {
			status, body = http.StatusBadRequest, `{"error":"`+code+`"}`
		}
	case r.URL.Path == routeGrants && r.Method == http.MethodGet:
		body = f.grantsAnswer()
	case r.URL.Path == routeGrants && !refused:
		var g contracts.Grant
		json.Unmarshal(b, &g)
		f.grant(g.GrantRef, g.ConnectionID)
	case r.URL.Path == routeGrantsEnd && !refused:
		var g contracts.GrantEnd
		json.Unmarshal(b, &g)
		f.ungrant(g.GrantRef)
	}
	if refuseGet != nil && r.Method == http.MethodGet {
		if s, b := refuseGet(n); s != 0 {
			status, body = s, b
		}
	}
	if body != "" {
		w.Header().Set("Content-Type", "application/json")
	}
	if status != http.StatusUnauthorized && (unsigned == nil || r.Method != http.MethodPost || !unsigned(r.URL.Path, n)) {
		signer := f.server
		if f.signer != nil {
			signer = f.signer
		}
		w.Header().Set(accesskey.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: status, RequestSignature: sig, Body: []byte(body)}))
	}
	w.WriteHeader(status)
	io.WriteString(w, body)
}

// enrol answers POST /.well-known/qory-enrolment as enrolReply says, every answer but a
// 401 signed under the server's key as an enrolment answer. A 201 makes the enrolled key
// the adapter's, which the fake checks each later request's signature under.
func (f *fakeApiary) enrol(w http.ResponseWriter, r *http.Request) {
	var req accesskey.EnrolmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || r.Method != http.MethodPost || !req.VerifyProof() {
		f.t.Errorf("the enrolment request does not verify: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.enrolments = append(f.enrolments, req)
	n := len(f.enrolments)
	f.mu.Unlock()
	hold := f.enrolHold
	a := enrolAnswer{status: http.StatusCreated}
	if f.enrolReply != nil {
		a = f.enrolReply(n)
	}
	if hold != nil {
		<-hold
	}
	if a.drop {
		c, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			c.Close()
		}
		return
	}
	if a.retryAfter != "" {
		w.Header().Set("Retry-After", a.retryAfter)
	}
	if a.status == http.StatusUnauthorized {
		w.WriteHeader(a.status)
		return
	}
	listed := pinOf(f.server)
	var doc any = map[string]any{"error": a.refusal, "apiary_public_key": listed}
	if a.status == http.StatusCreated {
		pub, _ := accesskey.ParsePublicKey(req.PublicKey)
		f.mu.Lock()
		id := testKeyID
		if len(f.enrolKeyIDs) > 0 {
			id, f.enrolKeyIDs = f.enrolKeyIDs[0], f.enrolKeyIDs[1:]
		}
		if f.keyIDs == nil {
			f.keyIDs = map[accesskey.PublicKey]string{}
		}
		f.keyIDs[pub] = id
		f.adapter = pub
		f.mu.Unlock()
		kind, node := cmp.Or(a.kind, "adapter"), cmp.Or(a.node, testAdapterID)
		f.mu.Lock()
		f.node = node
		f.mu.Unlock()
		doc = map[string]any{"version": 1, "access_key_id": id, "node_id": node, "node_kind": kind, "stored_secrets": false, "apiary_public_key": listed}
	}
	body, _ := json.Marshal(doc)
	w.Header().Set(accesskey.HeaderSignature, f.server.SignAnswer(accesskey.Answer{Enrolment: true, Status: a.status, RequestSignature: req.Proof, Body: body}))
	w.WriteHeader(a.status)
	w.Write(body)
}

// enrolled are the enrolment requests the fake received.
func (f *fakeApiary) enrolled() []accesskey.EnrolmentRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.enrolments)
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

// storeApp makes the fake store the App a for the adapter, as an upload of the App
// setup would.
func (f *fakeApiary) storeApp(a *app) {
	f.t.Helper()
	p, err := a.plaintext()
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets = p.Secrets
	// Secrets are stored only under a description that lists them, so the record of
	// the last enrolment has one.
	if f.described == nil {
		f.described = map[string][]string{}
	}
	names := make([]string, len(p.Secrets))
	for i, e := range p.Secrets {
		names[i] = e.Name
	}
	f.described[cmp.Or(f.node, testAdapterID)] = names
}

// storeTestApp makes the fake store [testApp].
func (f *fakeApiary) storeTestApp() { f.storeApp(testApp()) }

// stored are the secrets the fake stores, by name.
func (f *fakeApiary) stored() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	for _, e := range f.secrets {
		out[e.Name] = e.Value
	}
	return out
}

// uploaded are the plaintexts of the uploads the fake opened.
func (f *fakeApiary) uploaded() []contracts.AdapterSecretsPlaintext {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.uploads)
}

// sealedSecrets is the body of the answer to GET /v1/adapter/secrets: the secrets the
// fake stores, sealed to the access key pub that signed the request, whose id is keyID,
// for the adapter of the last enrolment, as adapter-secrets-answer.schema.json says, changed by
// sealing when it is set.
func (f *fakeApiary) sealedSecrets(pub accesskey.PublicKey, keyID string) string {
	f.mu.Lock()
	secrets := f.secrets
	if secrets == nil {
		secrets = []contracts.SecretEntry{}
	}
	pt, err := json.Marshal(contracts.AdapterSecretsPlaintext{Version: contracts.Version, Secrets: secrets})
	sealing, node := f.sealing, cmp.Or(f.node, testAdapterID)
	f.mu.Unlock()
	if err != nil {
		f.t.Fatal(err)
	}
	enc, ct := sealTo(f.t, pub, pt, contracts.SecretsInfo(keyID), contracts.SecretsAAD(node, keyID))
	doc := map[string]any{"version": contracts.Version, "revision": contracts.Revision, "sealed": map[string]any{
		"suite": contracts.SealSuite, "access_key_id": keyID, "enc": enc, "ct": ct,
	}}
	if sealing != nil {
		sealing(doc, keyID)
	}
	b, _ := json.Marshal(doc)
	return string(b)
}

// sealTo seals pt to the Ed25519 public key pub's X25519 form with info and aad, and
// returns enc and the ciphertext in base64url, as the contract writes them.
func sealTo(t *testing.T, pub accesskey.PublicKey, pt, info, aad []byte) (string, string) {
	t.Helper()
	u, err := pub.X25519()
	if err != nil {
		t.Fatal(err)
	}
	kem, kdf, aead := sealSuite()
	pk, err := kem.NewPublicKey(u)
	if err != nil {
		t.Fatal(err)
	}
	enc, sender, err := hpke.NewSender(pk, kdf, aead, info)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sender.Seal(aad, pt)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(enc), base64.RawURLEncoding.EncodeToString(ct)
}

// describe keeps the secret names of the description in the start-up body b as the
// latest of the adapter record of the last enrolment, and returns what puts the names
// before back.
func (f *fakeApiary) describe(b []byte) func() {
	var doc struct {
		Description struct {
			Roles struct {
				Source struct {
					Secrets []string `json:"secrets"`
				} `json:"source"`
			} `json:"roles"`
		} `json:"description"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		f.t.Errorf("the start-up body is not JSON: %v", err)
		return func() {}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.described == nil {
		f.described = map[string][]string{}
	}
	node := cmp.Or(f.node, testAdapterID)
	before, had := f.described[node]
	f.described[node] = doc.Description.Roles.Source.Secrets
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if had {
			f.described[node] = before
		} else {
			delete(f.described, node)
		}
	}
}

// openUpload opens the upload b, signed with the access key keyID, with the server
// key, as Qory Apiary does: info from sealed.server_key, aad from the adapter of the
// last enrolment and keyID. It returns the refusal's code: unknown_server_key for an
// upload sealed to another key than the server's, invalid_request for one that does
// not open, has no plaintext the contract takes, or has a secret whose name the source
// role of the record's latest description does not list, and "" for an accepted one,
// which replaces the secrets the fake stores.
func (f *fakeApiary) openUpload(b []byte, keyID string) string {
	var doc contracts.AdapterSecrets
	if err := json.Unmarshal(b, &doc); err != nil {
		return codeInvalidRequest
	}
	if doc.Sealed.ServerKey != f.server.PublicKey().String() {
		return codeUnknownServerKey
	}
	f.mu.Lock()
	node := cmp.Or(f.node, testAdapterID)
	f.mu.Unlock()
	pt, err := openSealedWith(f.server, doc.Sealed.Enc, doc.Sealed.CT, contracts.SecretsUploadInfo(doc.Sealed.ServerKey), contracts.SecretsAAD(node, keyID))
	if err != nil {
		return codeInvalidRequest
	}
	var p contracts.AdapterSecretsPlaintext
	if err := json.Unmarshal(pt, &p); err != nil || p.Version != contracts.Version || p.Check() != nil {
		return codeInvalidRequest
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range p.Secrets {
		if !slices.Contains(f.described[node], e.Name) {
			return codeInvalidRequest
		}
	}
	f.secrets = p.Secrets
	f.uploads = append(f.uploads, p)
	return ""
}

// openSealedWith opens enc and ct, in base64url, with key's X25519 form, info and aad.
func openSealedWith(key *accesskey.Key, enc, ct string, info, aad []byte) ([]byte, error) {
	e, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	c, err := base64.RawURLEncoding.DecodeString(ct)
	if err != nil {
		return nil, err
	}
	kem, kdf, aead := sealSuite()
	priv, err := kem.NewPrivateKey(key.X25519PrivateKey())
	if err != nil {
		return nil, err
	}
	r, err := hpke.NewRecipient(e, priv, kdf, aead, info)
	if err != nil {
		return nil, err
	}
	return r.Open(aad, c)
}

// grant adds to the fake's copy that connection holds the grant ref.
func (f *fakeApiary) grant(ref, connection string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.grants == nil {
		f.grants = map[string]string{}
	}
	f.grants[ref] = connection
}

// ungrant drops the grant ref from the fake's copy.
func (f *fakeApiary) ungrant(ref string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.grants, ref)
}

// grantsAnswer is the body of the answer to GET /v1/grants: the fake's copy, as
// grants.schema.json says.
func (f *fakeApiary) grantsAnswer() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := []map[string]string{}
	for ref, connection := range f.grants {
		list = append(list, map[string]string{"connection_id": connection, "grant_ref": ref})
	}
	b, _ := json.Marshal(map[string]any{"version": contracts.Version, "revision": contracts.Revision, "grants": list})
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
	return &Apiary{URL: f.srv.URL, KeyID: testKeyID, Key: key, Pin: pinOf(f.server), InstanceID: testInstance, ProgramVersion: testVersion}
}

// fakeGitHub is GitHub's API as the adapter reaches it for the installation 42 of
// acme: the token mint, the listing of the installation's repositories, one page, and
// acme/widgets's issues and comments, and a take in's label and comment on issue 7 and
// an undo's removal of the label, each by the repository's id, /repositories/{id}.
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
	// listAuth is the Authorization of each request for a page of the installation's
	// repositories.
	listAuth []string
	// installGone answers the check of the installation 42, GET /app/installations/42,
	// 404, as GitHub answers for an installation deleted; installUnauthorized answers it
	// 401, as GitHub answers an App's token it does not take; installSuspended answers
	// it 200 with suspended_at set, as for an installation suspended.
	installGone, installUnauthorized, installSuspended bool
	// installStatus, when set, answers the check of 42 with that status; goneAfterChecks,
	// when set, answers it 404 once that many checks of 42 were asked for, as for an
	// installation deleted meanwhile.
	installStatus, goneAfterChecks int
	// labelStatus, when set, answers the creation of the label in acme/widgets with
	// that status, as GitHub answers a write in an archived repository.
	labelStatus int
	// oldMintStatus, when set, answers a mint for acme/old with that status in place of
	// 422; oldPublic answers GET /repositories/{id} for acme/old 200, as GitHub answers
	// it for a public repository under any token.
	oldMintStatus int
	oldPublic     bool
	// oldGrant is how many mints for acme/old GitHub grants before it answers 422, and
	// oldRead, when set, is called once GitHub answered the read of acme/old by its id,
	// with f.mu held.
	oldGrant int
	oldRead  func()
	// refused are more repositories whose mint GitHub answers 422, by id, as it answers
	// acme/old's. issuesRead, when set, is called once GitHub answered the read of
	// acme/widgets's issues, with f.mu held.
	refused    []int64
	issuesRead func()
	// answered, when set, is called with each request, its method and URI, and its
	// body, once GitHub answered it, with f.mu held.
	answered func(f *fakeGitHub, request string, body []byte)
	// listingMintStatus, when set, answers a mint of 42's listing token, which names no
	// repository, with that status once its check passed; installLogin, when set, is
	// the login the check of 42 answers in place of acme.
	listingMintStatus int
	installLogin      string
	// checked are the installations besides 42 whose check GitHub answers 200, by id,
	// with their account's login; the check of any other answers 404.
	checked map[int64]string
	// unauthorized answers the listings of acme/widgets's issues, by REST and by
	// GraphQL, 401, as GitHub answers a token it no longer takes; issuesDown answers
	// them 502. goneComments answers that issue's comments 404, as for an issue deleted
	// while it is listed. reposDown answers every request under /repos/ and
	// /repositories/, and GraphQL's, 502.
	unauthorized, issuesDown, reposDown bool
	goneComments                        int
	// repoPageSize, when set, lists the installation's repositories that many on a
	// page, each page's Link header naming the next; repoPageDown answers that page,
	// counted from 1, 502. repoAfter, when set, is called with each page's number once
	// the page is answered, with f.mu held.
	repoPageSize, repoPageDown int
	repoAfter                  func(f *fakeGitHub, page int)
	// repoTotalOff is added to the total_count each page of the installation's
	// repositories answers, as when GitHub's count and its pages do not agree.
	repoTotalOff int
	// linkBase, when set, is the server the Link header's next page names, in place of
	// the fake's, as when the fake answers behind another server.
	linkBase string
	// gqlFailOn answers that page of GraphQL's listing, counted from 1, as gqlFail
	// says: "errors", a 200 whose errors say the query failed; "limited", a 200 that
	// says GraphQL's rate limit, for that page and every try after it; or "502".
	// onPage, when set, is called with each page's number and request before the page
	// is answered, without f.mu held. gqlPages counts the pages asked for.
	gqlFailOn int
	gqlFail   string
	onPage    func(page int, r *http.Request)
	gqlPages  int
	// readStatus, when set, answers the read of acme/widgets by its id, GET
	// /repositories/{id}, with that status and no repository. gqlIDSet makes GraphQL
	// answer gqlID as acme/widgets's fullDatabaseId, nil for none, or another
	// repository's id as a JSON string, as when the name came to name another repository
	// after it was read, and
	// gqlNotFound makes GraphQL answer that it resolves no repository by acme/widgets, as
	// when the name came to name none.
	readStatus  int
	gqlIDSet    bool
	gqlID       any
	gqlNotFound bool
	// issuesOff answers the read of acme/widgets by its id with has_issues false, as
	// GitHub answers for a repository with Issues turned off; issuesGone answers the
	// listing of its issues by REST 410 and GraphQL's with hasIssuesEnabled false, as
	// GitHub answers them once Issues are turned off.
	issuesOff, issuesGone bool
	// gqlAsked is the owner/name each GraphQL request named, in order.
	gqlAsked []string
	// envs are the repositories' environment definitions, by id, each a .devcontainer
	// folder's tree id; a repository it does not name has none. envFail answers each read
	// of environment definitions as it says: "node", an error for each node, or
	// "errors", an error that names no node. envAsked are the node ids each read named.
	// envAfter, when set, is called once each read is answered, with f.mu held.
	envs     map[int64]string
	envFail  string
	envAsked [][]string
	envAfter func(f *fakeGitHub)
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

// checksOf42 is how many checks of the installation 42 were asked for, the one being
// answered among them; f.mu is held.
func (f *fakeGitHub) checksOf42() int {
	n := 0
	for _, r := range f.requests {
		if r == "GET /app/installations/42" {
			n++
		}
	}
	return n
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := io.ReadAll(r.Body)
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	if f.answered != nil {
		defer f.answered(f, r.Method+" "+r.URL.RequestURI(), b)
	}
	w.Header().Set("Content-Type", "application/json")
	const widgets = "/repositories/" + widgetsRef
	moved := "/repositories/" + strconv.Itoa(movedID)
	switch {
	case r.Method == "GET" && r.URL.Path == "/app":
		answerApp(w, r)
	case r.Method == "GET" && r.URL.Path == "/app/installations/42" && (f.installGone || f.goneAfterChecks > 0 && f.checksOf42() > f.goneAfterChecks):
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found"}`)
	case r.Method == "GET" && r.URL.Path == "/app/installations/42" && f.installStatus != 0:
		w.WriteHeader(f.installStatus)
		io.WriteString(w, `{"message":"Not Found"}`)
	case r.Method == "GET" && r.URL.Path == "/app/installations/42" && f.installUnauthorized:
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Bad credentials"}`)
	case r.Method == "GET" && r.URL.Path == "/app/installations/42" && f.installSuspended:
		io.WriteString(w, `{"id":42,"account":{"login":"acme"},"suspended_at":"2026-10-01T00:00:00Z"}`)
	case r.Method == "GET" && r.URL.Path == "/app/installations/42" && f.installLogin != "":
		json.NewEncoder(w).Encode(map[string]any{"id": 42, "account": map[string]any{"login": f.installLogin}, "suspended_at": nil})
	case r.Method == "GET" && r.URL.Path == "/app/installations/42":
		io.WriteString(w, `{"id":42,"account":{"login":"acme"},"suspended_at":null}`)
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/app/installations/") && f.checked[checkedID(r.URL.Path)] != "":
		json.NewEncoder(w).Encode(map[string]any{"id": checkedID(r.URL.Path), "account": map[string]any{"login": f.checked[checkedID(r.URL.Path)]}, "suspended_at": nil})
	case r.Method == "POST" && r.URL.Path == "/app/installations/42/access_tokens" && strings.Contains(string(b), strconv.Itoa(oldID)) && f.oldGrant > 0:
		f.oldGrant--
		w.WriteHeader(201)
		io.WriteString(w, `{"token":"`+ghToken+`","expires_at":"2099-01-01T00:00:00Z"}`)
	case r.Method == "POST" && r.URL.Path == "/app/installations/42/access_tokens" && !strings.Contains(string(b), "repository_ids") && f.listingMintStatus != 0:
		w.WriteHeader(f.listingMintStatus)
		io.WriteString(w, `{"message":"`+http.StatusText(f.listingMintStatus)+`"}`)
	case r.Method == "POST" && r.URL.Path == "/app/installations/42/access_tokens" && strings.Contains(string(b), strconv.Itoa(oldID)) && f.oldMintStatus != 0:
		w.WriteHeader(f.oldMintStatus)
		io.WriteString(w, `{"message":"`+http.StatusText(f.oldMintStatus)+`"}`)
	case r.Method == "POST" && r.URL.Path == "/app/installations/42/access_tokens" && strings.Contains(string(b), strconv.Itoa(oldID)):
		// The installation no longer reaches acme/old.
		w.WriteHeader(422)
		io.WriteString(w, `{"message":"There is at least one repository that does not exist or is not accessible to the parent installation."}`)
	case r.Method == "POST" && r.URL.Path == "/app/installations/42/access_tokens" && slices.ContainsFunc(f.refused, func(id int64) bool { return strings.Contains(string(b), strconv.FormatInt(id, 10)) }):
		w.WriteHeader(422)
		io.WriteString(w, `{"message":"There is at least one repository that does not exist or is not accessible to the parent installation."}`)
	case r.Method == "GET" && r.URL.Path == "/repositories/"+strconv.Itoa(oldID) && f.oldPublic:
		io.WriteString(w, `{"id":`+strconv.Itoa(oldID)+`,"full_name":"acme/old","html_url":"https://github.com/acme/old","private":false}`)
		if f.oldRead != nil {
			f.oldRead()
		}
	case r.Method == "POST" && (r.URL.Path == "/app/installations/42/access_tokens" || r.URL.Path == "/app/installations/9/access_tokens"):
		f.mints = append(f.mints, string(b))
		w.WriteHeader(201)
		io.WriteString(w, `{"token":"`+ghToken+`","expires_at":"2099-01-01T00:00:00Z"}`)
	case r.Method == "GET" && r.URL.Path == "/installation/repositories":
		f.listAuth = append(f.listAuth, r.Header.Get("Authorization"))
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		page = max(page, 1)
		if page == f.repoPageDown {
			w.WriteHeader(502)
			io.WriteString(w, `{"message":"Bad Gateway"}`)
			return
		}
		names := f.repos
		if f.repoPageSize > 0 {
			from := min((page-1)*f.repoPageSize, len(names))
			if to := from + f.repoPageSize; to < len(names) {
				names = names[from:to]
				base := f.srv.URL
				if f.linkBase != "" {
					base = f.linkBase
				}
				w.Header().Set("Link", "<"+base+"/installation/repositories?per_page=100&page="+strconv.Itoa(page+1)+`>; rel="next"`)
			} else {
				names = names[from:]
			}
		}
		repos := []map[string]any{}
		for _, name := range names {
			repos = append(repos, map[string]any{"id": repoID(name), "node_id": nodeID(name), "full_name": name, "html_url": "https://github.com/" + name})
		}
		json.NewEncoder(w).Encode(map[string]any{"total_count": len(f.repos) + f.repoTotalOff, "repositories": repos})
		if f.repoAfter != nil {
			f.repoAfter(f, page)
		}
	case r.Method == "GET" && r.URL.Path == widgets && f.readStatus != 0:
		w.WriteHeader(f.readStatus)
		io.WriteString(w, `{"message":"`+http.StatusText(f.readStatus)+`"}`)
	case r.Method == "GET" && r.URL.Path == widgets && f.issuesOff:
		io.WriteString(w, `{"id":`+widgetsRef+`,"full_name":"acme/widgets","html_url":"https://github.com/acme/widgets","has_issues":false}`)
	case r.Method == "GET" && r.URL.Path == widgets:
		io.WriteString(w, `{"id":`+widgetsRef+`,"full_name":"acme/widgets","html_url":"https://github.com/acme/widgets"}`)
	case r.Method == "POST" && r.URL.Path == "/graphql":
		f.graphql(w, r, b)
	case f.reposDown && (strings.HasPrefix(r.URL.Path, "/repos/") || strings.HasPrefix(r.URL.Path, "/repositories/")):
		w.WriteHeader(502)
		io.WriteString(w, `{"message":"Bad Gateway"}`)
	case r.Method == "GET" && r.URL.Path == widgets+"/issues" && f.issuesGone:
		w.WriteHeader(410)
		io.WriteString(w, `{"message":"Issues are disabled for this repo"}`)
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
		if f.issuesRead != nil {
			f.issuesRead()
		}
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, widgets+"/issues/") && strings.HasSuffix(r.URL.Path, "/comments"):
		n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, widgets+"/issues/"), "/comments"))
		json.NewEncoder(w).Encode(append([]map[string]any{}, f.comments[n]...))
	case r.Method == "POST" && r.URL.Path == widgets+"/labels" && f.labelStatus != 0:
		w.WriteHeader(f.labelStatus)
		io.WriteString(w, `{"message":"Repository was archived so is read-only."}`)
	case r.Method == "POST" && r.URL.Path == widgets+"/labels":
		w.WriteHeader(201)
		w.Write(b)
	case r.Method == "POST" && r.URL.Path == widgets+"/issues/7/labels":
		f.labelled = append(f.labelled, string(b))
		io.WriteString(w, `[{"name":"qory"}]`)
	case r.Method == "DELETE" && r.URL.Path == widgets+"/issues/7/labels/qory":
		io.WriteString(w, `[]`)
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
		// acme/moved was renamed: GitHub redirects every request for it by name.
		w.Header().Set("Location", "https://api.github.com"+moved+strings.TrimPrefix(r.URL.Path, "/repos/acme/moved"))
		w.WriteHeader(301)
		io.WriteString(w, `{"message":"Moved Permanently"}`)
	case strings.HasPrefix(r.URL.Path, moved+"/") || r.URL.Path == moved:
		// A request by acme/moved's id is redirected too, as GitHub redirects a request for
		// an issue that was transferred.
		w.Header().Set("Location", "https://api.github.com/repositories/1"+strings.TrimPrefix(r.URL.Path, moved))
		w.WriteHeader(301)
		io.WriteString(w, `{"message":"Moved Permanently"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

// checkedID is the installation's id a check's path names, or 0.
func checkedID(path string) int64 {
	id, _ := strconv.ParseInt(strings.TrimPrefix(path, "/app/installations/"), 10, 64)
	return id
}

// graphql answers the listing of a repository's open issues by GraphQL's cursor, the
// repository named by owner/name and answered with its id, fullDatabaseId, a BigInt
// that GraphQL writes as a JSON string: acme/widgets's issues, open ones alone, first to
// a page after the cursor, which is the issue's place in f.issues; acme/moved as GitHub
// names it since it was renamed, with the same id; and any other repository as one
// GraphQL cannot resolve. f.mu is held.
func (f *fakeGitHub) graphql(w http.ResponseWriter, r *http.Request, b []byte) {
	var env struct {
		Variables struct {
			IDs []string `json:"ids"`
		} `json:"variables"`
	}
	if json.Unmarshal(b, &env); env.Variables.IDs != nil {
		f.environments(w, env.Variables.IDs)
		return
	}
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
	f.gqlAsked = append(f.gqlAsked, v.Owner+"/"+v.Name)
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
	id := repoID(name)
	switch {
	case name == "acme/widgets" && !f.gqlNotFound:
	case name == "acme/moved":
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
	var dbID any = strconv.FormatInt(id, 10)
	if name == "acme/widgets" && f.gqlIDSet {
		dbID = f.gqlID
	}
	json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"repository": map[string]any{
		"fullDatabaseId":   dbID,
		"nameWithOwner":    name,
		"url":              "https://github.com/" + name,
		"hasIssuesEnabled": name != "acme/widgets" || !f.issuesGone,
		"issues": map[string]any{
			"pageInfo": map[string]any{"hasNextPage": more, "endCursor": end},
			"nodes":    nodes,
		},
	}}})
}

// nodeID is the node id the fake gives the repository name, owner/name: R_ and its id.
func nodeID(name string) string { return "R_" + strconv.FormatInt(repoID(name), 10) }

// environments answers a read of the environment definitions of the repositories whose
// node ids are ids, by f.envs, as f.envFail says. f.mu is held.
func (f *fakeGitHub) environments(w http.ResponseWriter, ids []string) {
	f.envAsked = append(f.envAsked, ids)
	if f.envAfter != nil {
		defer f.envAfter(f)
	}
	if f.envFail == "errors" {
		io.WriteString(w, `{"data":null,"errors":[{"type":"SERVICE_UNAVAILABLE","message":"Something went wrong while executing your query."}]}`)
		return
	}
	nodes := []any{}
	errs := []any{}
	for i, node := range ids {
		id, _ := strconv.ParseInt(strings.TrimPrefix(node, "R_"), 10, 64)
		if f.envFail == "node" {
			nodes = append(nodes, nil)
			errs = append(errs, map[string]any{"type": "FORBIDDEN", "path": []any{"nodes", i}, "message": "Resource not accessible by integration"})
			continue
		}
		var dir any
		if oid, ok := f.envs[id]; ok {
			dir = map[string]any{"__typename": "Tree", "oid": oid}
		}
		nodes = append(nodes, map[string]any{"fullDatabaseId": strconv.FormatInt(id, 10), "dir": dir, "file": nil})
	}
	answer := map[string]any{"data": map[string]any{"nodes": nodes}}
	if len(errs) > 0 {
		answer["errors"] = errs
	}
	json.NewEncoder(w).Encode(answer)
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

// settingsFiles writes the access key's secret in dir, and returns settings that name
// it, Qory Apiary at apiaryURL, under the pin. The App is in no setting: a test that
// runs serve with one has the fake Qory Apiary store it, see [fakeApiary.storeTestApp].
func settingsFiles(t *testing.T, dir string, access *accesskey.Key, apiaryURL string, pin accesskey.Pin) Settings {
	t.Helper()
	accessFile := filepath.Join(dir, "access-key")
	writeFile(t, accessFile, access.Secret()+"\n", 0o600)
	return Settings{
		Listen: "127.0.0.1:0", StateDir: filepath.Join(dir, "state"),
		APIURL: appAPI(t), ApiaryURL: apiaryURL, PublicURL: "https://qory-github.example.com",
		AccessKeyID: testKeyID, AccessKeySecretFile: accessFile, ApiaryPublicKey: pin,
		AdapterID: testAdapterID,
	}
}

// testPEM is the App's key, appKey, in PEM.
func testPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(appKey())})
}

// testApp is the App most tests run serve with, as Qory Apiary delivers it: app_id 1,
// testSlug, the client testClientID, the key appKey, the webhook secret secret and the
// client secret clientSecret, its webhook active and its secret confirmed.
func testApp() *app {
	return &app{
		id: "1", numericID: 1, slug: testSlug, clientID: testClientID, pem: testPEM(), key: appKey(),
		webhookSecret: []byte(secret), clientSecret: []byte(clientSecret), webhookActive: true,
		owner: "acme", ownerKind: github.AccountOrganization, confirmed: true,
	}
}

// setupApp is the App the fake GitHub's conversion answers, setupAppID, as Qory Apiary
// stores it after the App setup.
func setupApp() *app {
	return &app{
		id: strconv.Itoa(setupAppID), numericID: setupAppID, slug: setupSlug, clientID: setupClientID, pem: []byte(strings.TrimSpace(appKeyPEM())), key: appKey(),
		webhookSecret: []byte(setupHookSecret), clientSecret: []byte(setupClientSecret), webhookActive: true,
		owner: "acme", ownerKind: github.AccountOrganization, confirmed: true,
	}
}

// tokenApp is the App id the App's token in the Authorization a names, its iss, or
// nothing when a holds no such token. The token's signature is not checked.
func tokenApp(a string) string {
	parts := strings.Split(strings.TrimPrefix(a, "Bearer "), ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	json.Unmarshal(b, &claims)
	return claims.Iss
}

// appAPI is the URL of GitHub's API as serve's check of the App at start reaches it,
// see [answerApp]; it answers every other request 404.
func appAPI(t *testing.T) string {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/app" {
			answerApp(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(api.Close)
	return api.URL
}

// answerApp answers GET /app as GitHub answers it for the App's token in r: the test
// App, app_id 1, is testSlug, and the setup's App, app_id setupAppID, is setupSlug; any
// other token is answered 401.
func answerApp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch tokenApp(r.Header.Get("Authorization")) {
	case "1":
		io.WriteString(w, `{"id":1,"slug":"`+testSlug+`"}`)
	case strconv.Itoa(setupAppID):
		io.WriteString(w, `{"id":`+strconv.Itoa(setupAppID)+`,"slug":"`+setupSlug+`"}`)
	default:
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"message":"A JSON web token could not be decoded"}`)
	}
}

// listings is how many listings of the installation's repositories the fake answered:
// the requests for their first page.
func (f *fakeGitHub) listings() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r == "GET /installation/repositories?per_page=100" {
			n++
		}
	}
	return n
}

// setReach seeds the store's record that installation reaches the repository ref, with
// no moment of a listing, Read 0, which a listing of any installation whose started_at
// parses takes, see [claimReach].
func setReach(st *store.Store, ref string, installation int64) error {
	b, err := json.Marshal(reach{Installation: installation, Ref: ref})
	if err != nil {
		return err
	}
	return st.Put(nsRepositories, collectionKey(ref), b, 0)
}

// keptFirsts is how many first listings the adapter keeps, see [Adapter.sendFirst].
func (a *Adapter) keptFirsts() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.firsts)
}

// keptFirst is whether the adapter keeps a first listing for the installation and
// connection, see [Adapter.sendFirst].
func (a *Adapter) keptFirst(installation int64, connection string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.firsts[firstKey{installation, connection}] != nil
}

// grantedLink links the installation to the connection, in state, as [Link] does, and
// keeps in the store's copy of Qory Apiary's grants that the connection holds its
// grant, so its deliveries are handled, see [granted].
func grantedLink(st *store.Store, installation int64, connection, state string) error {
	if err := Link(st, installation, connection, state); err != nil {
		return err
	}
	return putGrant(st, installation, connection)
}

// grantedPutLink keeps the installation's link l, as [putLink] does, and the grant of
// l's connection in the store's copy, see [grantedLink].
func grantedPutLink(st *store.Store, installation int64, l link) error {
	if err := putLink(st, installation, l); err != nil {
		return err
	}
	return putGrant(st, installation, l.Connection)
}
