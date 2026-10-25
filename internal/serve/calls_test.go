package serve

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// widgetsCommit is the commit of acme/widgets that main and v1.0 name in [callsGitHub].
const widgetsCommit = "0123456789abcdef0123456789abcdef01234567"

// callsGitHub is GitHub's API as the calls reach it, in front of [fakeGitHub], which
// answers the check of the installation 42 and everything else: the App's installation
// on acme's repositories, 42, by owner/name in any case; a repository by its name, each
// of acme's; the mint of a token limited to repositories by id, which lists them as
// GitHub's answer does, and answers 422 for one in refused; acme/widgets's commits at
// main, v1.0 and widgetsCommit; and acme/widgets's files at that commit: README.md,
// docs, a directory, big.txt, past the read's limit, and bin, with a NUL.
type callsGitHub struct {
	gh  *fakeGitHub
	srv *httptest.Server

	mu       sync.Mutex
	mints    []string
	requests []string
	// refused are the repositories whose mint GitHub answers 422; mintStatus, when set,
	// answers every mint with that status.
	refused    []int64
	mintStatus int
}

func newCallsGitHub(t *testing.T) *callsGitHub {
	t.Helper()
	c := &callsGitHub{gh: newFakeGitHub(t)}
	c.srv = httptest.NewServer(c)
	t.Cleanup(c.srv.Close)
	return c
}

func (c *callsGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(b))
	c.requests = append(c.requests, r.Method+" "+r.URL.RequestURI())
	w.Header().Set("Content-Type", "application/json")
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	widgets := "/repositories/" + widgetsRef
	switch {
	case r.Method == "GET" && len(parts) == 4 && parts[0] == "repos" && parts[3] == "installation":
		if !strings.EqualFold(parts[1], "acme") || tokenApp(r.Header.Get("Authorization")) != "1" {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Not Found"}`)
			return
		}
		io.WriteString(w, `{"id":42,"account":{"login":"acme"}}`)
	case r.Method == "GET" && len(parts) == 3 && parts[0] == "repos":
		if !strings.EqualFold(parts[1], "acme") || r.Header.Get("Authorization") != "Bearer "+ghToken {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Not Found"}`)
			return
		}
		name := "acme/" + strings.ToLower(parts[2])
		json.NewEncoder(w).Encode(map[string]any{"id": repoID(name), "full_name": name})
	case r.Method == "POST" && r.URL.Path == "/app/installations/42/access_tokens" && strings.Contains(string(b), "repository_ids"):
		c.mints = append(c.mints, string(b))
		var req struct {
			IDs []int64 `json:"repository_ids"`
		}
		json.Unmarshal(b, &req)
		if c.mintStatus != 0 {
			w.WriteHeader(c.mintStatus)
			io.WriteString(w, `{"message":"`+http.StatusText(c.mintStatus)+`"}`)
			return
		}
		repos := []map[string]any{}
		for _, id := range req.IDs {
			if slices.Contains(c.refused, id) {
				w.WriteHeader(422)
				io.WriteString(w, `{"message":"The permissions requested are not granted to this installation."}`)
				return
			}
			for name, known := range knownIDs {
				if known == id && strings.HasPrefix(name, "acme/") && name != "acme/sprockets" {
					repos = append(repos, map[string]any{"id": id, "full_name": name})
				}
			}
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"token": ghToken, "expires_at": "2099-01-01T00:00:00Z", "repositories": repos})
	case r.Method == "GET" && r.URL.Path == widgets+"/commits":
		switch r.URL.Query().Get("sha") {
		case "main", "v1.0", widgetsCommit:
			io.WriteString(w, `[{"sha":"`+widgetsCommit+`"}]`)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"No commit found for SHA: nothing"}`)
		}
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, widgets+"/contents/") && r.URL.Query().Get("ref") == widgetsCommit:
		file := func(content []byte, size int) {
			json.NewEncoder(w).Encode(map[string]any{"type": "file", "size": size, "encoding": "base64", "content": base64.StdEncoding.EncodeToString(content)})
		}
		switch strings.TrimPrefix(r.URL.EscapedPath(), widgets+"/contents/") {
		case "README.md":
			file([]byte("# Widgets\n"), 10)
		case "docs/a%20b.md":
			file([]byte("spaced"), 6)
		case "docs":
			io.WriteString(w, `[{"type":"file","name":"a b.md"}]`)
		case "big.txt":
			file(nil, contracts.ReadContentMaxBytes+1)
		case "bin":
			file([]byte("a\x00b"), 3)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Not Found"}`)
		}
	default:
		c.mu.Unlock()
		c.gh.ServeHTTP(w, r)
		c.mu.Lock()
	}
}

// mintsSoFar are the bodies of the mints limited to repositories so far.
func (c *callsGitHub) mintsSoFar() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.mints...)
}

// callsRig is [Calls] for the installation 42, linked, which reaches acme/widgets and
// acme/gadgets, behind [Calls.Route] on a server, with Qory Apiary's key server, which
// the pin lists, and the adapter's access key access.
type callsRig struct {
	st     *store.Store
	gh     *callsGitHub
	calls  *Calls
	server *accesskey.Key
	access *accesskey.Key
	log    *syncBuffer
	srv    *httptest.Server
	// base is the time the rig's call bodies count back from, and bodies counts
	// them, see [callsRig.callBody].
	base   time.Time
	bodies atomic.Int64
}

func newCallsRig(t *testing.T) *callsRig {
	t.Helper()
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	rig := &callsRig{st: st, gh: newCallsGitHub(t), server: newKey(t), access: newKey(t), log: &syncBuffer{}, base: time.Now()}
	if err := grantedLink(st, 42, testConnection, linkLive); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{widgetsRef, gadgetsRef} {
		if err := setReach(st, ref, 42); err != nil {
			t.Fatal(err)
		}
	}
	gh := github.Client{API: rig.gh.srv.URL}
	adapter := &Adapter{Store: st, GitHub: gh, AppID: "1", Key: appKey(), Slug: testSlug}
	rig.calls = &Calls{
		Store: st, Grants: storeGrants{st: st}, GitHub: gh, AppID: "1", Key: appKey(), InstanceID: testInstance,
		Log:   slog.New(slog.NewJSONHandler(rig.log, nil)),
		creds: &credentials{e: enrolment{keyID: testKeyID, key: rig.access, pin: pinOf(rig.server), adapterID: testAdapterID}},
		listingToken: func(ctx context.Context, installation int64) (string, error) {
			return adapter.token(ctx, installation, 0, "")
		},
		refusalEvery: time.Nanosecond,
	}
	rig.srv = httptest.NewServer(rig.calls.Route(http.NotFoundHandler()))
	t.Cleanup(rig.srv.Close)
	t.Cleanup(func() {
		for _, secret := range []string{ghToken, rig.access.Secret(), string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(appKey())}))[40:80]} {
			if strings.Contains(rig.log.String(), secret) {
				t.Errorf("a line has a secret: %s", strings.ReplaceAll(rig.log.String(), secret, "[secret]"))
			}
		}
	})
	return rig
}

// signedCall is one call as the rig sends it: the path it is sent to, the path, the
// adapter id and the instance id its signature covers, the key that signs it, and
// headers set or deleted after it is signed.
type signedCall struct {
	sentTo, path, adapterID, instance string
	signer                            *accesskey.Key
	method                            string
	edit                              func(h http.Header)
}

// answer is the rig's answer to a call: its status, its body and whether its signature
// verifies under the access key, bound to the call's signature.
type callAnswer struct {
	status int
	body   []byte
	signed bool
	header http.Header
}

// send sends body as the call c, Qory Apiary's server key signing it unless c names
// another signer, to the path c names or else c.path.
func (rig *callsRig) send(t *testing.T, c signedCall, body string) callAnswer {
	t.Helper()
	if c.signer == nil {
		c.signer = rig.server
	}
	if c.adapterID == "" {
		c.adapterID = testAdapterID
	}
	if c.instance == "" {
		c.instance = testInstance
	}
	if c.method == "" {
		c.method = http.MethodPost
	}
	m, _ := contracts.Call{AdapterID: c.adapterID, InstanceID: c.instance, Method: http.MethodPost, Path: c.path, Body: []byte(body)}.Message()
	sig := base64.RawURLEncoding.EncodeToString(c.signer.Sign(m))
	req, err := http.NewRequest(c.method, rig.srv.URL+callsPath+cmpOr(c.sentTo, c.path), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(accesskey.HeaderSignature, sig)
	req.Header.Set(contracts.HeaderAdapterID, c.adapterID)
	req.Header.Set(accesskey.HeaderInstanceID, c.instance)
	req.Header.Set(headerContractVersion, "1")
	if c.edit != nil {
		c.edit(req.Header)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	got := callAnswer{status: resp.StatusCode, body: b, header: resp.Header}
	if v := resp.Header.Values(accesskey.HeaderSignature); len(v) == 1 {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(v[0])
		got.signed = err == nil && rig.access.PublicKey().Verify(contracts.CallAnswer{Status: resp.StatusCode, CallSignature: req.Header.Get(accesskey.HeaderSignature), Body: b}.Message(), raw)
	}
	return got
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// callBody is a call's body: the members given, and a time a second earlier than the
// body built before it in the rig, counted from the rig's time base. No two bodies of
// one rig share a time, so no two share a signature by accident: the same body sent
// twice is a replay. A rig builds fewer than 250 bodies, so each time is within the
// 300 seconds a call may be off the clock.
func (rig *callsRig) callBody(members string) string {
	n := rig.bodies.Add(1)
	return callBodyAt(rig.base.Add(-time.Duration(n)*time.Second), members)
}

func callBodyAt(at time.Time, members string) string {
	return `{"version":1,"time":"` + contracts.FormatTime(at) + `",` + members + `}`
}

// shown is an answer's body for a test's output, with the token the fake mints in
// place of [token], so no output has it.
func shown(b []byte) string { return strings.ReplaceAll(string(b), ghToken, "[token]") }

// checkAnswer reports an answer that is not signed, not status, or whose body breaks
// the schema name, or is not the refusal code when code is set.
func checkAnswer(t *testing.T, got callAnswer, status int, schema, code string) {
	t.Helper()
	if got.status != status || !got.signed {
		t.Fatalf("answered %d, signed %v, %s; want %d signed", got.status, got.signed, shown(got.body), status)
	}
	s, err := contracts.Compile(schema)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(got.body))
	if err == nil {
		err = s.Validate(doc)
	}
	if err != nil {
		t.Errorf("the answer %s breaks %s: %v", shown(got.body), schema, err)
	}
	if code != "" && string(got.body) != `{"error":"`+code+`"}` {
		t.Errorf("answered %s, want the refusal %s", shown(got.body), code)
	}
}

// checkUnsigned reports an answer that is signed, not status, or not the refusal code.
func checkUnsigned(t *testing.T, what string, got callAnswer, status int, code string) {
	t.Helper()
	if got.status != status || len(got.header.Values(accesskey.HeaderSignature)) != 0 || string(got.body) != `{"error":"`+code+`"}` {
		t.Errorf("%s: answered %d, signature %q, %s; want %d unsigned %s", what, got.status, got.header.Get(accesskey.HeaderSignature), shown(got.body), status, code)
	}
}

const widgetsAddress = `"addresses":["https://github.com/acme/widgets"]`

// TestACallIsCheckedBeforeItIsAnswered pins the checks of a call: POST alone, a body
// of 1 MiB at most, a signature under the pin over the call's path, the adapter id and
// the instance id serve is enrolled with, a time within 300 seconds, and no replay,
// each refused with the unsigned answer; and, once the call verifies, the contract's
// revision, the call's schema and a path that is a call's, each refused with a signed
// answer. A call that passes them all is answered signed with the access key, bound to
// the call's signature.
func TestACallIsCheckedBeforeItIsAnswered(t *testing.T) {
	rig := newCallsRig(t)
	resolve := signedCall{path: contracts.ResolvePath}
	checkAnswer(t, rig.send(t, resolve, rig.callBody(widgetsAddress)), 200, "resolve-answer.schema.json", "")

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		got := rig.send(t, signedCall{path: contracts.ResolvePath, method: method}, rig.callBody(widgetsAddress))
		checkUnsigned(t, method, got, http.StatusMethodNotAllowed, codeMethodNotAllowed)
		if got.header.Get("Allow") != http.MethodPost {
			t.Errorf("%s: Allow is %q", method, got.header.Get("Allow"))
		}
	}
	large := rig.callBody(`"addresses":["https://github.com/acme/` + strings.Repeat("a", contracts.MaxRequest) + `"]`)
	checkUnsigned(t, "a body over 1 MiB", rig.send(t, resolve, large), http.StatusRequestEntityTooLarge, codePayloadTooLarge)
	// A body sent in chunks, with no Content-Length, is cut at the limit as it arrives.
	m, _ := contracts.Call{AdapterID: testAdapterID, InstanceID: testInstance, Method: "POST", Path: contracts.ResolvePath, Body: []byte(large)}.Message()
	req, _ := http.NewRequest(http.MethodPost, rig.srv.URL+callsPath+contracts.ResolvePath, io.MultiReader(strings.NewReader(large)))
	req.Header.Set(accesskey.HeaderSignature, base64.RawURLEncoding.EncodeToString(rig.server.Sign(m)))
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusRequestEntityTooLarge || resp.Header.Get(accesskey.HeaderSignature) != "" {
		t.Errorf("a body in chunks over 1 MiB: %v %v", resp, err)
	}

	stranger := newKey(t)
	for name, c := range map[string]signedCall{
		"signed by a key the pin does not list":      {path: contracts.ResolvePath, signer: stranger},
		"signed by the adapter's access key":         {path: contracts.ResolvePath, signer: rig.access},
		"signed for another adapter":                 {path: contracts.ResolvePath, adapterID: "na_fedcba9876543210"},
		"signed for another instance":                {path: contracts.ResolvePath, instance: "i_BBBBBBBBBBBBBBBBBBBBBB"},
		"signed for the path read, sent to resolve":  {path: contracts.ReadPath, sentTo: contracts.ResolvePath},
		"without a signature":                        {path: contracts.ResolvePath, edit: func(h http.Header) { h.Del(accesskey.HeaderSignature) }},
		"with the signature twice":                   {path: contracts.ResolvePath, edit: func(h http.Header) { h.Add(accesskey.HeaderSignature, h.Get(accesskey.HeaderSignature)) }},
		"with a signature that is not base64url":     {path: contracts.ResolvePath, edit: func(h http.Header) { h.Set(accesskey.HeaderSignature, h.Get(accesskey.HeaderSignature)+"=") }},
		"without the adapter id":                     {path: contracts.ResolvePath, edit: func(h http.Header) { h.Del(contracts.HeaderAdapterID) }},
		"with the adapter id twice":                  {path: contracts.ResolvePath, edit: func(h http.Header) { h.Add(contracts.HeaderAdapterID, testAdapterID) }},
		"with another adapter id than it was signed": {path: contracts.ResolvePath, edit: func(h http.Header) { h.Set(contracts.HeaderAdapterID, "na_fedcba9876543210") }},
		"without the instance id":                    {path: contracts.ResolvePath, edit: func(h http.Header) { h.Del(accesskey.HeaderInstanceID) }},
	} {
		checkUnsigned(t, name, rig.send(t, c, rig.callBody(widgetsAddress)), http.StatusUnauthorized, codeUnauthorized)
	}
	for _, off := range []time.Duration{-301 * time.Second, 301 * time.Second, -time.Hour} {
		checkUnsigned(t, "a time "+off.String()+" from the clock", rig.send(t, resolve, callBodyAt(time.Now().Add(off), widgetsAddress)), http.StatusUnauthorized, codeUnauthorized)
	}
	checkAnswer(t, rig.send(t, resolve, callBodyAt(time.Now().Add(-250*time.Second), widgetsAddress)), 200, "resolve-answer.schema.json", "")

	// The same call again is a replay, whose signature serve kept.
	body := rig.callBody(`"addresses":["https://github.com/acme/gadgets"]`)
	checkAnswer(t, rig.send(t, resolve, body), 200, "resolve-answer.schema.json", "")
	checkUnsigned(t, "a replay", rig.send(t, resolve, body), http.StatusUnauthorized, codeUnauthorized)

	for name, edit := range map[string]func(http.Header){
		"no X-Qory-Contract-Version":   func(h http.Header) { h.Del(headerContractVersion) },
		"X-Qory-Contract-Version 2":    func(h http.Header) { h.Set(headerContractVersion, "2") },
		"X-Qory-Contract-Version x":    func(h http.Header) { h.Set(headerContractVersion, "x") },
		"X-Qory-Contract-Version 1.0":  func(h http.Header) { h.Set(headerContractVersion, "1.0") },
		"X-Qory-Contract-Version sent": func(h http.Header) { h.Add(headerContractVersion, "1") },
	} {
		got := rig.send(t, signedCall{path: contracts.ResolvePath, edit: edit}, rig.callBody(widgetsAddress))
		t.Run(name, func(t *testing.T) {
			checkAnswer(t, got, http.StatusBadRequest, "refusal.schema.json", codeUnsupportedContractVersion)
		})
	}
	for name, body := range map[string]string{
		"a member the schema does not define": rig.callBody(widgetsAddress + `,"extra":1`),
		"a member twice":                      rig.callBody(widgetsAddress + `,` + widgetsAddress),
		"the version twice":                   rig.callBody(widgetsAddress + `,"version":1`),
		"a version with a fraction":           strings.Replace(rig.callBody(widgetsAddress), `"version":1`, `"version":1.0`, 1),
		"no time":                             `{"version":1,` + widgetsAddress + `}`,
		"a time with a fraction of a second":  `{"version":1,"time":"` + time.Now().UTC().Format("2006-01-02T15:04:05.000Z") + `",` + widgetsAddress + `}`,
		"no addresses":                        rig.callBody(`"addresses":[]`),
		"a value after the body":              rig.callBody(widgetsAddress) + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			checkAnswer(t, rig.send(t, resolve, body), http.StatusBadRequest, "refusal.schema.json", codeInvalidRequest)
		})
	}
	checkAnswer(t, rig.send(t, signedCall{path: "credentials"}, rig.callBody(widgetsAddress)), http.StatusNotFound, "refusal.schema.json", codeNotFound)
	if !strings.Contains(rig.log.String(), `"msg":"call answered without a signature","call":"resolve","status":401`) {
		t.Errorf("no line for a 401: %s", rig.log.String())
	}
}

// TestCallsBeyondTheBoundAreAnswered503 pins that a call beyond [maxCallsAtOnce] held
// at once is answered with the unsigned 503 before its body is read.
func TestCallsBeyondTheBoundAreAnswered503(t *testing.T) {
	rig := newCallsRig(t)
	rig.calls.init()
	for range maxCallsAtOnce {
		rig.calls.slots <- struct{}{}
	}
	checkUnsigned(t, "a call beyond the bound", rig.send(t, signedCall{path: contracts.ResolvePath}, rig.callBody(widgetsAddress)), http.StatusServiceUnavailable, codeBusy)
	<-rig.calls.slots
	checkAnswer(t, rig.send(t, signedCall{path: contracts.ResolvePath}, rig.callBody(widgetsAddress)), 200, "resolve-answer.schema.json", "")
}

// harnessCall is a run-credential call's members for a harness under the grant.
func harnessCall(grant string, resources []string, access string) string {
	rs, _ := json.Marshal(resources)
	return `"grant_ref":"` + grant + `","resources":` + string(rs) + `,"access":"` + access + `","purpose":"harness"`
}

// workCall is a run-credential call's members for work under the connection, with the
// one resource ref.
func workCall(connection, ref, access string) string {
	return `"connection_id":"` + connection + `","resources":["` + ref + `"],"access":"` + access + `","purpose":"work"`
}

// TestARunCredentialForWorkMapsTheAccess pins a run credential for work: access read
// mints contents, metadata and pull_requests read, access write contents and
// pull_requests write, never workflows, for the one repository alone, by id; the answer
// is [github.Uses] for that repository: the token on github.com with basic and
// x-access-token on its git paths, and on api.github.com with bearer on its API paths,
// with GitHub's expiry.
func TestARunCredentialForWorkMapsTheAccess(t *testing.T) {
	for access, perms := range map[string]string{
		"read":  `{"contents":"read","metadata":"read","pull_requests":"read"}`,
		"write": `{"contents":"write","pull_requests":"write"}`,
	} {
		t.Run(access, func(t *testing.T) {
			rig := newCallsRig(t)
			got := rig.send(t, signedCall{path: contracts.RunCredentialPath}, rig.callBody(workCall(testConnection, widgetsRef, access)))
			checkAnswer(t, got, 200, "run-credential-answer.schema.json", "")
			mints := rig.gh.mintsSoFar()
			if want := `{"permissions":` + perms + `,"repository_ids":[` + widgetsRef + `]}`; len(mints) != 1 || mints[0] != want {
				t.Errorf("minted %q, want %s", mints, want)
			}
			var ans contracts.RunCredentialAnswer
			json.Unmarshal(got.body, &ans)
			want := contracts.RunCredentialAnswer{Version: 1, Revision: contracts.Revision, Credential: contracts.Credential{
				Version: 1, Token: ghToken, ExpiresAt: "2099-01-01T00:00:00Z", Apply: []contracts.CredentialApply{
					{Hosts: []string{"github.com"}, Scheme: "basic", Username: "x-access-token", Paths: []string{"/acme/widgets.git/*", "/acme/widgets/*"}},
					{Hosts: []string{"api.github.com"}, Scheme: "bearer", Paths: []string{"/repos/acme/widgets", "/repos/acme/widgets/*", "/graphql"}},
				},
			}}
			if fmt.Sprint(ans) != fmt.Sprint(want) {
				t.Errorf("answered %s", shown(got.body))
			}
			uses := github.Uses([]github.Repository{{Owner: "acme", Name: "widgets"}})
			if len(uses) != len(ans.Credential.Apply) {
				t.Fatalf("answered %d apply items, want %d", len(ans.Credential.Apply), len(uses))
			}
			for i, u := range uses {
				if fmt.Sprint(ans.Credential.Apply[i]) != fmt.Sprint(contracts.CredentialApply{Hosts: u.Hosts, Scheme: u.Scheme, Username: u.Username, Paths: u.Paths}) {
					t.Errorf("apply item %d is %v, want %v", i, ans.Credential.Apply[i], u)
				}
			}
		})
	}
}

// TestARunCredentialForAHarnessReadsContentsOnGitHubAlone pins a run credential for a
// harness: contents read, and one apply item, github.com on the repositories' git
// paths, with nothing for api.github.com. A call for a harness with access write gets
// 400 invalid_request, as run-credential.schema.json requires, and nothing is minted.
func TestARunCredentialForAHarnessReadsContentsOnGitHubAlone(t *testing.T) {
	rig := newCallsRig(t)
	got := rig.send(t, signedCall{path: contracts.RunCredentialPath}, rig.callBody(harnessCall("42", []string{widgetsRef}, "write")))
	checkAnswer(t, got, http.StatusBadRequest, "refusal.schema.json", codeInvalidRequest)
	if mints := rig.gh.mintsSoFar(); len(mints) != 0 {
		t.Fatalf("minted %q for a harness call with access write", mints)
	}
	got = rig.send(t, signedCall{path: contracts.RunCredentialPath}, rig.callBody(harnessCall("42", []string{widgetsRef}, "read")))
	checkAnswer(t, got, 200, "run-credential-answer.schema.json", "")
	if mints := rig.gh.mintsSoFar(); len(mints) != 1 || mints[0] != `{"permissions":{"contents":"read"},"repository_ids":[`+widgetsRef+`]}` {
		t.Errorf("minted %q", mints)
	}
	var ans contracts.RunCredentialAnswer
	json.Unmarshal(got.body, &ans)
	if len(ans.Credential.Apply) != 1 || fmt.Sprint(ans.Credential.Apply[0]) != fmt.Sprint(contracts.CredentialApply{Hosts: []string{"github.com"}, Scheme: "basic", Username: "x-access-token", Paths: []string{"/acme/widgets.git/*", "/acme/widgets/*"}}) {
		t.Errorf("answered %s", shown(got.body))
	}
	if strings.Contains(string(got.body), "api.github.com") || strings.Contains(string(got.body), "graphql") {
		t.Errorf("a harness's credential reaches the API: %s", shown(got.body))
	}
	rig = newCallsRig(t)
	got = rig.send(t, signedCall{path: contracts.RunCredentialPath}, rig.callBody(harnessCall("42", []string{widgetsRef, gadgetsRef}, "read")))
	checkAnswer(t, got, 200, "run-credential-answer.schema.json", "")
	if mints := rig.gh.mintsSoFar(); len(mints) != 1 || mints[0] != `{"permissions":{"contents":"read"},"repository_ids":[`+widgetsRef+`,`+gadgetsRef+`]}` {
		t.Errorf("two resources: minted %q", mints)
	}
}

// TestARunCredentialWithNoResourcesMintsNothing pins that a run-credential call with an
// empty resources list gets 400 invalid_request and mints nothing: through the route,
// where the schema refuses it, and past the schema, where the code refuses it, since a
// mint that lists no repository covers every repository of the installation. Past the
// schema, a call for work with a grant_ref, with no connection_id or with two resources
// gets 400 invalid_request too.
func TestARunCredentialWithNoResourcesMintsNothing(t *testing.T) {
	rig := newCallsRig(t)
	for _, members := range []string{
		`"connection_id":"` + testConnection + `","resources":[],"access":"read","purpose":"work"`,
		harnessCall("42", []string{}, "read"),
	} {
		got := rig.send(t, signedCall{path: contracts.RunCredentialPath}, rig.callBody(members))
		checkAnswer(t, got, http.StatusBadRequest, "refusal.schema.json", codeInvalidRequest)
	}
	for name, req := range map[string]contracts.RunCredential{
		"work, nil resources":        {ConnectionID: testConnection, Access: "read", Purpose: "work"},
		"work, no resources":         {ConnectionID: testConnection, Resources: []string{}, Access: "read", Purpose: "work"},
		"harness, nil resources":     {GrantRef: "42", Access: "read", Purpose: "harness"},
		"harness, no resources":      {GrantRef: "42", Resources: []string{}, Access: "read", Purpose: "harness"},
		"work with a grant_ref":      {GrantRef: "42", ConnectionID: testConnection, Resources: []string{widgetsRef}, Access: "read", Purpose: "work"},
		"work with no connection":    {Resources: []string{widgetsRef}, Access: "read", Purpose: "work"},
		"work with two resources":    {ConnectionID: testConnection, Resources: []string{widgetsRef, gadgetsRef}, Access: "read", Purpose: "work"},
		"work with a bad connection": {ConnectionID: "ac_", Resources: []string{widgetsRef}, Access: "read", Purpose: "work"},
	} {
		req.Version = 1
		status, answer := rig.calls.runCredentialFor(context.Background(), req, time.Now())
		if refusal, _ := answer.(contracts.Refusal); status != http.StatusBadRequest || refusal.Error != codeInvalidRequest {
			t.Errorf("%s: answered %d %v", name, status, answer)
		}
	}
	if mints := rig.gh.mintsSoFar(); len(mints) != 0 {
		t.Errorf("minted %q for a refused call", mints)
	}
}

// TestARunCredentialIsRefusedInTheContractsOrder pins the refusals of a run credential
// for a harness: 409 grant_unknown for a grant_ref that is not a linked installation,
// or that GitHub has no more; 403 resource_not_covered for a repository the
// installation does not reach, with a line that names it, before anything is minted;
// 403 access_not_granted when GitHub returns 422 to the mint or the installation is
// suspended; and 503 source_unavailable when GitHub fails.
func TestARunCredentialIsRefusedInTheContractsOrder(t *testing.T) {
	rig := newCallsRig(t)
	send := func(grant string, resources ...string) callAnswer {
		return rig.send(t, signedCall{path: contracts.RunCredentialPath}, rig.callBody(harnessCall(grant, resources, "read")))
	}
	for _, grant := range []string{"7", "042", "+42", "0", "-42", "acme", "9223372036854775808"} {
		checkAnswer(t, send(grant, widgetsRef), http.StatusConflict, "refusal.schema.json", codeGrantUnknown)
	}
	for _, ref := range []string{refOf("acme/other"), "0" + widgetsRef, "acme/widgets", strconv.Itoa(oldID)} {
		checkAnswer(t, send("42", widgetsRef, ref), http.StatusForbidden, "refusal.schema.json", codeResourceNotCovered)
		if !strings.Contains(rig.log.String(), `"resource":"`+ref+`"`) {
			t.Errorf("no line names the resource %s: %s", ref, rig.log.String())
		}
	}
	if mints := rig.gh.mintsSoFar(); len(mints) != 0 {
		t.Errorf("minted %q for a refused call", mints)
	}
	rig.gh.mu.Lock()
	rig.gh.refused = []int64{gadgetsID}
	rig.gh.mu.Unlock()
	checkAnswer(t, send("42", widgetsRef, gadgetsRef), http.StatusForbidden, "refusal.schema.json", codeAccessNotGranted)
	rig.gh.mu.Lock()
	rig.gh.refused, rig.gh.mintStatus = nil, http.StatusBadGateway
	rig.gh.mu.Unlock()
	checkAnswer(t, send("42", widgetsRef), http.StatusServiceUnavailable, "refusal.schema.json", codeSourceUnavailable)
	rig.gh.mu.Lock()
	rig.gh.mintStatus = 0
	rig.gh.mu.Unlock()
	rig.gh.gh.mu.Lock()
	rig.gh.gh.installSuspended = true
	rig.gh.gh.mu.Unlock()
	checkAnswer(t, send("42", widgetsRef), http.StatusForbidden, "refusal.schema.json", codeAccessNotGranted)
	rig.gh.gh.mu.Lock()
	rig.gh.gh.installSuspended, rig.gh.gh.installGone = false, true
	rig.gh.gh.mu.Unlock()
	checkAnswer(t, send("42", widgetsRef), http.StatusConflict, "refusal.schema.json", codeGrantUnknown)
}

// TestAWorkCredentialGetsTheContractsRefusalsInOrder pins the refusals of a run
// credential for work, which has a connection_id and no grant_ref: 403
// resource_not_covered, with a line that contains the resource and the connection, and
// before anything is minted, for a resource that is not a repository's id, for a
// repository no installation reaches, for one whose installation is linked to another
// connection or whose link is pending, and for one whose installation's grant Qory
// Apiary's copy of the grants does not contain under the call's connection; then 403
// access_not_granted when GitHub returns 422 to the mint or the installation is
// suspended; 403 resource_not_covered, never 409 grant_unknown, when GitHub has the
// installation no more; and 503 source_unavailable when GitHub fails.
func TestAWorkCredentialGetsTheContractsRefusalsInOrder(t *testing.T) {
	rig := newCallsRig(t)
	send := func(connection, ref string) callAnswer {
		return rig.send(t, signedCall{path: contracts.RunCredentialPath}, rig.callBody(workCall(connection, ref, "write")))
	}
	notCovered := func(what, connection, ref string) {
		t.Helper()
		checkAnswer(t, send(connection, ref), http.StatusForbidden, "refusal.schema.json", codeResourceNotCovered)
		if !strings.Contains(rig.log.String(), `"connection":"`+connection+`","resource":"`+ref+`"`) {
			t.Errorf("%s: no line contains the connection and the resource: %s", what, rig.log.String())
		}
	}
	for _, ref := range []string{refOf("acme/other"), "0" + widgetsRef, "acme/widgets", strconv.Itoa(oldID), "42"} {
		notCovered("ref "+ref, testConnection, ref)
	}
	notCovered("another connection", otherConnection, widgetsRef)

	if err := putLink(rig.st, 42, link{Connection: testConnection, State: linkPending}); err != nil {
		t.Fatal(err)
	}
	notCovered("a pending link", testConnection, widgetsRef)

	if err := putLink(rig.st, 42, link{Connection: testConnection, State: linkLive}); err != nil {
		t.Fatal(err)
	}
	if err := putGrant(rig.st, 42, otherConnection); err != nil {
		t.Fatal(err)
	}
	notCovered("a grant the copy has under another connection", testConnection, widgetsRef)

	if err := grantedLink(rig.st, 42, otherConnection, linkLive); err != nil {
		t.Fatal(err)
	}
	notCovered("a collection moved to another connection", testConnection, widgetsRef)
	if mints := rig.gh.mintsSoFar(); len(mints) != 0 {
		t.Fatalf("minted %q for a refused call", mints)
	}

	if err := grantedLink(rig.st, 42, testConnection, linkLive); err != nil {
		t.Fatal(err)
	}
	rig.gh.mu.Lock()
	rig.gh.refused = []int64{widgetsID}
	rig.gh.mu.Unlock()
	checkAnswer(t, send(testConnection, widgetsRef), http.StatusForbidden, "refusal.schema.json", codeAccessNotGranted)
	rig.gh.mu.Lock()
	rig.gh.refused, rig.gh.mintStatus = nil, http.StatusBadGateway
	rig.gh.mu.Unlock()
	checkAnswer(t, send(testConnection, widgetsRef), http.StatusServiceUnavailable, "refusal.schema.json", codeSourceUnavailable)
	rig.gh.mu.Lock()
	rig.gh.mintStatus = 0
	rig.gh.mu.Unlock()
	rig.gh.gh.mu.Lock()
	rig.gh.gh.installSuspended = true
	rig.gh.gh.mu.Unlock()
	checkAnswer(t, send(testConnection, widgetsRef), http.StatusForbidden, "refusal.schema.json", codeAccessNotGranted)
	rig.gh.gh.mu.Lock()
	rig.gh.gh.installSuspended, rig.gh.gh.installGone = false, true
	rig.gh.gh.mu.Unlock()
	checkAnswer(t, send(testConnection, widgetsRef), http.StatusForbidden, "refusal.schema.json", codeResourceNotCovered)
	rig.gh.gh.mu.Lock()
	rig.gh.gh.installGone = false
	rig.gh.gh.mu.Unlock()
	checkAnswer(t, send(testConnection, widgetsRef), http.StatusOK, "run-credential-answer.schema.json", "")
}

// TestResolveMapsGitHubAddressesToTheInstallation pins resolve: an https address of a
// repository on github.com, with or without .git, in any case of its owner, is the
// installation of the App on that owner and the repository's id, when the installation
// is linked and reaches the repository; every other address is covered: false, the scp
// form among them, in the call's order.
func TestResolveMapsGitHubAddressesToTheInstallation(t *testing.T) {
	rig := newCallsRig(t)
	addresses := []string{
		"https://github.com/acme/widgets",
		"https://github.com/ACME/Widgets.git",
		"https://github.com/Acme/gadgets",
		"git@github.com:acme/widgets.git",
		"ssh://git@github.com/acme/widgets.git",
		"https://github.com/octo-org/widgets",
		"https://github.com/acme/other",
		"https://example.com/acme/widgets",
		"https://github.com/acme/widgets/tree/main",
		"https://github.com/acme/widgets.git.git",
		"http://github.com/acme/widgets",
		"https://github.com/acme/widgets?x=1",
	}
	b, _ := json.Marshal(addresses)
	got := rig.send(t, signedCall{path: contracts.ResolvePath}, rig.callBody(`"addresses":`+string(b)))
	checkAnswer(t, got, 200, "resolve-answer.schema.json", "")
	var ans contracts.ResolveAnswer
	json.Unmarshal(got.body, &ans)
	covered := map[string]string{addresses[0]: widgetsRef, addresses[1]: widgetsRef, addresses[2]: gadgetsRef}
	if len(ans.Results) != len(addresses) {
		t.Fatalf("answered %s", shown(got.body))
	}
	for i, r := range ans.Results {
		ref, ok := covered[addresses[i]]
		switch {
		case r.Address != addresses[i]:
			t.Errorf("result %d is for %q, want %q", i, r.Address, addresses[i])
		case ok && (r.GrantRef != "42" || r.ResourceRef != ref || r.Covered != nil):
			t.Errorf("%s: %+v, want grant 42 and resource %s", addresses[i], r, ref)
		case !ok && (r.Covered == nil || *r.Covered || r.GrantRef != "" || r.ResourceRef != ""):
			t.Errorf("%s: %+v, want covered: false", addresses[i], r)
		}
	}
	// An installation that is not linked, or no longer reaches the repository, covers
	// nothing.
	if err := dropReach(rig.st, gadgetsRef, 42); err != nil {
		t.Fatal(err)
	}
	got = rig.send(t, signedCall{path: contracts.ResolvePath}, rig.callBody(`"addresses":["https://github.com/acme/gadgets"]`))
	if !strings.Contains(string(got.body), `"covered":false`) {
		t.Errorf("a repository the installation does not reach: %s", shown(got.body))
	}
	if err := Unlink(rig.st, 42); err != nil {
		t.Fatal(err)
	}
	got = rig.send(t, signedCall{path: contracts.ResolvePath}, rig.callBody(widgetsAddress))
	if !strings.Contains(string(got.body), `"covered":false`) {
		t.Errorf("an installation not linked: %s", shown(got.body))
	}
}

// read is a read call's members.
func read(grant, resource, path, at string) string {
	return `"grant_ref":"` + grant + `","resource_ref":"` + resource + `","path":"` + path + `","at":"` + at + `"`
}

// TestReadReadsAFileAtAVersion pins read: the file's text at the commit a branch, a tag
// or a commit names, with that commit as resolved_at, read with a token that reads that
// repository's contents alone, minted once; found: false for a path the commit has no
// file at; 404 version_not_found for a version the repository does not have; 409
// document_not_text for a directory, a file past the limit and one with a NUL; and the
// grant's and the resource's refusals.
func TestReadReadsAFileAtAVersion(t *testing.T) {
	rig := newCallsRig(t)
	send := func(members string) callAnswer {
		return rig.send(t, signedCall{path: contracts.ReadPath}, rig.callBody(members))
	}
	for _, at := range []string{"main", "v1.0", widgetsCommit} {
		got := send(read("42", widgetsRef, "README.md", at))
		checkAnswer(t, got, 200, "read-answer.schema.json", "")
		if want := `{"version":1,"revision":1,"content":"# Widgets\n","resolved_at":"` + widgetsCommit + `"}`; string(got.body) != want {
			t.Errorf("at %s: answered %s, want %s", at, shown(got.body), want)
		}
	}
	got := send(read("42", widgetsRef, "docs/a b.md", "main"))
	if checkAnswer(t, got, 200, "read-answer.schema.json", ""); !strings.Contains(string(got.body), `"content":"spaced"`) {
		t.Errorf("a path with a space: %s", shown(got.body))
	}
	if mints := rig.gh.mintsSoFar(); len(mints) != 1 || mints[0] != `{"permissions":{"contents":"read"},"repository_ids":[`+widgetsRef+`]}` {
		t.Errorf("minted %q, want one token that reads acme/widgets's contents", mints)
	}
	got = send(read("42", widgetsRef, "missing.md", "main"))
	checkAnswer(t, got, 200, "read-answer.schema.json", "")
	if want := `{"version":1,"revision":1,"found":false,"resolved_at":"` + widgetsCommit + `"}`; string(got.body) != want {
		t.Errorf("a missing file: answered %s, want %s", shown(got.body), want)
	}
	checkAnswer(t, send(read("42", widgetsRef, "README.md", "nothing")), http.StatusNotFound, "refusal.schema.json", codeVersionNotFound)
	for _, path := range []string{"docs", "big.txt", "bin"} {
		checkAnswer(t, send(read("42", widgetsRef, path, "main")), http.StatusConflict, "refusal.schema.json", codeDocumentNotText)
	}
	checkAnswer(t, send(read("7", widgetsRef, "README.md", "main")), http.StatusConflict, "refusal.schema.json", codeGrantUnknown)
	checkAnswer(t, send(read("42", refOf("acme/other"), "README.md", "main")), http.StatusForbidden, "refusal.schema.json", codeResourceNotCovered)
	for _, path := range []string{"../README.md", "/README.md", "docs/", "a//b"} {
		checkAnswer(t, send(read("42", widgetsRef, path, "main")), http.StatusBadRequest, "refusal.schema.json", codeInvalidRequest)
	}
}

// TestJSONRulesRefuseRepeatsAndFractions pins the JSON rules of a call's body at every
// depth.
func TestJSONRulesRefuseRepeatsAndFractions(t *testing.T) {
	for body, ok := range map[string]bool{
		`{"a":1,"b":[1,2,{"c":3}]}`:   true,
		`{"a":{"a":1},"b":{"a":2}}`:   true,
		`{"a":1,"a":1}`:               false,
		`{"a":[{"b":1,"b":2}]}`:       false,
		`{"a":{"b":{"c":1,"c":1}}}`:   false,
		`{"a":1.5}`:                   false,
		`{"a":[1e3]}`:                 false,
		`{"a":-1E2}`:                  false,
		`{"a":1} {"b":2}`:             false,
		`{"a":`:                       false,
		`{"a":"1.5","b":"e","c":"E"}`: true,
	} {
		if err := jsonRules([]byte(body)); (err == nil) != ok {
			t.Errorf("%s: %v", body, err)
		}
	}
}

// TestCallURLIsTheContractsCallURL pins the setting call_url, in the file and in the
// environment: an https URL with no query and no fragment whose path ends with /, and
// the error for any other, which quotes nothing.
func TestCallURLIsTheContractsCallURL(t *testing.T) {
	const good = "https://github.example.com/v1/calls/"
	for _, u := range []string{good, "https://qory.example.com/", "https://qory.example.com:8443/calls/"} {
		if err := checkCallURL(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range []string{"http://qory.example.com/calls/", "https://qory.example.com/calls", "https://qory.example.com/calls/?a=1", "https://qory.example.com/calls/#x", "https://user@qory.example.com/calls/", "https://qory.example.com/qak_" + strings.Repeat("a", 43) + "/", "qory.example.com/calls/", "https://qory.example.com/a b/", "https://qory.example.com/" + strings.Repeat("a", 2048) + "/"} {
		if err := checkCallURL(u); err != errCallURL {
			t.Errorf("%s: %v", u, err)
		}
	}
	env := map[string]string{"QORY_GITHUB_LISTEN": "127.0.0.1:0", "QORY_GITHUB_STATE_DIR": "/d", "QORY_GITHUB_APIARY_URL": "https://apiary.example.com", "QORY_GITHUB_PUBLIC_URL": "https://qory-github.example.com", "QORY_GITHUB_CALL_URL": good}
	lookup := func(name string) (string, bool) { v, ok := env[name]; return v, ok }
	if s, err := ReadEnvironment(lookup); err != nil || s.CallURL != good {
		t.Errorf("call_url %q, err %v", s.CallURL, err)
	}
	env["QORY_GITHUB_CALL_URL"] = "https://qory.example.com/calls"
	if _, err := ReadEnvironment(lookup); err == nil || err.Error() != "the settings in the environment are invalid: QORY_GITHUB_CALL_URL: is not an https URL with no query and no fragment whose path ends with /, at most 2048 characters" {
		t.Errorf("err %v", err)
	}
	if _, err := parseSettings([]byte(`{"listen":"127.0.0.1:0","state_dir":"/d","apiary_url":"https://apiary.example.com","public_url":"https://qory-github.example.com","call_url":"https://qory.example.com/calls/?x"}`)); err == nil || err.Error() != "the settings are invalid: /call_url: is not an https URL with no query and no fragment whose path ends with /, at most 2048 characters" {
		t.Errorf("err %v", err)
	}
}

// TestTheDeclarationHasCallURLOnlyWithoutSetupURL pins that Declare sends call_url when
// it is set and the declaration has no setup_url, and leaves it out otherwise.
func TestTheDeclarationHasCallURLOnlyWithoutSetupURL(t *testing.T) {
	const call = "https://github.example.com/v1/calls/"
	for _, c := range []struct {
		callURL, setupURL string
		want              bool
	}{{call, "", true}, {call, "https://qory-github.example.com/setup", false}, {"", "", false}} {
		access := newKey(t)
		apiary := newFakeApiary(t, access)
		client := apiary.client(access)
		client.CallURL = c.callURL
		if err := client.Declare(context.Background(), "https://qory-github.example.com", c.setupURL); err != nil {
			t.Fatal(err)
		}
		declared := apiary.sent(routeAdapter)
		if len(declared) != 1 {
			t.Fatalf("declared %d times", len(declared))
		}
		got, ok := declared[0].body["call_url"]
		if ok != c.want || ok && got != call {
			t.Errorf("call_url %q setup_url %q: declared %s", c.callURL, c.setupURL, declared[0].raw)
		}
	}
}

// TestRunServesCallsOnlyWithCallURL runs serve with an App and call_url set: it declares
// call_url, and its listener answers a call at /v1/calls/; without call_url, it declares
// none, and the path is answered 404.
func TestRunServesCallsOnlyWithCallURL(t *testing.T) {
	const call = "https://github.example.com/v1/calls/"
	for _, callURL := range []string{call, ""} {
		dir := t.TempDir()
		access := newKey(t)
		apiary := newFakeApiary(t, access)
		s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
		s.CallURL = callURL
		addr := make(chan net.Addr, 1)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- Run(ctx, s, Options{ProgramVersion: testVersion, Listening: func(a net.Addr) { addr <- a }})
		}()
		at := <-addr
		eventually(t, "declared", func() bool { return len(apiary.sent(routeAdapter)) > 0 })
		resp, err := http.Post("http://"+at.String()+callsPath+contracts.ResolvePath, "application/json", strings.NewReader(callBodyAt(time.Now(), widgetsAddress)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		declared := apiary.sent(routeAdapter)[0]
		got, ok := declared.body["call_url"]
		switch {
		case callURL != "" && (got != call || resp.StatusCode != http.StatusUnauthorized):
			t.Errorf("with call_url: declared %s, a call unsigned answered %d", declared.raw, resp.StatusCode)
		case callURL == "" && (ok || resp.StatusCode != http.StatusNotFound):
			t.Errorf("without call_url: declared %s, a call answered %d", declared.raw, resp.StatusCode)
		}
	}
}
