package serve

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// callsPath is where serve receives Qory Apiary's calls, by POST: Qory Apiary sends
// each call to call_url followed by the call's path, such as run-credential. The
// instance admin sets call_url to public_url followed by callsPath, such as
// https://github.example.com/v1/calls/, so each call reaches callsPath followed by the
// call's path. The call's signature covers the path alone, not the address.
const callsPath = "/v1/calls/"

// callWindow is how far a call's time may be from serve's clock, either way: a call
// whose time is further gets the unsigned 401.
const callWindow = 300 * time.Second

// maxCallsAtOnce is how many calls serve holds at once, each with a body of
// [contracts.MaxRequest] bytes at most. A call beyond it gets an unsigned 503 before
// its body is read, so a sender with no key takes up 64 MiB at most.
const maxCallsAtOnce = 64

// nsCallSignatures is the store's namespace of the signatures of the calls serve
// accepted, by the signature's 64 bytes in hexadecimal, each kept until the call's time
// is more than [callWindow] behind serve's clock: a call whose signature is there is a
// replay, which gets the unsigned 401, before and after a restart.
const nsCallSignatures = "call_signatures"

// The refusal codes of a call, refusal.schema.json's. codeMethodNotAllowed,
// codePayloadTooLarge, codeBusy and codeNotFound are serve's, for what the contract
// has no code for: a method other than POST, a body over [contracts.MaxRequest], a
// call beyond [maxCallsAtOnce], and a path no call has.
const (
	codeUnauthorized               = "unauthorized"
	codeUnsupportedContractVersion = "unsupported_contract_version"
	codeInvalidRequest             = "invalid_request"
	codeGrantUnknown               = "grant_unknown"
	codeResourceNotCovered         = "resource_not_covered"
	codeAccessNotGranted           = "access_not_granted"
	codeSourceUnavailable          = "source_unavailable"
	codeVersionNotFound            = "version_not_found"
	codeDocumentNotText            = "document_not_text"
	codeMethodNotAllowed           = "method_not_allowed"
	codePayloadTooLarge            = "payload_too_large"
	codeBusy                       = "busy"
	codeNotFound                   = "not_found"
)

// grants is what the calls read of the installations linked to Qory Apiary, each a
// grant whose grant_ref is the installation's id, and of the repositories each one
// reaches, each a resource whose resource_ref is the repository's id. [storeGrants]
// reads them from the store.
type grants interface {
	// linked is whether the installation is linked to a connection in Qory Apiary.
	linked(installation int64) (bool, error)
	// reaches is whether the installation reaches the repository whose id is
	// repository.
	reaches(installation, repository int64) (bool, error)
	// liveUnder is the installation that reaches the repository whose id is
	// repository, when that installation is linked to connection and the link is
	// live: the repository is then a live collection under connection. Otherwise it is
	// false.
	liveUnder(connection string, repository int64) (int64, bool, error)
	// copied is whether Qory Apiary's copy of the grants contains the installation's
	// grant under connection. A link whose grant's report is still being sent does
	// not count.
	copied(installation int64, connection string) (bool, error)
}

// storeGrants are the grants the store keeps: the installations' links, see [Link], and
// the repositories each installation's listings named, see [claimReach]. For linked, an
// installation counts as linked under the rule intake follows, see [granted]: Qory
// Apiary's copy of the grants contains it, or the connect return of its link has not
// expired. For copied, only the copy counts, see [grantOf]. now is the clock; nil is
// time.Now.
type storeGrants struct {
	st  *store.Store
	now func() time.Time
}

func (g storeGrants) linked(installation int64) (bool, error) {
	now := time.Now
	if g.now != nil {
		now = g.now
	}
	return granted(g.st, installation, now())
}

func (g storeGrants) reaches(installation, repository int64) (bool, error) {
	id, ok, err := reachOf(g.st, github.CollectionRef(repository))
	return err == nil && ok && id == installation, err
}

func (g storeGrants) liveUnder(connection string, repository int64) (int64, bool, error) {
	installation, ok, err := reachOf(g.st, github.CollectionRef(repository))
	if err != nil || !ok {
		return 0, false, err
	}
	l, ok, err := linkOf(g.st, installation)
	if err != nil || !ok || l.Connection != connection || l.State != linkLive {
		return 0, false, err
	}
	return installation, true, nil
}

func (g storeGrants) copied(installation int64, connection string) (bool, error) {
	held, err := grantOf(g.st, installation)
	return err == nil && held == connection, err
}

// Calls serves Qory Apiary's calls at [callsPath]: run-credential, resolve and read,
// each a POST signed with a key of the pin, see [Calls.ServeHTTP]. Each answer is signed
// with the adapter's access key. A grant_ref is an installation's id in decimal, and a
// resource_ref a repository's id in decimal, as a collection's ref is.
type Calls struct {
	// Store keeps the signatures of the calls accepted.
	Store *store.Store
	// Grants are the installations linked to Qory Apiary and the repositories each
	// reaches.
	Grants grants
	// GitHub reaches GitHub's API.
	GitHub github.Client
	// AppID and Key are the App's id and private key, which mint installation tokens.
	AppID string
	Key   *rsa.PrivateKey
	// InstanceID is serve's instance id, which a call has in X-Qory-Instance-Id.
	InstanceID string
	// Log takes one line for each call; nil logs nothing. No line has a token, a key or
	// a body.
	Log *slog.Logger

	// creds are the enrolment: the pin a call is checked under, the adapter's id it
	// contains, and the access key an answer is signed with.
	creds *credentials
	// listingToken is the installation's token that reads which repositories it reaches,
	// such as [Adapter.token] keeps, with which a resolve reads a repository's id.
	listingToken func(ctx context.Context, installation int64) (string, error)
	// now is the clock; nil is time.Now. refusalEvery replaces [refusalEvery].
	now          func() time.Time
	refusalEvery time.Duration

	once     sync.Once
	slots    chan struct{}
	refusals *throttle
	// mu guards reads, the tokens a read reads with, by installation and repository.
	mu    sync.Mutex
	reads map[[2]int64]github.InstallationToken
}

func (c *Calls) init() {
	c.once.Do(func() {
		c.slots = make(chan struct{}, maxCallsAtOnce)
		c.refusals = &throttle{every: cmp.Or(c.refusalEvery, refusalEvery), now: c.now, flush: func(dropped int) {
			c.log().LogAttrs(context.Background(), slog.LevelInfo, "call refusals dropped", slog.Int("refusals_dropped", dropped))
		}}
	})
}

func (c *Calls) log() *slog.Logger {
	if c.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return c.Log
}

func (c *Calls) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// stopLog logs the count of refusals held back, if any, as [throttle.stop] does.
func (c *Calls) stopLog() {
	c.init()
	c.refusals.stop()
}

// Route is c at [callsPath] and below, and next for every other path.
func (c *Calls) Route(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.EscapedPath(), callsPath) {
			next.ServeHTTP(w, r)
			return
		}
		c.ServeHTTP(w, r)
	})
}

// ServeHTTP serves one call. It returns, unsigned:
//
//   - 405 method_not_allowed to a method other than POST;
//   - 503 busy when [maxCallsAtOnce] calls are held;
//   - 413 payload_too_large to a body over [contracts.MaxRequest] bytes;
//   - 401 unauthorized when X-Qory-Signature-Ed25519, X-Qory-Adapter-Id or
//     X-Qory-Instance-Id is missing or sent twice, when the adapter id is not the one
//     serve is enrolled as or the instance id not serve's, when the signature does not
//     verify under a key of the pin over [contracts.Call], when the body's time is more
//     than [callWindow] from serve's clock, either way, and when serve accepted a call
//     with the same signature before, see [nsCallSignatures].
//
// Every other answer is signed with the access key over [contracts.CallAnswer]: 400
// invalid_request for a body that has no time, breaks the JSON rules or the call's
// schema; 400 unsupported_contract_version for an X-Qory-Contract-Version that is
// missing, sent twice, not a decimal integer or not [contracts.Revision]; 404 not_found
// for a path that is not a call's; and the call's answer, see [Calls.runCredential],
// [Calls.resolve] and [Calls.read].
func (c *Calls) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.init()
	path := strings.TrimPrefix(r.URL.EscapedPath(), callsPath)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		c.unsigned(w, path, http.StatusMethodNotAllowed, codeMethodNotAllowed)
		return
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		c.unsigned(w, path, http.StatusServiceUnavailable, codeBusy)
		return
	}
	if r.ContentLength > contracts.MaxRequest {
		c.unsigned(w, path, http.StatusRequestEntityTooLarge, codePayloadTooLarge)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, contracts.MaxRequest))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		c.unsigned(w, path, http.StatusRequestEntityTooLarge, codePayloadTooLarge)
		return
	case err != nil:
		c.unsigned(w, path, http.StatusBadRequest, codeInvalidRequest)
		return
	}
	sig, ok1 := oneHeader(r.Header, accesskey.HeaderSignature)
	adapterID, ok2 := oneHeader(r.Header, contracts.HeaderAdapterID)
	instance, ok3 := oneHeader(r.Header, accesskey.HeaderInstanceID)
	e := c.creds.get()
	msg, err := contracts.Call{AdapterID: adapterID, InstanceID: instance, Method: r.Method, Path: path, Body: body}.Message()
	if !ok1 || !ok2 || !ok3 || err != nil || adapterID != e.adapterID || instance != c.InstanceID || !e.pin.Verify(msg, sig) {
		c.unsigned(w, path, http.StatusUnauthorized, codeUnauthorized)
		return
	}
	at, ok := callTime(body)
	if !ok {
		c.signed(w, e, sig, path, http.StatusBadRequest, contracts.Refusal{Error: codeInvalidRequest})
		return
	}
	now := c.clock()
	if at.Sub(now) > callWindow || now.Sub(at) > callWindow {
		c.unsigned(w, path, http.StatusUnauthorized, codeUnauthorized)
		return
	}
	raw, _ := base64.RawURLEncoding.Strict().DecodeString(sig)
	fresh, err := c.Store.PutNew(nsCallSignatures, hex.EncodeToString(raw), []byte{1}, at.Add(callWindow+time.Second).Sub(now))
	if err != nil {
		c.log().Error("keeping a call's signature", slog.String("call", callName(path)), slog.String("error", err.Error()))
		c.signed(w, e, sig, path, http.StatusServiceUnavailable, contracts.Refusal{Error: codeSourceUnavailable})
		return
	}
	if !fresh {
		c.unsigned(w, path, http.StatusUnauthorized, codeUnauthorized)
		return
	}
	if !contractVersion(r.Header) {
		c.signed(w, e, sig, path, http.StatusBadRequest, contracts.Refusal{Error: codeUnsupportedContractVersion})
		return
	}
	var status int
	var answer any
	switch path {
	case contracts.RunCredentialPath:
		status, answer = c.runCredential(r.Context(), body, at)
	case contracts.ResolvePath:
		status, answer = c.resolve(r.Context(), body)
	case contracts.ReadPath:
		status, answer = c.read(r.Context(), body)
	default:
		status, answer = http.StatusNotFound, contracts.Refusal{Error: codeNotFound}
	}
	c.signed(w, e, sig, path, status, answer)
}

// oneHeader is the header's value when the request has it once.
func oneHeader(h http.Header, name string) (string, bool) {
	v := h.Values(name)
	if len(v) != 1 {
		return "", false
	}
	return v[0], true
}

// decimalShape is a decimal integer as X-Qory-Contract-Version writes one.
var decimalShape = regexp.MustCompile(`^[0-9]{1,9}$`)

// contractVersion is whether the call's X-Qory-Contract-Version is there once, a
// decimal integer, and [contracts.Revision].
func contractVersion(h http.Header) bool {
	v, ok := oneHeader(h, headerContractVersion)
	if !ok || !decimalShape.MatchString(v) {
		return false
	}
	n, err := strconv.Atoi(v)
	return err == nil && n == contracts.Revision
}

// callTime is the time of a call's body, [contracts.TimeLayout] and written back the
// same, or false when the body is not an object with such a time.
func callTime(body []byte) (time.Time, bool) {
	var doc struct {
		Time string `json:"time"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return time.Time{}, false
	}
	return passExpiry(doc.Time)
}

// callName is a call's path for a line: the path of a call serve serves, or "other",
// so a sender with no key writes nothing of its choice in the log.
func callName(path string) string {
	switch path {
	case contracts.RunCredentialPath, contracts.ResolvePath, contracts.ReadPath:
		return path
	}
	return "other"
}

// unsigned writes status with the refusal code, unsigned, and logs it, once each
// [refusalEvery] at most.
func (c *Calls) unsigned(w http.ResponseWriter, path string, status int, code string) {
	if ok, dropped := c.refusals.allow(); ok {
		attrs := []slog.Attr{slog.String("call", callName(path)), slog.Int("status", status), slog.String("refusal", code)}
		if dropped > 0 {
			attrs = append(attrs, slog.Int("refusals_dropped", dropped))
		}
		c.log().LogAttrs(context.Background(), slog.LevelInfo, "call answered without a signature", attrs...)
	}
	b, _ := json.Marshal(contracts.Refusal{Error: code})
	writeCall(w, status, b)
}

// signed writes status with answer as JSON, signed with e's access key over
// [contracts.CallAnswer], bound to the call's signature sig, and logs the call's path,
// the status and, for a refusal, its code.
func (c *Calls) signed(w http.ResponseWriter, e enrolment, sig, path string, status int, answer any) {
	b, err := json.Marshal(answer)
	if err != nil {
		status, b = http.StatusServiceUnavailable, []byte(`{"error":"source_unavailable"}`)
	}
	attrs := []slog.Attr{slog.String("call", callName(path)), slog.Int("status", status)}
	if r, ok := answer.(contracts.Refusal); ok {
		attrs = append(attrs, slog.String("refusal", r.Error))
	}
	c.log().LogAttrs(context.Background(), slog.LevelInfo, "call answered", attrs...)
	m := contracts.CallAnswer{Status: status, CallSignature: sig, Body: b}.Message()
	w.Header().Set(accesskey.HeaderSignature, base64.RawURLEncoding.EncodeToString(e.key.Sign(m)))
	writeCall(w, status, b)
}

// writeCall writes an answer to a call: JSON, which no cache keeps.
func writeCall(w http.ResponseWriter, status int, b []byte) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write(b)
}

// callSchemas are the schemas of the calls' bodies, compiled once each, by name.
var callSchemas sync.Map // string -> func() (*jsonschema.Schema, error)

// decodeCall decodes body into doc when it follows the JSON rules of
// definitions.schema.json, see [jsonRules], and the schema name.
func decodeCall(name string, body []byte, doc any) bool {
	compile, _ := callSchemas.LoadOrStore(name, sync.OnceValues(func() (*jsonschema.Schema, error) { return contracts.Compile(name) }))
	schema, err := compile.(func() (*jsonschema.Schema, error))()
	if err != nil || jsonRules(body) != nil {
		return false
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil || schema.Validate(v) != nil {
		return false
	}
	return json.Unmarshal(body, doc) == nil
}

// jsonRules refuses a body that is not one JSON value, that repeats a member of an
// object, at any depth, or that writes a number with a fraction or an exponent: the
// calls' bodies have integers alone.
func jsonRules(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	type frame struct {
		object bool
		key    bool
		keys   map[string]bool
	}
	var stack []*frame
	done := false
	valueDone := func() {
		if len(stack) == 0 {
			done = true
		} else if top := stack[len(stack)-1]; top.object {
			top.key = true
		}
	}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) && done {
			return nil
		}
		if err != nil {
			return err
		}
		if done {
			return errors.New("something follows the JSON value")
		}
		if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].key {
			top := stack[n-1]
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:n-1]
				valueDone()
				continue
			}
			k, _ := tok.(string)
			if top.keys[k] {
				return fmt.Errorf("an object repeats the member %q", k)
			}
			top.keys[k], top.key = true, false
			continue
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, &frame{object: true, key: true, keys: map[string]bool{}})
			case '[':
				stack = append(stack, &frame{})
			default:
				stack = stack[:len(stack)-1]
				valueDone()
			}
		case json.Number:
			if strings.ContainsAny(string(t), ".eE") {
				return errors.New("a number has a fraction or an exponent")
			}
			valueDone()
		default:
			valueDone()
		}
	}
}

// installationOf is the installation of a grant_ref: a positive id in decimal, as
// strconv writes it.
func installationOf(ref string) (int64, bool) {
	id, err := strconv.ParseInt(ref, 10, 64)
	return id, err == nil && id > 0 && strconv.FormatInt(id, 10) == ref
}

// repositoryOf is the repository of a resource_ref: a positive id in decimal, as
// strconv writes it.
func repositoryOf(ref string) (int64, bool) { return installationOf(ref) }

// runPermissions are the permissions of a run's token for purpose and access. A token
// for work reads the repositories' contents and pull requests with access read, and
// writes both with access write; GitHub adds metadata read to every token. A token for
// a harness reads the contents alone, whatever the access. No token has workflows.
func runPermissions(purpose, access string) map[string]string {
	switch {
	case purpose == "harness":
		return map[string]string{"contents": "read"}
	case access == "write":
		return map[string]string{"contents": "write", "pull_requests": "write"}
	}
	return map[string]string{"contents": "read", "metadata": "read", "pull_requests": "read"}
}

// runCredential serves the call run-credential, run-credential.schema.json, made at at:
// a token GitHub mints for one installation, limited to the repositories of the
// resources and to [runPermissions]. A call for a harness has the installation's id in
// grant_ref, see [Calls.harnessGrant]; a call for work has the connection of its one
// repository in connection_id, see [Calls.workGrant]. Past those checks, it returns
// 403 access_not_granted when GitHub returns 422 for the permissions on those
// repositories, as for an installation that does not grant them, or the installation
// is suspended; when the mint fails for good, as for an installation GitHub has no
// more, 409 grant_unknown for a harness and 403 resource_not_covered for work; and 503
// source_unavailable when GitHub fails otherwise. The answer's apply has, for work,
// github.com with basic and the username x-access-token on the repository's git paths
// and api.github.com with bearer on its API paths, as [github.Uses] returns them; for a
// harness, the github.com item alone.
func (c *Calls) runCredential(ctx context.Context, body []byte, at time.Time) (int, any) {
	var req contracts.RunCredential
	if !decodeCall("run-credential.schema.json", body, &req) {
		return http.StatusBadRequest, contracts.Refusal{Error: codeInvalidRequest}
	}
	return c.runCredentialFor(ctx, req, at)
}

// runCredentialFor is [Calls.runCredential] for the decoded call req. At GitHub, a
// mint that lists no repository covers every repository of the installation, so a call
// with no resources gets 400 invalid_request here, beside the schema's minItems. A call
// for work with a grant_ref, with no connection_id or with other than one resource gets
// 400 invalid_request here too, beside the schema.
func (c *Calls) runCredentialFor(ctx context.Context, req contracts.RunCredential, at time.Time) (int, any) {
	if len(req.Resources) == 0 {
		return http.StatusBadRequest, contracts.Refusal{Error: codeInvalidRequest}
	}
	work := req.Purpose == "work"
	if work && (req.GrantRef != "" || len(req.Resources) != 1 || !connectionShape.MatchString(req.ConnectionID)) {
		return http.StatusBadRequest, contracts.Refusal{Error: codeInvalidRequest}
	}
	var installation int64
	var ids []int64
	var status int
	var refusal any
	if work {
		installation, ids, status, refusal = c.workGrant(req.ConnectionID, req.Resources[0])
	} else {
		installation, ids, status, refusal = c.harnessGrant(req.GrantRef, req.Resources)
	}
	if status != 0 {
		return status, refusal
	}
	t, err := c.GitHub.MintInstallationToken(ctx, github.Request{AppID: c.AppID, Key: c.Key, InstallationID: installation, RepositoryIDs: ids, Permissions: runPermissions(req.Purpose, req.Access)})
	switch {
	case errors.Is(err, github.ErrRepositoryRefused):
		c.log().Info("minting the run credential's token failed: GitHub returned 422", slog.Int64("installation", installation), slog.String("error", err.Error()))
		return http.StatusForbidden, contracts.Refusal{Error: codeAccessNotGranted}
	case errors.Is(err, github.ErrSuspended):
		c.log().Info("minting the run credential's token failed: the installation is suspended", slog.Int64("installation", installation))
		return http.StatusForbidden, contracts.Refusal{Error: codeAccessNotGranted}
	case errors.Is(err, github.ErrMintRefused) && work:
		c.log().Info("minting the work credential's token failed for good, so no grant covers the collection", slog.Int64("installation", installation), slog.String("error", err.Error()))
		return http.StatusForbidden, contracts.Refusal{Error: codeResourceNotCovered}
	case errors.Is(err, github.ErrMintRefused):
		c.log().Info("minting the run credential's token failed for good, so the grant counts as unknown", slog.Int64("installation", installation), slog.String("error", err.Error()))
		return http.StatusConflict, contracts.Refusal{Error: codeGrantUnknown}
	case err != nil:
		c.log().Warn("minting the run credential's token", slog.Int64("installation", installation), slog.String("error", err.Error()))
		return http.StatusServiceUnavailable, contracts.Refusal{Error: codeSourceUnavailable}
	}
	repos := make([]github.Repository, 0, len(ids))
	for _, id := range ids {
		name, ok := t.Repositories[id]
		if !ok {
			c.log().Warn("GitHub's answer to the run credential's mint does not list a repository", slog.Int64("installation", installation), slog.String("resource", github.CollectionRef(id)))
			return http.StatusServiceUnavailable, contracts.Refusal{Error: codeSourceUnavailable}
		}
		repos = append(repos, name)
	}
	uses := github.Uses(repos)
	if req.Purpose == "harness" {
		uses = uses[:1]
	}
	apply := make([]contracts.CredentialApply, len(uses))
	for i, u := range uses {
		apply[i] = contracts.CredentialApply{Hosts: u.Hosts, Scheme: u.Scheme, Username: u.Username, Paths: u.Paths}
	}
	answer := contracts.RunCredentialAnswer{Version: contracts.Version, Revision: contracts.Revision, Credential: contracts.Credential{
		Version: 1, Token: t.Token, ExpiresAt: contracts.FormatTime(t.ExpiresAt), Apply: apply,
	}}
	if err := answer.Check(at); err != nil {
		c.log().Warn("GitHub's token does not fit the run credential answer", slog.Int64("installation", installation), slog.String("error", err.Error()))
		return http.StatusServiceUnavailable, contracts.Refusal{Error: codeSourceUnavailable}
	}
	return http.StatusOK, answer
}

// harnessGrant is the installation of grant and the repositories of resources for a
// call for a harness, or the status and refusal: 409 grant_unknown for a grant that is
// not an installation linked to Qory Apiary, see [Calls.held], then 403
// resource_not_covered for a resource that is not a repository the installation
// reaches, with a line that contains the resource, see [Calls.covered].
func (c *Calls) harnessGrant(grant string, resources []string) (int64, []int64, int, any) {
	installation, ok := installationOf(grant)
	if status, refusal := c.held(ok, installation); status != 0 {
		return 0, nil, status, refusal
	}
	ids := make([]int64, 0, len(resources))
	for _, ref := range resources {
		if status, refusal := c.covered(installation, ref); status != 0 {
			return 0, nil, status, refusal
		}
		id, _ := repositoryOf(ref)
		ids = append(ids, id)
	}
	return installation, ids, 0, nil
}

// workGrant is the installation and the repository for a call for work under
// connection whose one resource is ref, or the status and refusal. The repository of
// ref must be a live collection under connection, see [grants.liveUnder], and Qory
// Apiary's copy of the grants must contain the grant of the installation that reaches
// it under connection, see [grants.copied]; else the call gets 403
// resource_not_covered, with a line that contains ref and connection. The check
// compares the connection of ref's installation with connection and never takes the
// connection from ref. When the store fails, the call gets 503 source_unavailable.
func (c *Calls) workGrant(connection, ref string) (int64, []int64, int, any) {
	notCovered := func(why string) (int64, []int64, int, any) {
		c.log().Info(why, slog.String("connection", connection), slog.String("resource", ref))
		return 0, nil, http.StatusForbidden, contracts.Refusal{Error: codeResourceNotCovered}
	}
	failed := func(err error) (int64, []int64, int, any) {
		c.log().Error("reading the collection and the grant of a work call", slog.String("connection", connection), slog.String("resource", ref), slog.String("error", err.Error()))
		return 0, nil, http.StatusServiceUnavailable, contracts.Refusal{Error: codeSourceUnavailable}
	}
	id, ok := repositoryOf(ref)
	if !ok {
		return notCovered("the resource of the work call is not a repository's id")
	}
	installation, live, err := c.Grants.liveUnder(connection, id)
	if err != nil {
		return failed(err)
	}
	if !live {
		return notCovered("the resource of the work call is not a live collection under the call's connection")
	}
	copied, err := c.Grants.copied(installation, connection)
	if err != nil {
		return failed(err)
	}
	if !copied {
		return notCovered("Qory Apiary's copy of the grants does not contain a grant under the call's connection that covers the work call's resource")
	}
	return installation, []int64{id}, 0, nil
}

// held is 0 when ok and the installation is linked to Qory Apiary; else 409
// grant_unknown, or 503 source_unavailable when the store fails.
func (c *Calls) held(ok bool, installation int64) (int, any) {
	if !ok {
		return http.StatusConflict, contracts.Refusal{Error: codeGrantUnknown}
	}
	linked, err := c.Grants.linked(installation)
	switch {
	case err != nil:
		c.log().Error("reading an installation's link", slog.Int64("installation", installation), slog.String("error", err.Error()))
		return http.StatusServiceUnavailable, contracts.Refusal{Error: codeSourceUnavailable}
	case !linked:
		return http.StatusConflict, contracts.Refusal{Error: codeGrantUnknown}
	}
	return 0, nil
}

// covered is 0 when ref is a repository the installation reaches; else 403
// resource_not_covered, with a line that contains ref, or 503 source_unavailable when
// the store fails.
func (c *Calls) covered(installation int64, ref string) (int, any) {
	id, ok := repositoryOf(ref)
	reaches := false
	if ok {
		var err error
		if reaches, err = c.Grants.reaches(installation, id); err != nil {
			c.log().Error("reading which installation reaches a repository", slog.String("resource", ref), slog.String("error", err.Error()))
			return http.StatusServiceUnavailable, contracts.Refusal{Error: codeSourceUnavailable}
		}
	}
	if !reaches {
		c.log().Info("a resource of the call is not a repository the installation reaches", slog.Int64("installation", installation), slog.String("resource", ref))
		return http.StatusForbidden, contracts.Refusal{Error: codeResourceNotCovered}
	}
	return 0, nil
}

// resolve serves the call resolve, resolve.schema.json: for each address, the
// installation and the repository that cover it, see [Calls.resolveOne], in the call's
// order.
func (c *Calls) resolve(ctx context.Context, body []byte) (int, any) {
	var req contracts.Resolve
	if !decodeCall("resolve.schema.json", body, &req) {
		return http.StatusBadRequest, contracts.Refusal{Error: codeInvalidRequest}
	}
	answer := contracts.ResolveAnswer{Version: contracts.Version, Revision: contracts.Revision, Results: make([]contracts.Resolved, len(req.Addresses))}
	for i, address := range req.Addresses {
		answer.Results[i] = c.resolveOne(ctx, address)
	}
	return http.StatusOK, answer
}

// githubAddress is the repository at an address, https://github.com/<owner>/<name>
// with or without .git after the name, or false for any other form, the form
// git@github.com:<owner>/<name> among them.
func githubAddress(address string) (github.Repository, bool) {
	rest, ok := strings.CutPrefix(address, "https://"+github.GitHost+"/")
	if !ok {
		return github.Repository{}, false
	}
	repos, err := github.ParseRepositories(strings.TrimSuffix(rest, ".git"))
	if err != nil || len(repos) != 1 {
		return github.Repository{}, false
	}
	return repos[0], true
}

// resolveOne is the result for one address: the installation of the App on the
// repository's owner, as GitHub returns it, whose account's login is the owner's
// without regard to case, that is linked to Qory Apiary, and that reaches the
// repository, read by its name with the installation's listing token. Any other
// address, one GitHub returns no installation for among them, is covered: false.
func (c *Calls) resolveOne(ctx context.Context, address string) contracts.Resolved {
	covered := false
	notCovered := contracts.Resolved{Address: address, Covered: &covered}
	repo, ok := githubAddress(address)
	if !ok {
		return notCovered
	}
	installation, login, err := c.GitHub.RepositoryInstallation(ctx, c.AppID, c.Key, repo)
	if err != nil {
		if !errors.Is(err, github.ErrNotInstalled) {
			c.log().Warn("finding the installation of a repository to resolve", slog.String("error", err.Error()))
		}
		return notCovered
	}
	// Both are ASCII, so EqualFold folds ASCII's cases alone.
	if !strings.EqualFold(login, repo.Owner) {
		return notCovered
	}
	if status, _ := c.held(true, installation); status != 0 {
		return notCovered
	}
	token, err := c.listingToken(ctx, installation)
	if err != nil {
		c.log().Warn("minting a token to resolve a repository", slog.Int64("installation", installation), slog.String("error", err.Error()))
		return notCovered
	}
	id, _, err := c.GitHub.RepositoryID(ctx, token, repo)
	if err != nil {
		if !errors.Is(err, github.ErrRepositoryGone) {
			c.log().Warn("reading a repository to resolve", slog.Int64("installation", installation), slog.String("error", err.Error()))
		}
		return notCovered
	}
	if reaches, err := c.Grants.reaches(installation, id); err != nil || !reaches {
		return notCovered
	}
	return contracts.Resolved{Address: address, GrantRef: strconv.FormatInt(installation, 10), ResourceRef: github.CollectionRef(id)}
}

// read serves the call read, read.schema.json: the file at path in the repository of
// resource_ref, at the commit of at, read with a token that reads that repository's
// contents alone, see [Calls.readToken]. It returns, in this order: 409
// grant_unknown and 403 resource_not_covered as [Calls.harnessGrant] does; 404
// version_not_found when GitHub has no commit, branch or tag by at; 409
// document_not_text for a path that is not a UTF-8 text file of at most
// [contracts.ReadContentMaxBytes] bytes without a NUL; and 503 source_unavailable when
// GitHub fails otherwise. A path the commit has no file at is found: false.
func (c *Calls) read(ctx context.Context, body []byte) (int, any) {
	var req contracts.Read
	if !decodeCall("read.schema.json", body, &req) {
		return http.StatusBadRequest, contracts.Refusal{Error: codeInvalidRequest}
	}
	installation, ok := installationOf(req.GrantRef)
	if status, refusal := c.held(ok, installation); status != 0 {
		return status, refusal
	}
	if status, refusal := c.covered(installation, req.ResourceRef); status != 0 {
		return status, refusal
	}
	repository, _ := repositoryOf(req.ResourceRef)
	token, err := c.readToken(ctx, installation, repository)
	switch {
	case errors.Is(err, github.ErrRepositoryRefused):
		return http.StatusForbidden, contracts.Refusal{Error: codeResourceNotCovered}
	case errors.Is(err, github.ErrMintRefused):
		return http.StatusConflict, contracts.Refusal{Error: codeGrantUnknown}
	case err != nil:
		c.log().Warn("minting the read's token", slog.Int64("installation", installation), slog.String("error", err.Error()))
		return http.StatusServiceUnavailable, contracts.Refusal{Error: codeSourceUnavailable}
	}
	commit, err := c.GitHub.CommitAt(ctx, token, repository, req.At)
	if errors.Is(err, github.ErrVersionNotFound) {
		return http.StatusNotFound, contracts.Refusal{Error: codeVersionNotFound}
	}
	if err != nil {
		return c.readFailed(installation, repository, err)
	}
	content, found, err := c.GitHub.ReadDocument(ctx, token, repository, req.Path, commit, contracts.ReadContentMaxBytes)
	if errors.Is(err, github.ErrNotText) {
		return http.StatusConflict, contracts.Refusal{Error: codeDocumentNotText}
	}
	if err != nil {
		return c.readFailed(installation, repository, err)
	}
	answer := contracts.ReadAnswer{Version: contracts.Version, Revision: contracts.Revision, Content: content, ResolvedAt: commit}
	if !found {
		answer.Found = &found
	}
	if answer.Check() != nil {
		return http.StatusConflict, contracts.Refusal{Error: codeDocumentNotText}
	}
	return http.StatusOK, answer
}

// readFailed is the answer to a read whose request to GitHub failed with err: 503
// source_unavailable, with a line. A 401 drops the read's token, so the next read
// mints a new one.
func (c *Calls) readFailed(installation, repository int64, err error) (int, any) {
	if github.Unauthorized(err) {
		c.mu.Lock()
		delete(c.reads, [2]int64{installation, repository})
		c.mu.Unlock()
	}
	c.log().Warn("reading a file for a read call", slog.Int64("installation", installation), slog.String("resource", github.CollectionRef(repository)), slog.String("error", err.Error()))
	return http.StatusServiceUnavailable, contracts.Refusal{Error: codeSourceUnavailable}
}

// readToken is a token for the installation that reads the contents of the repository
// whose id is repository and no other, kept until [tokenMargin] before it expires.
func (c *Calls) readToken(ctx context.Context, installation, repository int64) (string, error) {
	key := [2]int64{installation, repository}
	c.mu.Lock()
	t, ok := c.reads[key]
	c.mu.Unlock()
	if ok && time.Until(t.ExpiresAt) > tokenMargin {
		return t.Token, nil
	}
	t, err := c.GitHub.MintInstallationToken(ctx, github.Request{AppID: c.AppID, Key: c.Key, InstallationID: installation, RepositoryIDs: []int64{repository}, Permissions: map[string]string{"contents": "read"}})
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reads == nil {
		c.reads = map[[2]int64]github.InstallationToken{}
	}
	c.reads[key] = t
	return t.Token, nil
}
