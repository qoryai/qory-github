package github

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The App's slug, its bot, and the installation token the fake GitHub takes: synthetic,
// and the token is what no error may contain.
const (
	takeInSlug  = "qory-test"
	takeInBot   = "qory-test[bot]"
	takeInToken = "ghs_takeintokenthatmustnotleak"
)

// takeInComment is one comment on the fake issue.
type takeInComment struct {
	Body string `json:"body"`
	User struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"user"`
}

func commentBy(login, typ, body string) takeInComment {
	var c takeInComment
	c.Body, c.User.Login, c.User.Type = body, login, typ
	return c
}

// fakeAnswer is one answer the fake gives a request in place of what it would.
type fakeAnswer struct {
	status int
	header map[string]string
	body   string
}

// fakeTakeIn is GitHub's API as far as a take in uses it, for the issue acme/widgets#7.
// It records every request it receives.
type fakeTakeIn struct {
	srv         *httptest.Server
	repoLabel   map[string]any // the label created in the repository; nil is none
	issueLabels []string
	comments    []takeInComment
	pageSize    int // comments to a page; zero is a hundred
	issueStatus int // the status of every request on the issue, when set: 404 or 410
	nextHost    string
	answers     map[string]fakeAnswer // by method and path: what GitHub answers instead
	mu          sync.Mutex
	requests    []string // method and path with its query
	auth        []string
	bodies      []string
}

func (f *fakeTakeIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	b, _ := io.ReadAll(r.Body)
	f.bodies = append(f.bodies, string(b))
	if a, ok := f.answers[r.Method+" "+r.URL.Path]; ok {
		for k, v := range a.header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(a.status)
		io.WriteString(w, a.body)
		return
	}
	const issue = "/repos/acme/widgets/issues/7"
	if f.issueStatus != 0 && strings.HasPrefix(r.URL.Path, issue) {
		w.WriteHeader(f.issueStatus)
		io.WriteString(w, `{"message":"`+http.StatusText(f.issueStatus)+`"}`)
		return
	}
	switch {
	case r.Method == "POST" && r.URL.Path == "/repos/acme/widgets/labels":
		if f.repoLabel != nil {
			w.WriteHeader(422)
			io.WriteString(w, `{"message":"Validation Failed","errors":[{"resource":"Label","code":"already_exists","field":"name"}]}`)
			return
		}
		json.Unmarshal(b, &f.repoLabel)
		w.WriteHeader(201)
		w.Write(b)
	case r.Method == "POST" && r.URL.Path == issue+"/labels":
		var got struct {
			Labels []string `json:"labels"`
		}
		json.Unmarshal(b, &got)
		for _, l := range got.Labels {
			if !slices.Contains(f.issueLabels, l) {
				f.issueLabels = append(f.issueLabels, l)
			}
		}
		json.NewEncoder(w).Encode(f.issueLabels)
	case r.Method == "DELETE" && r.URL.Path == issue+"/labels/qory":
		if !slices.Contains(f.issueLabels, "qory") {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Label does not exist"}`)
			return
		}
		f.issueLabels = nil
		io.WriteString(w, `[]`)
	case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/issues/7/comments"):
		size := f.pageSize
		if size == 0 {
			size = 100
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		page = max(page, 1)
		from, to := min((page-1)*size, len(f.comments)), min(page*size, len(f.comments))
		if to < len(f.comments) {
			host := f.srv.URL
			if f.nextHost != "" {
				host = f.nextHost
			}
			// GitHub's next page is under /repositories/{id}, not the path asked for.
			w.Header().Set("Link", `<`+host+`/repositories/1/issues/7/comments?per_page=100&page=`+strconv.Itoa(page+1)+`>; rel="next", <`+host+`/repositories/1/issues/7/comments?per_page=100&page=9>; rel="last"`)
		}
		json.NewEncoder(w).Encode(f.comments[from:to])
	case r.Method == "POST" && r.URL.Path == issue+"/comments":
		var got struct {
			Body string `json:"body"`
		}
		json.Unmarshal(b, &got)
		f.comments = append(f.comments, commentBy(takeInBot, "Bot", got.Body))
		w.WriteHeader(201)
		io.WriteString(w, `{"id":1}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

// serveTakeIn starts the fake and returns a client for it and a token function that
// records the repositories it is asked for.
func serveTakeIn(t *testing.T, f *fakeTakeIn) (Client, TokenFunc, *[]Repository) {
	t.Helper()
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	var asked []Repository
	token := func(_ context.Context, repo Repository) (string, error) {
		asked = append(asked, repo)
		return takeInToken, nil
	}
	return Client{API: f.srv.URL}, token, &asked
}

var takenIn = Change{WorkItemID: "wi_42", Ref: "acme/widgets#7", Status: StatusTakenIn, URL: "https://apiary.example.com/work-items/wi_42"}

const takenInComment = "<!-- qory:work-item wi_42 -->\nQory took this into Factory: <https://apiary.example.com/work-items/wi_42>"

// posts are the comments the App's bot has posted.
func (f *fakeTakeIn) posts() []string {
	var out []string
	for i, r := range f.requests {
		if r == "POST /repos/acme/widgets/issues/7/comments" {
			var got struct {
				Body string `json:"body"`
			}
			json.Unmarshal([]byte(f.bodies[i]), &got)
			out = append(out, got.Body)
		}
	}
	return out
}

// TestATakeInLabelsTheIssueAndCommentsOnce applies a take in to an issue in a repository
// without the label, and checks the label it creates, the label on the issue, the one
// comment's text, the order of the requests, the token they carry, and that applying
// the same change again posts no second comment.
func TestATakeInLabelsTheIssueAndCommentsOnce(t *testing.T) {
	f := &fakeTakeIn{}
	c, token, asked := serveTakeIn(t, f)
	if err := c.ApplyChange(context.Background(), nil, token, takeInSlug, takenIn); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"POST /repos/acme/widgets/labels",
		"POST /repos/acme/widgets/issues/7/labels",
		"GET /repos/acme/widgets/issues/7/comments?per_page=100",
		"POST /repos/acme/widgets/issues/7/comments",
	}
	if strings.Join(f.requests, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests:\n%s\nwant:\n%s", strings.Join(f.requests, "\n"), strings.Join(want, "\n"))
	}
	label := map[string]any{"name": "qory", "color": "6E56CF", "description": "Qory took this into Factory. The work item is in Qory Apiary."}
	b, _ := json.Marshal(f.repoLabel)
	w, _ := json.Marshal(label)
	if string(b) != string(w) {
		t.Errorf("the label created is %s, want %s", b, w)
	}
	if f.bodies[1] != `{"labels":["qory"]}` {
		t.Errorf("the issue's labels are added with %s", f.bodies[1])
	}
	if got := f.posts(); len(got) != 1 || got[0] != takenInComment {
		t.Errorf("the comments posted are %q, want %q", got, takenInComment)
	}
	for _, a := range f.auth {
		if a != "Bearer "+takeInToken {
			t.Errorf("a request carries %q", a)
		}
	}
	if len(*asked) != 1 || (*asked)[0] != (Repository{Owner: "acme", Name: "widgets"}) {
		t.Errorf("a token was asked for %v", *asked)
	}

	if err := c.ApplyChange(context.Background(), nil, token, takeInSlug, takenIn); err != nil {
		t.Fatal(err)
	}
	if got := f.posts(); len(got) != 1 {
		t.Errorf("a repeat posted a comment again: %q", got)
	}
	if !slices.Contains(f.issueLabels, "qory") || len(f.issueLabels) != 1 {
		t.Errorf("the issue's labels are %v", f.issueLabels)
	}
}

// TestATakeInWhereTheLabelExistsLabelsTheIssue has the repository hold the label already,
// which GitHub answers 422 already_exists, and checks that the take in carries on.
func TestATakeInWhereTheLabelExistsLabelsTheIssue(t *testing.T) {
	f := &fakeTakeIn{repoLabel: map[string]any{"name": "qory", "color": "000000"}}
	c, token, _ := serveTakeIn(t, f)
	if err := c.ApplyChange(context.Background(), nil, token, takeInSlug, takenIn); err != nil {
		t.Fatal(err)
	}
	if f.repoLabel["color"] != "000000" {
		t.Errorf("the label was changed: %v", f.repoLabel)
	}
	if !slices.Contains(f.issueLabels, "qory") || len(f.posts()) != 1 {
		t.Errorf("labels %v, comments %q", f.issueLabels, f.posts())
	}
}

// TestAnotherValidationErrorFailsTheTakeIn has GitHub answer the label's creation 422
// for another reason than its existence, and checks that nothing more is sent.
func TestAnotherValidationErrorFailsTheTakeIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/widgets/labels" {
			t.Errorf("%s %s was sent", r.Method, r.URL.Path)
		}
		w.WriteHeader(422)
		io.WriteString(w, `{"message":"Validation Failed","errors":[{"resource":"Label","code":"invalid","field":"color"}]}`)
	}))
	defer srv.Close()
	token := func(context.Context, Repository) (string, error) { return takeInToken, nil }
	err := Client{API: srv.URL}.ApplyChange(context.Background(), nil, token, takeInSlug, takenIn)
	if want := "creating the label qory: GitHub answered 422: Validation Failed"; err == nil || err.Error() != want {
		t.Errorf("err %v, want %s", err, want)
	}
}

// TestOnlyTheBotsMarkerCounts puts the marker on the issue in a person's comment, and in
// one by another App's bot, and checks that the take in comments all the same.
func TestOnlyTheBotsMarkerCounts(t *testing.T) {
	f := &fakeTakeIn{comments: []takeInComment{
		commentBy("someone", "User", takenInComment),
		commentBy(takeInBot, "User", takenInComment),
		commentBy("other-app[bot]", "Bot", takenInComment),
		commentBy(takeInBot, "Bot", "<!-- qory:work-item wi_4 -->\nQory took this into Factory: https://apiary.example.com/work-items/wi_4"),
		commentBy(takeInBot, "Bot", "quoted: "+takenInComment),
	}}
	c, token, _ := serveTakeIn(t, f)
	if err := c.ApplyChange(context.Background(), nil, token, takeInSlug, takenIn); err != nil {
		t.Fatal(err)
	}
	if got := f.posts(); len(got) != 1 || got[0] != takenInComment {
		t.Errorf("the comments posted are %q", got)
	}
}

// TestTheCommentIsFoundOnALaterPage pages the issue's comments, two to a page, with the
// bot's on the second page under GitHub's /repositories/{id} path, and checks that it is
// found and no comment is posted.
func TestTheCommentIsFoundOnALaterPage(t *testing.T) {
	f := &fakeTakeIn{pageSize: 2, comments: []takeInComment{
		commentBy("someone", "User", "first"),
		commentBy("someone", "User", "second"),
		commentBy(takeInBot, "Bot", takenInComment),
	}}
	c, token, _ := serveTakeIn(t, f)
	if err := c.ApplyChange(context.Background(), nil, token, takeInSlug, takenIn); err != nil {
		t.Fatal(err)
	}
	if got := f.posts(); len(got) != 0 {
		t.Errorf("a comment was posted again: %q", got)
	}
	if !slices.Contains(f.requests, "GET /repositories/1/issues/7/comments?per_page=100&page=2") {
		t.Errorf("the second page was not read: %v", f.requests)
	}
}

// TestANextPageOnAnotherHostIsNotRead has GitHub's Link header name another host, and
// checks that it is not read, nothing is posted, and the error carries no token.
func TestANextPageOnAnotherHostIsNotRead(t *testing.T) {
	var reached bool
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer other.Close()
	f := &fakeTakeIn{pageSize: 1, nextHost: other.URL, comments: []takeInComment{commentBy("someone", "User", "first"), commentBy("someone", "User", "second")}}
	c, token, _ := serveTakeIn(t, f)
	err := c.ApplyChange(context.Background(), nil, token, takeInSlug, takenIn)
	if want := "reading the issue's comments: the next page GitHub names is not on the API, so it is not read"; err == nil || err.Error() != want {
		t.Errorf("err %v, want %s", err, want)
	}
	if reached || len(f.posts()) != 0 {
		t.Errorf("reached %v, posted %q", reached, f.posts())
	}
}

// TestUndoneRemovesTheLabelAlone undoes a take in, and checks that the label leaves the
// issue, the comment stays and nothing is posted, and that undoing it again, which GitHub
// answers 404, is done all the same.
func TestUndoneRemovesTheLabelAlone(t *testing.T) {
	f := &fakeTakeIn{issueLabels: []string{"qory"}, comments: []takeInComment{commentBy(takeInBot, "Bot", takenInComment)}}
	c, token, _ := serveTakeIn(t, f)
	undone := takenIn
	undone.Status = StatusUndone
	for range 2 {
		if err := c.ApplyChange(context.Background(), nil, token, takeInSlug, undone); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"DELETE /repos/acme/widgets/issues/7/labels/qory", "DELETE /repos/acme/widgets/issues/7/labels/qory"}
	if strings.Join(f.requests, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests: %v", f.requests)
	}
	if len(f.issueLabels) != 0 || len(f.comments) != 1 {
		t.Errorf("labels %v, comments %v", f.issueLabels, f.comments)
	}
}

// TestAGoneIssueIsAPermanentError has GitHub answer 404 and 410 for the issue, and checks
// that the take in stops with an error that wraps ErrIssueGone and carries no token,
// while an undo of a gone issue is done.
func TestAGoneIssueIsAPermanentError(t *testing.T) {
	for _, status := range []int{404, 410} {
		f := &fakeTakeIn{issueStatus: status}
		c, token, _ := serveTakeIn(t, f)
		err := c.ApplyChange(context.Background(), nil, token, takeInSlug, takenIn)
		if !errors.Is(err, ErrIssueGone) {
			t.Errorf("%d: err %v, want ErrIssueGone", status, err)
		}
		if err != nil && strings.Contains(err.Error(), takeInToken) {
			t.Errorf("%d: the error contains the token: %v", status, err)
		}
		if len(f.requests) != 2 || len(f.posts()) != 0 {
			t.Errorf("%d: requests %v", status, f.requests)
		}
		undone := takenIn
		undone.Status = StatusUndone
		if err := c.ApplyChange(context.Background(), nil, token, takeInSlug, undone); err != nil {
			t.Errorf("%d: undo: %v", status, err)
		}
	}
}

// TestAnInvalidChangeIsRefusedBeforeAnything applies changes whose ref, work item id or
// URL is not one, and checks that each is refused, that no token is asked for and
// nothing is sent, and that the error names the rule and not the value.
func TestAnInvalidChangeIsRefusedBeforeAnything(t *testing.T) {
	long := "https://apiary.example.com/" + strings.Repeat("a", 2048-len("https://apiary.example.com/")+1)
	for _, tc := range []struct {
		name string
		edit func(*Change)
		want string
	}{
		{"no number", func(e *Change) { e.Ref = "acme/widgets" }, "ref"},
		{"empty number", func(e *Change) { e.Ref = "acme/widgets#" }, "ref"},
		{"zero", func(e *Change) { e.Ref = "acme/widgets#0" }, "ref"},
		{"negative", func(e *Change) { e.Ref = "acme/widgets#-7" }, "ref"},
		{"signed", func(e *Change) { e.Ref = "acme/widgets#+7" }, "ref"},
		{"leading zero", func(e *Change) { e.Ref = "acme/widgets#07" }, "ref"},
		{"too large", func(e *Change) { e.Ref = "acme/widgets#99999999999999999999" }, "ref"},
		{"two hashes", func(e *Change) { e.Ref = "acme/widgets#7#8" }, "ref"},
		{"no owner", func(e *Change) { e.Ref = "widgets#7" }, "ref"},
		{"bad owner", func(e *Change) { e.Ref = "-acme/widgets#7" }, "ref"},
		{"dot dot", func(e *Change) { e.Ref = "acme/..#7" }, "ref"},
		{"path", func(e *Change) { e.Ref = "acme/widgets/issues#7" }, "ref"},
		{"two repositories", func(e *Change) { e.Ref = "acme/widgets,acme/gadgets#7" }, "ref"},
		{"empty id", func(e *Change) { e.WorkItemID = "" }, "work_item_id"},
		{"no prefix", func(e *Change) { e.WorkItemID = "42" }, "work_item_id"},
		{"marker breaker", func(e *Change) { e.WorkItemID = "wi_42 -->" }, "work_item_id"},
		{"newline id", func(e *Change) { e.WorkItemID = "wi_42\n" }, "work_item_id"},
		{"long id", func(e *Change) { e.WorkItemID = "wi_" + strings.Repeat("a", 65) }, "work_item_id"},
		{"http", func(e *Change) { e.URL = "http://apiary.example.com/work-items/wi_42" }, "url"},
		{"javascript", func(e *Change) { e.URL = "javascript:alert(1)" }, "url"},
		{"relative", func(e *Change) { e.URL = "/work-items/wi_42" }, "url"},
		{"no host", func(e *Change) { e.URL = "https:///work-items" }, "url"},
		{"empty", func(e *Change) { e.URL = "" }, "url"},
		{"too long", func(e *Change) { e.URL = long }, "url"},
		{"newline", func(e *Change) { e.URL = "https://apiary.example.com/\n[x](https://evil.example)" }, "url"},
		{"space", func(e *Change) { e.URL = "https://apiary.example.com/ x" }, "url"},
		{"delete", func(e *Change) { e.URL = "https://apiary.example.com/\x7f" }, "url"},
		{"bidi override", func(e *Change) { e.URL = "https://apiary.example.com/‮" }, "url"},
		{"user", func(e *Change) { e.URL = "https://user:secretvalue@apiary.example.com/" }, "url"},
		{"not UTF-8", func(e *Change) { e.URL = "https://apiary.example.com/\xff" }, "url"},
		{"not ASCII", func(e *Change) { e.URL = "https://apiary.example.com/caf\u00e9" }, "url"},
		{"an image", func(e *Change) { e.URL = "https://apiary.example.com/<img/src=https://evil.example/p.png>" }, "url"},
		{"an HTML comment", func(e *Change) { e.URL = "https://apiary.example.com/x<!--" }, "url"},
		{"a broken escape", func(e *Change) { e.URL = "https://apiary.example.com/%zz" }, "url"},
		{"a short escape", func(e *Change) { e.URL = "https://apiary.example.com/%4" }, "url"},
	} {
		for _, status := range []string{StatusTakenIn, StatusUndone} {
			tr := &sentTransport{}
			var asked bool
			token := func(context.Context, Repository) (string, error) { asked = true; return takeInToken, nil }
			e := takenIn
			e.Status = status
			tc.edit(&e)
			err := Client{HTTP: &http.Client{Transport: tr}}.ApplyChange(context.Background(), nil, token, takeInSlug, e)
			if err == nil || !strings.HasPrefix(err.Error(), "the change's "+tc.want+" ") || !errors.Is(err, ErrInvalidChange) {
				t.Errorf("%s, %s: err %v, want the change's %s", tc.name, status, err, tc.want)
			}
			if tr.sent || asked {
				t.Errorf("%s, %s: sent %v, token asked for %v", tc.name, status, tr.sent, asked)
			}
			if err != nil && strings.Contains(err.Error(), "secretvalue") {
				t.Errorf("%s: the error says the value: %v", tc.name, err)
			}
		}
	}
	if long := "https://apiary.example.com/" + strings.Repeat("a", 2048-len("https://apiary.example.com/")); len(long) != 2048 || checkChangeURL(long) != nil {
		t.Errorf("a URL of 2,048 characters is refused")
	}
}

// TestAnUnknownStatusIsLeftAlone applies a change of a status that is neither taken_in
// nor undone, valid or not, and checks that nothing is asked for or sent.
func TestAnUnknownStatusIsLeftAlone(t *testing.T) {
	for _, status := range []string{"", "proposed", "TAKEN_IN", "done"} {
		for _, ref := range []string{takenIn.Ref, "not a ref"} {
			tr := &sentTransport{}
			var asked bool
			token := func(context.Context, Repository) (string, error) { asked = true; return takeInToken, nil }
			e := takenIn
			e.Status, e.Ref = status, ref
			if err := (Client{HTTP: &http.Client{Transport: tr}}).ApplyChange(context.Background(), nil, token, takeInSlug, e); err != nil || tr.sent || asked {
				t.Errorf("%q, %q: err %v, sent %v, asked %v", status, ref, err, tr.sent, asked)
			}
		}
	}
}

// TestATokenThatCannotBeHadSendsNothing has the token function fail, and checks that
// nothing is sent and the error says for which repository.
func TestATokenThatCannotBeHadSendsNothing(t *testing.T) {
	tr := &sentTransport{}
	token := func(context.Context, Repository) (string, error) { return "", errors.New("no installation") }
	err := Client{HTTP: &http.Client{Transport: tr}}.ApplyChange(context.Background(), nil, token, takeInSlug, takenIn)
	if want := "the installation token for acme/widgets: no installation"; err == nil || err.Error() != want || tr.sent {
		t.Errorf("err %v, want %s; sent %v", err, want, tr.sent)
	}
	empty := func(context.Context, Repository) (string, error) { return "", nil }
	if err := (Client{HTTP: &http.Client{Transport: tr}}).ApplyChange(context.Background(), nil, empty, takeInSlug, takenIn); err == nil || tr.sent {
		t.Errorf("an empty token: err %v, sent %v", err, tr.sent)
	}
	working := func(context.Context, Repository) (string, error) { return takeInToken, nil }
	if err := (Client{HTTP: &http.Client{Transport: tr}}).ApplyChange(context.Background(), nil, working, takeInSlug+"]", takenIn); err == nil || !strings.HasPrefix(err.Error(), "the App's slug is not one") || tr.sent {
		t.Errorf("a slug that is not one: err %v, sent %v", err, tr.sent)
	}
}

// TestAURLHoldsOnlyWhatRFC3986Allows refuses a work item URL with each character RFC
// 3986 leaves out of a URI, and takes one with each it allows, which the comment then
// writes as an autolink, where neither Markdown nor HTML is read: a Markdown link in
// the URL stays part of the one link.
func TestAURLHoldsOnlyWhatRFC3986Allows(t *testing.T) {
	for _, c := range []string{"<", ">", `"`, "`", `\`, "{", "}", "|", "^", " ", "\t", "\n", "\x00", "\x7f", "é", "‮"} {
		if err := checkChangeURL("https://apiary.example.com/a" + c + "b"); err == nil {
			t.Errorf("%q is taken", c)
		}
	}
	for _, allowed := range []string{
		"https://apiary.example.com/work-items/wi_42/a-b._~:@!$&'()*+,;=[]%20?x=1&y=(2)#f",
		"https://apiary.example.com/x)[Approve](https://evil.example)",
	} {
		if err := checkChangeURL(allowed); err != nil {
			t.Fatalf("%s: %v", allowed, err)
		}
		f := &fakeTakeIn{}
		c, token, _ := serveTakeIn(t, f)
		e := takenIn
		e.URL = allowed
		if err := c.ApplyChange(context.Background(), nil, token, takeInSlug, e); err != nil {
			t.Fatal(err)
		}
		if want := "<!-- qory:work-item wi_42 -->\nQory took this into Factory: <" + allowed + ">"; len(f.posts()) != 1 || f.posts()[0] != want {
			t.Errorf("the comment is %q, want %q", f.posts(), want)
		}
	}
}

// toServer is a transport that sends every request to a test server, over HTTP,
// whatever its URL, and records the hosts the requests were for.
type toServer struct {
	addr  string
	mu    sync.Mutex
	hosts []string
}

func (s *toServer) RoundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.hosts = append(s.hosts, r.URL.Host)
	s.mu.Unlock()
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host = "http", s.addr
	return http.DefaultTransport.RoundTrip(r)
}

// TestTheDefaultPortIsTheSameAPI pages the comments with the API written with and
// without :443, and the next page GitHub names written the other way, and checks that
// the next page is read and the comment found.
func TestTheDefaultPortIsTheSameAPI(t *testing.T) {
	for _, tc := range []struct{ api, next string }{
		{"https://api.github.com:443", "https://api.github.com"},
		{"https://api.github.com", "https://api.github.com:443"},
		{"https://api.github.com:443", "https://api.github.com:443"},
	} {
		f := &fakeTakeIn{pageSize: 1, nextHost: tc.next, comments: []takeInComment{commentBy("someone", "User", "first"), commentBy(takeInBot, "Bot", takenInComment)}}
		_, token, _ := serveTakeIn(t, f)
		tr := &toServer{addr: strings.TrimPrefix(f.srv.URL, "http://")}
		c := Client{API: tc.api, HTTP: &http.Client{Transport: tr}}
		if err := c.ApplyChange(context.Background(), nil, token, takeInSlug, takenIn); err != nil {
			t.Errorf("%s, next on %s: %v", tc.api, tc.next, err)
		}
		if len(f.posts()) != 0 || !slices.Contains(f.requests, "GET /repositories/1/issues/7/comments?per_page=100&page=2") {
			t.Errorf("%s, next on %s: requests %v", tc.api, tc.next, f.requests)
		}
	}
	for _, next := range []string{"https://api.github.com:8443", "http://api.github.com"} {
		f := &fakeTakeIn{pageSize: 1, nextHost: next, comments: []takeInComment{commentBy("someone", "User", "first"), commentBy("someone", "User", "second")}}
		_, token, _ := serveTakeIn(t, f)
		c := Client{API: "https://api.github.com:443", HTTP: &http.Client{Transport: &toServer{addr: strings.TrimPrefix(f.srv.URL, "http://")}}}
		if err := c.ApplyChange(context.Background(), nil, token, takeInSlug, takenIn); err == nil || !strings.Contains(err.Error(), "the next page GitHub names is not on the API") {
			t.Errorf("next on %s: err %v", next, err)
		}
	}
}

// TestWhatAskingAgainWouldNotChangeIsPermanent has GitHub answer a step of a take in, or
// an undo, with an answer asking again would get, and with one that passes, and checks
// which permanent error, if any, each wraps, and that no redirect is followed.
func TestWhatAskingAgainWouldNotChangeIsPermanent(t *testing.T) {
	const (
		labels   = "POST /repos/acme/widgets/labels"
		add      = "POST /repos/acme/widgets/issues/7/labels"
		read     = "GET /repos/acme/widgets/issues/7/comments"
		post     = "POST /repos/acme/widgets/issues/7/comments"
		remove   = "DELETE /repos/acme/widgets/issues/7/labels/qory"
		moved    = `{"message":"Moved Permanently","url":"/moved"}`
		refused  = `{"message":"Resource not accessible by integration"}`
		limited  = `{"message":"You have exceeded a secondary rate limit."}`
		notFound = `{"message":"Not Found"}`
	)
	for _, tc := range []struct {
		at     string
		answer fakeAnswer
		want   error // nil is an error that is neither
	}{
		{labels, fakeAnswer{status: 404, body: notFound}, ErrUnreachable},
		{labels, fakeAnswer{status: 403, body: refused}, nil},
		{add, fakeAnswer{status: 403, body: refused}, ErrUnreachable},
		{post, fakeAnswer{status: 403, body: refused}, ErrUnreachable},
		{add, fakeAnswer{status: 403, body: limited}, nil},
		{post, fakeAnswer{status: 403, header: map[string]string{"Retry-After": "60"}, body: refused}, nil},
		{post, fakeAnswer{status: 403, header: map[string]string{"X-RateLimit-Remaining": "0"}, body: refused}, nil},
		{read, fakeAnswer{status: 403, body: refused}, nil},
		{add, fakeAnswer{status: 404, body: notFound}, ErrIssueGone},
		{post, fakeAnswer{status: 410, body: `{"message":"Gone"}`}, ErrIssueGone},
		{labels, fakeAnswer{status: 500, body: `{"message":"Server Error"}`}, nil},
		{remove, fakeAnswer{status: 403, body: refused}, nil},
	} {
		for _, status := range []int{0, 301, 308, 302, 307} {
			a := tc.answer
			want := tc.want
			if status != 0 {
				a = fakeAnswer{status: status, header: map[string]string{"Location": "/moved"}, body: moved}
				want = nil
				if status == 301 || status == 308 {
					want = ErrUnreachable
				}
			}
			f := &fakeTakeIn{answers: map[string]fakeAnswer{tc.at: a}}
			c, token, _ := serveTakeIn(t, f)
			e := takenIn
			if tc.at == remove {
				e.Status = StatusUndone
			}
			err := c.ApplyChange(context.Background(), (&fakeClock{}).pacer(), token, takeInSlug, e)
			if err == nil {
				t.Errorf("%s answered %d: no error", tc.at, a.status)
				continue
			}
			for _, permanent := range []error{ErrIssueGone, ErrUnreachable} {
				if errors.Is(err, permanent) != (permanent == want) {
					t.Errorf("%s answered %d: err %v, want it to wrap %v", tc.at, a.status, err, want)
				}
			}
			if strings.Contains(err.Error(), takeInToken) || slices.Contains(f.requests, "GET /moved") || slices.Contains(f.requests, "POST /moved") || slices.Contains(f.requests, "DELETE /moved") {
				t.Errorf("%s answered %d: err %v, requests %v", tc.at, a.status, err, f.requests)
			}
		}
	}
}

// TestSendFollowsNoRedirect has GitHub answer with each redirect, to a path on the same
// server, and checks that send hands the redirect back, does not follow it, and so
// never sends the token on, whatever client it is handed.
func TestSendFollowsNoRedirect(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, hc := range []*http.Client{nil, {}} {
			var followed bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/moved" {
					followed = true
					return
				}
				w.Header().Set("Location", "/moved")
				w.WriteHeader(status)
			}))
			a, err := Client{API: srv.URL, HTTP: hc}.send(context.Background(), nil, false, "reading", http.MethodGet, "/repos/acme/widgets/issues/7/comments", takeInToken, nil)
			srv.Close()
			if err != nil || a.status != status || followed {
				t.Errorf("%d: err %v, followed %v", status, err, followed)
			}
		}
	}
}

// TestARefusedChangeIsPermanent refuses a change for each field it checks, and checks
// that each error wraps ErrInvalidChange, and that an error that is not the change's, a
// slug that is not one or a token that cannot be had, does not.
func TestARefusedChangeIsPermanent(t *testing.T) {
	token := func(context.Context, Repository) (string, error) { return takeInToken, nil }
	c := Client{HTTP: &http.Client{Transport: &sentTransport{}}}
	for _, edit := range []func(*Change){
		func(e *Change) { e.Ref = "acme/widgets#0" },
		func(e *Change) { e.WorkItemID = "42" },
		func(e *Change) { e.URL = "http://apiary.example.com/work-items/wi_42" },
	} {
		e := takenIn
		edit(&e)
		if err := c.ApplyChange(context.Background(), nil, token, takeInSlug, e); !errors.Is(err, ErrInvalidChange) {
			t.Errorf("%+v: err %v, want ErrInvalidChange", e, err)
		}
	}
	if err := c.ApplyChange(context.Background(), nil, token, "qory test", takenIn); err == nil || errors.Is(err, ErrInvalidChange) {
		t.Errorf("a slug that is not one: err %v", err)
	}
	failing := func(context.Context, Repository) (string, error) { return "", errors.New("no installation") }
	if err := c.ApplyChange(context.Background(), nil, failing, takeInSlug, takenIn); err == nil || errors.Is(err, ErrInvalidChange) {
		t.Errorf("a token that cannot be had: err %v", err)
	}
}

// TestATakeInGoesThroughTheInstallationsPacer has GitHub say no request remains after
// the label is created, and checks that the take in's next request waits for the reset
// on the pacer it is handed, the one every caller for the installation shares.
func TestATakeInGoesThroughTheInstallationsPacer(t *testing.T) {
	f := &fakeTakeIn{answers: map[string]fakeAnswer{"POST /repos/acme/widgets/labels": {status: 201, header: map[string]string{"X-Ratelimit-Remaining": "0", "X-Ratelimit-Reset": unix(600 * time.Second)}, body: `{}`}}}
	c, token, _ := serveTakeIn(t, f)
	clock := &fakeClock{}
	if err := c.ApplyChange(context.Background(), clock.pacer(), token, takeInSlug, takenIn); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(clock.slept, []time.Duration{600 * time.Second}) || len(f.posts()) != 1 {
		t.Errorf("slept %v, posted %q", clock.slept, f.posts())
	}
}

// TestCheckSlug checks the slugs an App may have are taken and others refused, by an
// error that never says the value.
func TestCheckSlug(t *testing.T) {
	for _, ok := range []string{"q", "qory-acme", "Qory_Acme.2", "9lives", strings.Repeat("a", 100)} {
		if err := CheckSlug(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-qory", ".qory", "_qory", "qory acme", "qory/acme", "qory[bot]", "qöry", "qory\n", strings.Repeat("a", 101)} {
		err := CheckSlug(bad)
		if err == nil || err.Error() != "is not an App's slug, 1 to 100 letters, digits, dots, underscores or hyphens" {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
