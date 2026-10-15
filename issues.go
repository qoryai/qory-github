package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/qoryai/integrations/contracts"
)

// Qory Apiary refuses a whole request when one field in it breaks the contract's
// limits, [contractLimits], and cuts nothing, so the adapter never sends a field that
// does. GitHub's limits fit inside the contract's, so a text past its limit is not
// expected; one that is anyway is cut to the limit, as [cut] says, and the cut is
// logged as a [Cut]: a title, a body, a person's name, a label, a reason and a
// collection's title. An empty label is dropped, a label the same as one before it is
// dropped, and the labels past the most an item has are dropped, which is logged too.
// A field that cannot be cut into the contract, a ref, a URL, a target's path, an
// empty title or a time that is not RFC 3339, skips its item, comment or collection,
// which is logged by its ref, never by its text, and the rest are sent. A request is
// at most contracts.MaxRequest bytes, and lists at most the contract's most items,
// comments or collections.

// timeWidth stands for a request's time while the request is sized: the sink sets the
// time as it sends the request, and every time the wire carries, in
// contracts.TimeLayout's form, is as long as the layout itself.
const timeWidth = contracts.TimeLayout

// The most pages a listing reads: a repository's open issues, see
// [Lister.ListOpenIssuesComplete]; one issue's comments; and the installation's
// repositories. A listing that would read more stops, as does one whose next page
// repeats a page it read.
const (
	maxIssuePages      = 2000
	maxCommentPages    = 100
	maxRepositoryPages = 1000
)

// workItemMarker begins the comment the App writes on an issue that is work in
// Qory Apiary, see [Client.ApplyChange]. Such a comment by the App's bot is the
// adapter's, not the issue's, so it is never sent; the same words in a comment by anyone
// else are that person's comment.
const workItemMarker = "<!-- qory:work-item "

// Sink is where the wire's requests go: Qory Apiary's client, or a test's. Each method
// sends one request and returns once Qory Apiary took it. A request comes without its
// time, which the sink sets as it sends it. A request is at most 1 MiB as
// encoding/json's Marshal writes it, compact, its time set; a sink that encodes it
// otherwise, indented for one, may exceed that.
type Sink interface {
	// Collections sends POST /v1/source-collections.
	Collections(ctx context.Context, req contracts.SourceCollections) error
	// Items sends POST /v1/source-items.
	Items(ctx context.Context, req contracts.SourceItems) error
	// Comments sends POST /v1/source-items/comments.
	Comments(ctx context.Context, req contracts.SourceItemComments) error
	// Disconnect sends POST /v1/sources/disconnect.
	Disconnect(ctx context.Context, req contracts.SourcesDisconnect) error
}

// The fields of GitHub's answers and webhook payloads the adapter reads; the rest is
// ignored.
type (
	ghUser struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	}
	ghLabel struct {
		Name string `json:"name"`
	}
	ghRepo struct {
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	}
	ghIssue struct {
		Number      int64     `json:"number"`
		Title       string    `json:"title"`
		Body        *string   `json:"body"`
		State       string    `json:"state"`
		StateReason *string   `json:"state_reason"`
		HTMLURL     string    `json:"html_url"`
		Labels      []ghLabel `json:"labels"`
		User        *ghUser   `json:"user"`
		Comments    int       `json:"comments"`
		CreatedAt   string    `json:"created_at"`
		UpdatedAt   string    `json:"updated_at"`
		// PullRequest is set whenever the key is there, even null: GitHub lists pull
		// requests among issues and marks them with it.
		PullRequest json.RawMessage `json:"pull_request"`
	}
	ghComment struct {
		ID        int64   `json:"id"`
		HTMLURL   string  `json:"html_url"`
		Body      *string `json:"body"`
		User      *ghUser `json:"user"`
		CreatedAt string  `json:"created_at"`
		UpdatedAt string  `json:"updated_at"`
	}
)

// WebHost is the system an item's target names: the website of the API the client
// reaches, github.com for GitHub's, and for a test the loopback host. It is the host
// lower-cased and without its port, as the contract's pattern for a system takes it.
func (c Client) WebHost() string {
	u, err := url.Parse(c.base())
	if err != nil || u.Hostname() == APIHost {
		return GitHost
	}
	h := strings.ToLower(u.Hostname())
	if !contractLimits().system.MatchString(h) {
		// CheckAPIURL admits only GitHub's API or a loopback host, and a loopback
		// address such as ::1 does not fit the contract's pattern for a host name, so
		// the system is localhost, which does and names the same machine.
		return "localhost"
	}
	return h
}

// Cut is a text cut to the contract's limit, for the log: the ref of its item, comment
// or collection, the field, and its length before the cut, in characters, or in labels
// for the labels past the most an item has. It never holds the text.
type Cut struct {
	Ref, Field string
	Length     int
}

// fit is s cut to n characters, and when it is cut, a [Cut] of the field of ref added
// to cuts.
func fit(cuts *[]Cut, ref, field, s string, n int) string {
	if !tooLong(s, n) {
		return s
	}
	*cuts = append(*cuts, Cut{Ref: ref, Field: field, Length: utf8.RuneCountInString(s)})
	return cut(s, n)
}

// authorOf is who a user is on the wire, the field of ref: a bot is an automation,
// anyone else a person. The name is fitted to the contract's limit. A user GitHub no
// longer has, or one without a login, is its ghost.
func authorOf(u *ghUser, cuts *[]Cut, ref, field string) contracts.Person {
	p := contracts.Person{Kind: KindPerson}
	if u != nil {
		p.Name = fit(cuts, ref, field, u.Login, contractLimits().name)
		if u.Type == "Bot" {
			p.Kind = KindAutomation
		}
	}
	if p.Name == "" {
		p.Name = "ghost"
	}
	return p
}

// collectionOf is a repository's issues as a collection, without a target. A listing
// fits its title to the contract's limit; an event sends only its ref.
func collectionOf(r ghRepo) contracts.Collection {
	return contracts.Collection{Ref: r.FullName, URL: r.HTMLURL, Title: r.FullName}
}

// labelsOf are the labels of the issue ref as the contract takes them: each fitted to
// the limit of a label, an empty one dropped, one the same as a label before it
// dropped, and none past the most labels an item has, which is a [Cut] of labels.
func labelsOf(ls []ghLabel, cuts *[]Cut, ref string) []string {
	lim := contractLimits()
	labels := make([]string, 0, min(len(ls), lim.labels))
	seen := make(map[string]bool, cap(labels))
	for _, l := range ls {
		if len(labels) == lim.labels {
			*cuts = append(*cuts, Cut{Ref: ref, Field: "labels", Length: len(ls)})
			break
		}
		name := fit(cuts, ref, "label", l.Name, lim.label)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		labels = append(labels, name)
	}
	return labels
}

// stateReasons words GitHub's reasons an issue is closed for.
var stateReasons = map[string]string{"completed": "Completed", "not_planned": "Not planned", "duplicate": "Duplicate"}

// stateReason is why the closed issue ref is closed, in words, or nil: an open issue
// has no reason, and a reason without words is left out.
func stateReason(state string, reason *string, cuts *[]Cut, ref string) *string {
	if state != StateClosed || reason == nil {
		return nil
	}
	if w, ok := stateReasons[*reason]; ok {
		w = fit(cuts, ref, "state_reason", w, contractLimits().stateReason)
		return &w
	}
	return nil
}

// utc is a time GitHub says, in RFC 3339 and UTC.
func utc(s string) (string, bool) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return "", false
	}
	return t.UTC().Format(time.RFC3339), true
}

// itemOf is an issue of the repository r as an item whose target is on system, or why
// it is skipped, and the texts cut to fit it.
func itemOf(system string, r ghRepo, is ghIssue) (contracts.Item, string, []Cut) {
	lim := contractLimits()
	var cuts []Cut
	ref := r.FullName + "#" + strconv.FormatInt(is.Number, 10)
	state := StateOpen
	if is.State == StateClosed {
		state = StateClosed
	}
	body := ""
	if is.Body != nil {
		body = *is.Body
	}
	it := contracts.Item{
		Ref:          ref,
		URL:          is.HTMLURL,
		Title:        fit(&cuts, ref, "title", is.Title, lim.title),
		Body:         fit(&cuts, ref, "body", body, lim.body),
		BodyFormat:   FormatMarkdown,
		Type:         "issue",
		State:        state,
		StateReason:  stateReason(state, is.StateReason, &cuts, ref),
		Labels:       labelsOf(is.Labels, &cuts, ref),
		FiledBy:      authorOf(is.User, &cuts, ref, "filed_by.name"),
		CommentCount: max(is.Comments, 0),
		Target:       &contracts.Target{System: system, Path: r.FullName},
	}
	var ok1, ok2 bool
	it.CreatedAt, ok1 = utc(is.CreatedAt)
	it.UpdatedAt, ok2 = utc(is.UpdatedAt)
	switch {
	case !ok1 || !ok2:
		return it, "a time is not RFC 3339", nil
	case it.Title == "":
		return it, "its title is empty", nil
	}
	if why := checkRef(it.Ref); why != "" {
		return it, why, nil
	}
	if why := checkPath(it.Target.Path); why != "" {
		return it, why, nil
	}
	if why := checkURL(it.URL); why != "" {
		return it, why, nil
	}
	return it, "", cuts
}

// commentOf is a comment as the wire says it, or why it is skipped, and the texts cut
// to fit it.
func commentOf(c ghComment) (contracts.Comment, string, []Cut) {
	var cuts []Cut
	ref := strconv.FormatInt(c.ID, 10)
	body := ""
	if c.Body != nil {
		body = *c.Body
	}
	sc := contracts.Comment{
		Ref:        ref,
		URL:        c.HTMLURL,
		Author:     authorOf(c.User, &cuts, ref, "author.name"),
		Body:       fit(&cuts, ref, "body", body, contractLimits().body),
		BodyFormat: FormatMarkdown,
	}
	var ok1, ok2 bool
	sc.CreatedAt, ok1 = utc(c.CreatedAt)
	sc.UpdatedAt, ok2 = utc(c.UpdatedAt)
	if !ok1 || !ok2 {
		return sc, "a time is not RFC 3339", nil
	}
	if why := checkRef(sc.Ref); why != "" {
		return sc, why, nil
	}
	if why := checkURL(sc.URL); why != "" {
		return sc, why, nil
	}
	return sc, "", cuts
}

// checkCollection is why a collection is skipped, or "". A listing has fitted its
// title to the contract's limit, and an event sends only its ref.
func checkCollection(c contracts.Collection) string {
	if c.Title == "" {
		return "its title is empty"
	}
	if why := checkRef(c.Ref); why != "" {
		return why
	}
	if c.Target != nil {
		if why := checkPath(c.Target.Path); why != "" {
			return why
		}
	}
	return checkURL(c.URL)
}

func checkRef(ref string) string {
	if n := contractLimits().ref; ref == "" || tooLong(ref, n) {
		return fmt.Sprintf("a ref is empty or longer than %d characters", n)
	}
	return ""
}

func checkPath(path string) string {
	if n := contractLimits().path; path == "" || tooLong(path, n) {
		return fmt.Sprintf("its target's path is empty or longer than %d characters", n)
	}
	return ""
}

func checkURL(s string) string {
	u, err := url.Parse(s)
	if n := contractLimits().url; err != nil || u.Scheme != "https" || u.Host == "" || tooLong(s, n) {
		return fmt.Sprintf("its URL is not https or is longer than %d characters", n)
	}
	return ""
}

// size is how many bytes v is in JSON, as encoding/json writes it.
func size(v any) int {
	b, _ := json.Marshal(v)
	return len(b)
}

// sized is how many bytes a request is in JSON once the sink sets its time.
func sized[R contracts.SourceCollections | contracts.SourceItems | contracts.SourceItemComments](req R) int {
	switch r := any(&req).(type) {
	case *contracts.SourceCollections:
		r.Time = timeWidth
	case *contracts.SourceItems:
		r.Time = timeWidth
	case *contracts.SourceItemComments:
		r.Time = timeWidth
	}
	return size(req)
}

// Skipped is an item or a comment left out because Qory Apiary would refuse it: its ref,
// and why, never its text.
type Skipped struct {
	Ref, Why string
}

// ToSend is what a webhook's event becomes: the requests to send, in order, items
// before comments, and what was skipped and what was cut, for the log.
type ToSend struct {
	Items    []contracts.SourceItems
	Comments []contracts.SourceItemComments
	Skipped  []Skipped
	Cut      []Cut
}

// addItem adds an item of collection c to t, and the texts cut to fit it, unless it is
// to be skipped.
func (t *ToSend) addItem(c contracts.Collection, it contracts.Item, why string, cuts []Cut) {
	if cw := checkCollection(c); why == "" && cw != "" {
		why = "its collection: " + cw
	}
	req := contracts.SourceItems{Version: contracts.Version, CollectionRef: c.Ref, Items: []contracts.Item{it}}
	if why == "" && sized(req) > contracts.MaxRequest {
		why = "it is larger than a request may be"
	}
	if why != "" {
		t.Skipped = append(t.Skipped, Skipped{Ref: it.Ref, Why: why})
		return
	}
	t.Items = append(t.Items, req)
	t.Cut = append(t.Cut, cuts...)
}

// IssuesWebhook is what an issues event, GitHub's webhook payload, becomes; system is the
// target's system, [Client.WebHost]. Opened, reopened, edited, closed, labeled and
// unlabeled send the issue as it is now, and deleted sends it closed. Transferred sends
// the issue closed in the repository it left and, when active says the repository it
// went to is one Qory Apiary reads, the issue it became there. Every other action, and
// an event for a pull request, sends nothing. It does no I/O.
func IssuesWebhook(payload []byte, system string, active func(Repository) bool) (ToSend, error) {
	var ev struct {
		Action     string  `json:"action"`
		Issue      ghIssue `json:"issue"`
		Repository ghRepo  `json:"repository"`
		Changes    struct {
			NewIssue      *ghIssue `json:"new_issue"`
			NewRepository *ghRepo  `json:"new_repository"`
		} `json:"changes"`
	}
	var t ToSend
	if err := json.Unmarshal(payload, &ev); err != nil {
		return t, fmt.Errorf("the issues event is not JSON GitHub sends: %w", err)
	}
	if ev.Issue.PullRequest != nil {
		return t, nil
	}
	switch ev.Action {
	case "opened", "reopened", "edited", "closed", "labeled", "unlabeled":
	case "deleted", "transferred":
		ev.Issue.State, ev.Issue.StateReason = StateClosed, nil
	default:
		return t, nil
	}
	it, why, cuts := itemOf(system, ev.Repository, ev.Issue)
	t.addItem(collectionOf(ev.Repository), it, why, cuts)
	if ev.Action != "transferred" || ev.Changes.NewIssue == nil || ev.Changes.NewRepository == nil {
		return t, nil
	}
	owner, name, ok := strings.Cut(ev.Changes.NewRepository.FullName, "/")
	if !ok || active == nil || !active(Repository{Owner: owner, Name: name}) {
		return t, nil
	}
	it, why, cuts = itemOf(system, *ev.Changes.NewRepository, *ev.Changes.NewIssue)
	t.addItem(collectionOf(*ev.Changes.NewRepository), it, why, cuts)
	return t, nil
}

// IssueCommentWebhook is what an issue_comment event, GitHub's webhook payload, becomes;
// slug is the App's, whose bot writes the work item comment. Created and edited send the
// comment, and deleted sends it deleted. A comment on a pull request, the work item
// comment by the App's bot, and every other action send nothing. It does no I/O.
func IssueCommentWebhook(payload []byte, slug string) (ToSend, error) {
	var ev struct {
		Action     string    `json:"action"`
		Issue      ghIssue   `json:"issue"`
		Comment    ghComment `json:"comment"`
		Repository ghRepo    `json:"repository"`
	}
	var t ToSend
	if err := json.Unmarshal(payload, &ev); err != nil {
		return t, fmt.Errorf("the issue_comment event is not JSON GitHub sends: %w", err)
	}
	if ev.Issue.PullRequest != nil || workItemComment(ev.Comment, slug) {
		return t, nil
	}
	switch ev.Action {
	case "created", "edited", "deleted":
	default:
		return t, nil
	}
	// A deleted comment is sent without its body, so the size limits never lose a
	// deletion.
	if ev.Action == "deleted" {
		ev.Comment.Body = nil
	}
	c, why, cuts := commentOf(ev.Comment)
	c.Deleted = ev.Action == "deleted"
	coll := collectionOf(ev.Repository)
	req := contracts.SourceItemComments{
		Version:  contracts.Version,
		ItemRef:  ev.Repository.FullName + "#" + strconv.FormatInt(ev.Issue.Number, 10),
		Comments: []contracts.Comment{c},
	}
	if cw := checkCollection(coll); why == "" && cw != "" {
		why = "its collection: " + cw
	}
	if iw := checkRef(req.ItemRef); why == "" && iw != "" {
		why = "its item: " + iw
	}
	if why == "" && sized(req) > contracts.MaxRequest {
		why = "it is larger than a request may be"
	}
	if why != "" {
		t.Skipped = append(t.Skipped, Skipped{Ref: c.Ref, Why: why})
		return t, nil
	}
	t.Comments = append(t.Comments, req)
	t.Cut = append(t.Cut, cuts...)
	return t, nil
}

// workItemComment is whether c is the App's work item comment: written by the App's bot,
// slug[bot] of type Bot, and beginning with the marker. Logins are ASCII, so EqualFold
// folds ASCII's cases alone.
func workItemComment(c ghComment, slug string) bool {
	return slug != "" && c.User != nil && c.User.Type == "Bot" && strings.EqualFold(c.User.Login, slug+"[bot]") && c.Body != nil && strings.HasPrefix(*c.Body, workItemMarker)
}

// Lister lists what one installation of the App reaches on GitHub and sends it to
// Qory Apiary.
type Lister struct {
	// Client reaches GitHub's API.
	Client Client
	// Pacer is the installation's, shared with every other caller for it; nil is one
	// for each listing.
	Pacer *Pacer
	// Token returns an installation token for the listing: for
	// [Lister.ListOpenIssuesComplete] and [Lister.ListChanged] one that reads the
	// repository's issues, such as [Client.MintInstallationToken]
	// mints, and for [Lister.ListRepositories] one that reads which repositories the
	// installation reaches, such as [Client.MintListingToken] mints. It is called before
	// every request, so it keeps a token until shortly before it expires.
	Token func(context.Context) (string, error)
	// Slug is the App's, whose bot writes the work item comment.
	Slug string
	// Sink is where the requests go.
	Sink Sink
	// Logf logs what is skipped; nil is log.Printf.
	Logf func(format string, args ...any)
	// LogCut logs a text cut to the contract's limit, one call for each; nil logs it
	// with Logf.
	LogCut func(Cut)
}

func (l Lister) logf(format string, args ...any) {
	if l.Logf != nil {
		l.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// logCuts logs each of cuts.
func (l Lister) logCuts(cuts []Cut) {
	for _, c := range cuts {
		if l.LogCut != nil {
			l.LogCut(c)
			continue
		}
		l.logf("cut the %s of %s, %d long, to the contract's limit", c.Field, c.Ref, c.Length)
	}
}

// get reads one page with a fresh token and returns the next page's path.
func (l Lister) get(ctx context.Context, p *Pacer, what, path string, out any) (string, error) {
	token, err := l.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("%s: the installation token: %w", what, &tokenError{err})
	}
	return l.Client.get(ctx, p, true, what, path, token, out)
}

// tokenError is the error of a listing's token, so GitHub's answer to the mint is never
// taken for its answer to the listing's request.
type tokenError struct{ err error }

func (e *tokenError) Error() string { return e.err.Error() }
func (e *tokenError) Unwrap() error { return e.err }

// ErrRepositoryGone is wrapped in the error of a listing whose repository GitHub
// answers is gone or moved, [Gone], as it answers the read of the repository or of a
// page of its issues: deleted, renamed, transferred or out of the App's reach. Asking
// again does not change it.
var ErrRepositoryGone = errors.New("the repository is deleted, moved or out of the App's reach")

// answeredGone is whether err is GitHub's answer to a listing's request, not to its
// token's mint, that what was asked for is gone or moved.
func answeredGone(err error) bool {
	var t *tokenError
	return Gone(err) && !errors.As(err, &t)
}

// repositoryGone is err, wrapping [ErrRepositoryGone] when GitHub answered that the
// repository is gone or moved.
func repositoryGone(err error) error {
	if answeredGone(err) {
		return fmt.Errorf("%w: %w", ErrRepositoryGone, err)
	}
	return err
}

// pages keeps a listing to at most max pages, none read twice.
type pages struct {
	what string
	max  int
	seen map[string]bool
}

// read is whether the page at path may be read.
func (p *pages) read(path string) error {
	if p.seen[path] {
		return fmt.Errorf("%s: GitHub's next page repeats one already read", p.what)
	}
	if len(p.seen) == p.max {
		return fmt.Errorf("%s: GitHub has more than %d pages, which a listing never reads", p.what, p.max)
	}
	if p.seen == nil {
		p.seen = map[string]bool{}
	}
	p.seen[path] = true
	return nil
}

// A REST listing reads the next page GitHub's Link header names. GitHub documents its
// REST listings as paged by number, and a page's contents shift when an earlier one
// loses an entry, so a listing by number can miss one. GitHub's REST listing of issues,
// as GitHub answers it today, names its next page by a cursor, after, as well as by
// number, but GitHub's documentation still describes page numbers alone, so the adapter
// does not rely on that cursor: the listing of open issues reads them by GraphQL's
// cursor instead, which does not skip one, and says it is complete unless it skipped an
// item, see [Lister.ListOpenIssuesComplete]. The listings of an issue's comments never
// say they are complete: they add and update what they see, never drop what they do
// not, and a comment's deletion comes from webhooks' events alone. A listing of the
// installation's repositories says it is complete when GitHub answers it with one page
// and it skips none, which nothing can shift, see [Lister.ListRepositories].

// listingEnd is how long the request that ends a listing stopped early may take,
// even when the listing stopped because its context is done.
const listingEnd = 10 * time.Second

// ListRepositories lists the repositories the installation reaches, as collections, in
// parts of at most 100 collections and 1 MiB, and reads at most 1,000 pages. When GitHub
// answers with one page, up to 100 repositories, nothing can shift, so the last part
// says the listing is complete, and Qory Apiary disconnects a repository the
// installation no longer reaches; unless a repository was skipped, which then must not
// be disconnected, so that listing is not complete. A listing of more than one page never says it is
// complete, since a repository removed from the installation while it is listed shifts
// the pages after it: that is a limit, and such a removal reaches Qory Apiary only by
// the installation_repositories event that says it was removed. A listing stopped
// early, by an error or its context, still ends with a part, never complete.
func (l Lister) ListRepositories(ctx context.Context) error {
	if l.Sink == nil || l.Token == nil {
		return errors.New("the lister has no sink or no token")
	}
	p := l.pacerOr()
	// The listing starts before its first request to GitHub: Qory Apiary disconnects
	// what a complete listing left out and did not hear of since it started, so a
	// later start would drop a collection that changed meanwhile.
	listing := contracts.Listing{ID: randomHex(), StartedAt: contracts.FormatTime(p.now())}
	system := l.Client.WebHost()
	var pending []contracts.Collection
	skipped := false
	send := func(ctx context.Context, complete bool) error {
		listing.Part++
		listing.Complete = complete
		req := contracts.SourceCollections{Version: contracts.Version, Collections: pending, Listing: listing}
		if req.Collections == nil {
			req.Collections = []contracts.Collection{}
		}
		pending = nil
		return l.Sink.Collections(ctx, req)
	}
	envelope := sized(contracts.SourceCollections{Version: contracts.Version, Collections: []contracts.Collection{}, Listing: contracts.Listing{ID: listing.ID, Part: 1 << 31, StartedAt: listing.StartedAt}})
	used := envelope
	// A part Qory Apiary did not take leaves the listing short, so the listing stops
	// there, and the part that ends it says it is not complete.
	stop := func(err error) error {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), listingEnd)
		defer cancel()
		return errors.Join(err, send(ctx, false))
	}
	const what = "listing the installation's repositories"
	read := pages{what: what, max: maxRepositoryPages}
	path := "/installation/repositories?per_page=100"
	for path != "" {
		if err := read.read(path); err != nil {
			return stop(err)
		}
		var page struct {
			Repositories []ghRepo `json:"repositories"`
		}
		next, err := l.get(ctx, p, what, path, &page)
		if err != nil {
			return stop(err)
		}
		for _, r := range page.Repositories {
			var cuts []Cut
			c := collectionOf(r)
			c.Title = fit(&cuts, c.Ref, "title", c.Title, contractLimits().title)
			c.Target = &contracts.Target{System: system, Path: r.FullName}
			n := size(c)
			if why := checkCollection(c); why != "" || envelope+n > contracts.MaxRequest {
				l.logf("skipped the collection %s: %s", c.Ref, orTooLarge(why))
				skipped = true
				continue
			}
			l.logCuts(cuts)
			if len(pending) == contractLimits().collections || used+n+1 > contracts.MaxRequest {
				if err := send(ctx, false); err != nil {
					return stop(err)
				}
				used = envelope
			}
			pending = append(pending, c)
			used += n + 1
		}
		path = next
	}
	if err := send(ctx, len(read.seen) == 1 && !skipped); err != nil {
		return stop(err)
	}
	return nil
}

// orTooLarge is why, or, when why is empty, that the collection is larger than a request may be.
func orTooLarge(why string) string {
	if why == "" {
		return "it is larger than a request may be"
	}
	return why
}

func (l Lister) pacerOr() *Pacer {
	if l.Pacer != nil {
		return l.Pacer
	}
	return &Pacer{}
}

// listed is an item of a listing and what its comments are read by.
type listed struct {
	item     contracts.Item
	number   int64
	comments int
}

// openParts sends the open issues a listing reads to Qory Apiary, in parts of at most
// 100 items and 1 MiB, and after each part the comments of its items; see
// [Lister.ListOpenIssuesComplete].
type openParts struct {
	l       Lister
	p       *Pacer
	repo    Repository
	system  string
	listing contracts.Listing
	coll    contracts.Collection
	pending []listed
	// envelope is the size of a part without items, and used the size of the part
	// pending.
	envelope, used int
	// ended is whether the last part is sent, or there was none to send.
	ended bool
	// skipped is whether an item was left out, which a listing that says it is complete
	// never does, since Qory Apiary would close it.
	skipped bool
}

// openParts starts sending the parts of listing, the open issues of repo, the
// collection coll.
func (l Lister) openParts(p *Pacer, repo Repository, listing contracts.Listing, coll contracts.Collection) *openParts {
	o := &openParts{l: l, p: p, repo: repo, system: l.Client.WebHost(), listing: listing, coll: coll}
	o.envelope = sized(contracts.SourceItems{Version: contracts.Version, CollectionRef: coll.Ref, Items: []contracts.Item{}, Listing: &contracts.Listing{ID: listing.ID, Part: 1 << 31, StartedAt: listing.StartedAt}})
	o.used = o.envelope
	return o
}

// add adds the open issue is of the repository r to the part pending, or skips and
// logs it. A part that is full first goes, with its items' comments.
func (o *openParts) add(ctx context.Context, r ghRepo, is ghIssue) error {
	it, why, cuts := itemOf(o.system, r, is)
	n := size(it)
	if why == "" && o.envelope+n > contracts.MaxRequest {
		why = "it is larger than a request may be"
	}
	if why != "" {
		o.l.logf("skipped the item %s: %s", it.Ref, why)
		o.skipped = true
		return nil
	}
	o.l.logCuts(cuts)
	if len(o.pending) == contractLimits().items || o.used+n+1 > contracts.MaxRequest {
		sent, err := o.send(ctx, false, false)
		if err != nil {
			return err
		}
		if err := o.l.listComments(ctx, o.p, o.repo, sent); err != nil {
			return err
		}
	}
	o.pending = append(o.pending, listed{item: it, number: is.Number, comments: is.Comments})
	o.used += n + 1
	return nil
}

// send sends the part pending, which complete says is the complete listing's last, and
// returns its items. last marks the listing's last part. Nothing pending sends nothing,
// unless the part is the complete listing's last: a part without items then says every
// open issue is in the parts before it, or, as a listing's one part, that the
// repository has none.
func (o *openParts) send(ctx context.Context, last, complete bool) ([]listed, error) {
	if len(o.pending) == 0 && !complete {
		o.ended = last
		return nil, nil
	}
	o.listing.Part++
	part := o.listing
	part.Complete = complete
	req := contracts.SourceItems{Version: contracts.Version, CollectionRef: o.coll.Ref, Items: make([]contracts.Item, 0, len(o.pending)), Listing: &part}
	for _, x := range o.pending {
		req.Items = append(req.Items, x.item)
	}
	sent := o.pending
	o.pending, o.used = nil, o.envelope
	if err := o.l.Sink.Items(ctx, req); err != nil {
		return nil, err
	}
	o.ended = last
	return sent, nil
}

// end sends the last part, which says the listing is complete when complete does, and
// then its items' comments.
func (o *openParts) end(ctx context.Context, complete bool) error {
	sent, err := o.send(ctx, true, complete)
	if err != nil {
		return o.stop(ctx, err)
	}
	return o.l.listComments(ctx, o.p, o.repo, sent)
}

// stop ends a listing stopped early by err: the items read and not sent go as its last
// part, which never says it is complete, even once ctx is done.
func (o *openParts) stop(ctx context.Context, err error) error {
	if o.ended {
		return err
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), listingEnd)
	defer cancel()
	_, end := o.send(ctx, false, false)
	return errors.Join(err, end)
}

// listComments reads and sends the comments of the items that have any. An item's
// comments are read oldest first, by REST's pages, which GitHub documents by number, and
// a comment deleted while they are read can shift the pages after it, so no request
// says they are complete.
func (l Lister) listComments(ctx context.Context, p *Pacer, repo Repository, items []listed) error {
items:
	for _, x := range items {
		if x.comments <= 0 {
			continue
		}
		req := contracts.SourceItemComments{Version: contracts.Version, ItemRef: x.item.Ref, Comments: []contracts.Comment{}}
		envelope := sized(req)
		used := envelope
		what := "listing the comments on " + x.item.Ref
		read := pages{what: what, max: maxCommentPages}
		path := "/repos/" + repo.String() + "/issues/" + strconv.FormatInt(x.number, 10) + "/comments?per_page=100"
		for path != "" {
			if err := read.read(path); err != nil {
				return err
			}
			var page []ghComment
			next, err := l.get(ctx, p, what, path, &page)
			if answeredGone(err) {
				// The issue was deleted or moved while it was listed: its comments are
				// left, and the listing goes on.
				l.logf("skipped the comments on %s: GitHub answers that the issue is gone or moved", x.item.Ref)
				continue items
			}
			if err != nil {
				return err
			}
			for _, c := range page {
				if workItemComment(c, l.Slug) {
					continue
				}
				sc, why, cuts := commentOf(c)
				n := size(sc)
				if why == "" && envelope+n > contracts.MaxRequest {
					why = "it is larger than a request may be"
				}
				if why != "" {
					l.logf("skipped the comment %s on %s: %s", sc.Ref, x.item.Ref, why)
					continue
				}
				l.logCuts(cuts)
				if len(req.Comments) == contractLimits().comments || used+n+1 > contracts.MaxRequest {
					if err := l.Sink.Comments(ctx, req); err != nil {
						return err
					}
					req.Comments, used = []contracts.Comment{}, envelope
				}
				req.Comments = append(req.Comments, sc)
				used += n + 1
			}
			path = next
		}
		if len(req.Comments) == 0 {
			continue
		}
		if err := l.Sink.Comments(ctx, req); err != nil {
			return err
		}
	}
	return nil
}
