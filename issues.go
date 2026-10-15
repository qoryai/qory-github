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

// What Qory Apiary takes. It refuses a request that exceeds one of these and cuts
// nothing, so the adapter never sends one that does: an item, a comment or a
// collection that breaks one, in a listing or in a webhook's event, is skipped, and
// logged by its ref, never by its text. Lengths are counted in characters, Unicode
// code points. A request is at most contracts.MaxRequest bytes, and lists at most
// maxPerBatch items, comments or collections.
const (
	maxTitle    = 1024
	maxBody     = 65536
	maxLabels   = 100
	maxRef      = 200
	maxURL      = 2048
	maxPerBatch = 100
)

// timeWidth stands for a request's time while the request is sized: the sink sets the
// time as it sends the request, and every time the wire carries, in
// contracts.TimeLayout's form, is as long as the layout itself.
const timeWidth = contracts.TimeLayout

// The most pages a listing reads: a repository's issues, every state's, pull requests
// among them, since GitHub lists both and the adapter drops pull requests after reading
// them; one issue's comments; and the installation's repositories. A listing that would
// read more stops, as does one whose next page repeats a page it read.
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
// reaches, github.com for GitHub's, and for a test the loopback host and port.
func (c Client) WebHost() string {
	u, err := url.Parse(c.base())
	if err != nil || u.Hostname() == APIHost {
		return GitHost
	}
	return u.Host
}

// authorOf is who a user is on the wire: a bot is an automation, anyone else a person.
// A user GitHub no longer has is its ghost.
func authorOf(u *ghUser) contracts.Person {
	if u == nil {
		return contracts.Person{Name: "ghost", Kind: KindPerson}
	}
	if u.Type == "Bot" {
		return contracts.Person{Name: u.Login, Kind: KindAutomation}
	}
	return contracts.Person{Name: u.Login, Kind: KindPerson}
}

// collectionOf is a repository's issues as a collection, without a target.
func collectionOf(r ghRepo) contracts.Collection {
	return contracts.Collection{Ref: r.FullName, URL: r.HTMLURL, Title: r.FullName}
}

// stateReasons words GitHub's reasons an issue is closed for.
var stateReasons = map[string]string{"completed": "Completed", "not_planned": "Not planned", "duplicate": "Duplicate"}

// stateReason is why a closed issue is closed, in words, or nil: an open issue has no
// reason, and a reason without words is left out.
func stateReason(state string, reason *string) *string {
	if state != StateClosed || reason == nil {
		return nil
	}
	if w, ok := stateReasons[*reason]; ok {
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
// it is skipped.
func itemOf(system string, r ghRepo, is ghIssue) (contracts.Item, string) {
	labels := make([]string, 0, len(is.Labels))
	for _, l := range is.Labels {
		labels = append(labels, l.Name)
	}
	state := StateOpen
	if is.State == StateClosed {
		state = StateClosed
	}
	body := ""
	if is.Body != nil {
		body = *is.Body
	}
	it := contracts.Item{
		Ref:          r.FullName + "#" + strconv.FormatInt(is.Number, 10),
		URL:          is.HTMLURL,
		Title:        is.Title,
		Body:         body,
		BodyFormat:   FormatMarkdown,
		Type:         "issue",
		State:        state,
		StateReason:  stateReason(state, is.StateReason),
		Labels:       labels,
		FiledBy:      authorOf(is.User),
		CommentCount: is.Comments,
		Target:       &contracts.Target{System: system, Path: r.FullName},
	}
	var ok1, ok2 bool
	it.CreatedAt, ok1 = utc(is.CreatedAt)
	it.UpdatedAt, ok2 = utc(is.UpdatedAt)
	switch {
	case !ok1 || !ok2:
		return it, "a time is not RFC 3339"
	case utf8.RuneCountInString(it.Title) < 1 || utf8.RuneCountInString(it.Title) > maxTitle:
		return it, "its title is empty or longer than 1,024 characters"
	case utf8.RuneCountInString(it.Body) > maxBody:
		return it, "its body is longer than 65,536 characters"
	case len(it.Labels) > maxLabels:
		return it, "it has more than 100 labels"
	}
	if why := checkRef(it.Ref); why != "" {
		return it, why
	}
	if why := checkRef(it.Target.Path); why != "" {
		return it, why
	}
	return it, checkURL(it.URL)
}

// commentOf is a comment as the wire says it, or why it is skipped.
func commentOf(c ghComment) (contracts.Comment, string) {
	body := ""
	if c.Body != nil {
		body = *c.Body
	}
	sc := contracts.Comment{
		Ref:        strconv.FormatInt(c.ID, 10),
		URL:        c.HTMLURL,
		Author:     authorOf(c.User),
		Body:       body,
		BodyFormat: FormatMarkdown,
	}
	var ok1, ok2 bool
	sc.CreatedAt, ok1 = utc(c.CreatedAt)
	sc.UpdatedAt, ok2 = utc(c.UpdatedAt)
	switch {
	case !ok1 || !ok2:
		return sc, "a time is not RFC 3339"
	case utf8.RuneCountInString(sc.Body) > maxBody:
		return sc, "its body is longer than 65,536 characters"
	}
	if why := checkRef(sc.Ref); why != "" {
		return sc, why
	}
	return sc, checkURL(sc.URL)
}

// checkCollection is why a collection is skipped, or "".
func checkCollection(c contracts.Collection) string {
	if n := utf8.RuneCountInString(c.Title); n < 1 || n > maxTitle {
		return "its title is empty or longer than 1,024 characters"
	}
	if why := checkRef(c.Ref); why != "" {
		return why
	}
	return checkURL(c.URL)
}

func checkRef(ref string) string {
	if n := utf8.RuneCountInString(ref); n < 1 || n > maxRef {
		return "a ref is empty or longer than 200 characters"
	}
	return ""
}

func checkURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || len(s) > maxURL {
		return "its URL is not https or is longer than 2,048 characters"
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
// before comments, and what was skipped, for the log.
type ToSend struct {
	Items    []contracts.SourceItems
	Comments []contracts.SourceItemComments
	Skipped  []Skipped
}

// addItem adds an item of collection c to t, unless it is to be skipped.
func (t *ToSend) addItem(c contracts.Collection, it contracts.Item, why string) {
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
	it, why := itemOf(system, ev.Repository, ev.Issue)
	t.addItem(collectionOf(ev.Repository), it, why)
	if ev.Action != "transferred" || ev.Changes.NewIssue == nil || ev.Changes.NewRepository == nil {
		return t, nil
	}
	owner, name, ok := strings.Cut(ev.Changes.NewRepository.FullName, "/")
	if !ok || active == nil || !active(Repository{Owner: owner, Name: name}) {
		return t, nil
	}
	it, why = itemOf(system, *ev.Changes.NewRepository, *ev.Changes.NewIssue)
	t.addItem(collectionOf(*ev.Changes.NewRepository), it, why)
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
	c, why := commentOf(ev.Comment)
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
	// Token returns an installation token that reads the installation's issues, such
	// as [Client.MintInstallationToken] mints. It is called before every request, so it
	// keeps a token until shortly before it expires.
	Token func(context.Context) (string, error)
	// Slug is the App's, whose bot writes the work item comment.
	Slug string
	// Sink is where the requests go.
	Sink Sink
	// Logf logs what is skipped; nil is log.Printf.
	Logf func(format string, args ...any)
}

func (l Lister) logf(format string, args ...any) {
	if l.Logf != nil {
		l.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// get reads one page with a fresh token and returns the next page's path.
func (l Lister) get(ctx context.Context, p *Pacer, what, path string, out any) (string, error) {
	token, err := l.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("%s: the installation token: %w", what, err)
	}
	return l.Client.get(ctx, p, true, what, path, token, out)
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

// A listing reads GitHub's pages by number, and a page's contents shift when an
// earlier one loses an entry, so a listing can miss one. A listing of issues or of an
// issue's comments never says it is complete, then: it adds and updates what it sees,
// never closes or drops what it does not, and closing and deleting come from webhooks'
// events alone. The one exception is a listing of the installation's repositories that
// GitHub answers with one page and that skips none, which nothing can shift; see
// [Lister.ListRepositories].

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
			c := collectionOf(r)
			c.Target = &contracts.Target{System: system, Path: r.FullName}
			n := size(c)
			if why := checkCollection(c); why != "" || envelope+n > contracts.MaxRequest {
				l.logf("skipped the collection %s: %s", c.Ref, orTooLarge(why))
				skipped = true
				continue
			}
			if len(pending) == maxPerBatch || used+n+1 > contracts.MaxRequest {
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

// ListIssues lists the repository's open issues, pull requests left out, and their
// comments, and sends them to Qory Apiary: items in parts of at most 100 items and
// 1 MiB, and after each part the comments of its items, for an issue that has any, in
// requests of at most 100 comments and 1 MiB. The App's work item comment is left out.
//
// It reads every issue, in every state, oldest first, and sends the open ones alone:
// closing an issue then moves none of the others from one page to another, as it
// would in a list of open issues, which deleting or transferring one still does. It
// reads at most 2,000 pages of issues and 100 of an issue's comments.
//
// No part says the listing is complete, nor do an item's comments, so Qory Apiary closes
// and drops nothing a listing does not see. What that leaves is a limit: an issue a
// listing missed, as one deleted or transferred while it was listed makes it miss one,
// and an issue closed while its repository was not mirrored, stay as Qory Apiary has
// them until that issue next changes on GitHub, and its webhook event brings it. A
// listing stopped early, by an error or its context, still ends with a part; one that
// cannot read the repository sends nothing.
func (l Lister) ListIssues(ctx context.Context, repo Repository) error {
	if !ownerShape.MatchString(repo.Owner) || !nameShape.MatchString(repo.Name) || repo.Name == "." || repo.Name == ".." {
		return fmt.Errorf("%q is not owner/name", repo.String())
	}
	if l.Sink == nil || l.Token == nil || l.Slug == "" {
		return errors.New("the lister has no sink, no token or no App slug")
	}
	p := l.pacerOr()
	// The listing starts before its first request to GitHub: Qory Apiary disconnects
	// what a complete listing left out and did not hear of since it started, so a
	// later start would drop a collection that changed meanwhile.
	listing := contracts.Listing{ID: randomHex(), StartedAt: contracts.FormatTime(p.now())}
	var r ghRepo
	if _, err := l.get(ctx, p, "reading the repository "+repo.String(), "/repos/"+repo.String(), &r); err != nil {
		return err
	}
	coll := collectionOf(r)
	if why := checkCollection(coll); why != "" {
		return fmt.Errorf("the repository %s cannot be a collection: %s", repo, why)
	}
	system := l.Client.WebHost()
	var pending []listed
	ended := false
	send := func(ctx context.Context, last bool) ([]listed, error) {
		listing.Part++
		part := listing
		req := contracts.SourceItems{Version: contracts.Version, CollectionRef: coll.Ref, Items: make([]contracts.Item, 0, len(pending)), Listing: &part}
		for _, x := range pending {
			req.Items = append(req.Items, x.item)
		}
		sent := pending
		pending = nil
		if err := l.Sink.Items(ctx, req); err != nil {
			return nil, err
		}
		ended = last
		return sent, nil
	}
	envelope := sized(contracts.SourceItems{Version: contracts.Version, CollectionRef: coll.Ref, Items: []contracts.Item{}, Listing: &contracts.Listing{ID: listing.ID, Part: 1 << 31, StartedAt: listing.StartedAt}})
	used := envelope
	stop := func(err error) error {
		if ended {
			return err
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), listingEnd)
		defer cancel()
		_, end := send(ctx, false)
		return errors.Join(err, end)
	}
	what := "listing the issues of " + repo.String()
	read := pages{what: what, max: maxIssuePages}
	path := "/repos/" + repo.String() + "/issues?state=all&sort=created&direction=asc&per_page=100"
	for path != "" {
		if err := read.read(path); err != nil {
			return stop(err)
		}
		var page []ghIssue
		next, err := l.get(ctx, p, what, path, &page)
		if err != nil {
			return stop(err)
		}
		for _, is := range page {
			if is.PullRequest != nil || is.State != StateOpen {
				continue
			}
			it, why := itemOf(system, r, is)
			n := size(it)
			if why == "" && envelope+n > contracts.MaxRequest {
				why = "it is larger than a request may be"
			}
			if why != "" {
				l.logf("skipped the item %s: %s", it.Ref, why)
				continue
			}
			if len(pending) == maxPerBatch || used+n+1 > contracts.MaxRequest {
				sent, err := send(ctx, false)
				if err != nil {
					return stop(err)
				}
				used = envelope
				if err := l.listComments(ctx, p, repo, sent); err != nil {
					return stop(err)
				}
			}
			pending = append(pending, listed{item: it, number: is.Number, comments: is.Comments})
			used += n + 1
		}
		path = next
	}
	sent, err := send(ctx, true)
	if err != nil {
		return stop(err)
	}
	return l.listComments(ctx, p, repo, sent)
}

// listComments reads and sends the comments of the items that have any. An item's
// comments are read by page number too, oldest first, and a comment deleted while they
// are read shifts the pages after it, so no request says they are complete.
func (l Lister) listComments(ctx context.Context, p *Pacer, repo Repository, items []listed) error {
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
			if err != nil {
				return err
			}
			for _, c := range page {
				if workItemComment(c, l.Slug) {
					continue
				}
				sc, why := commentOf(c)
				n := size(sc)
				if why == "" && envelope+n > contracts.MaxRequest {
					why = "it is larger than a request may be"
				}
				if why != "" {
					l.logf("skipped the comment %s on %s: %s", sc.Ref, x.item.Ref, why)
					continue
				}
				if len(req.Comments) == maxPerBatch || used+n+1 > contracts.MaxRequest {
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
