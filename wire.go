package github

// The types below are the requests Qory Apiary takes from a work source's adapter, the
// generic wire. They mirror the integrations contract's draft and will be replaced by
// its Go types once the contract is published. Their field names and values carry no
// GitHub word: GitHub's names are only inside the opaque values, a ref, a URL, a path.
//
// Every time is RFC 3339 in UTC.

// WireVersion is the version of the wire every request says.
const WireVersion = 1

// Body formats an item's or a comment's body is in.
const (
	FormatMarkdown = "markdown"
	FormatText     = "text"
)

// States an item is in.
const (
	StateOpen   = "open"
	StateClosed = "closed"
)

// Kinds of author: a person, or an automation, such as a bot.
const (
	KindPerson     = "person"
	KindAutomation = "automation"
)

// Reasons a collection is disconnected.
const (
	ReasonRemoved = "removed"
	ReasonEnded   = "ended"
	ReasonPaused  = "paused"
)

// SourceCollections is POST /v1/source-collections: one part of a listing of the
// collections the adapter reaches.
type SourceCollections struct {
	Version     int                `json:"version"`
	Collections []SourceCollection `json:"collections"`
	Listing     Listing            `json:"listing"`
}

// SourceCollection is one collection of items, such as a repository's issues. In a
// request for items it has no target.
type SourceCollection struct {
	Ref    string  `json:"ref"`
	URL    string  `json:"url"`
	Title  string  `json:"title"`
	Target *Target `json:"target,omitempty"`
}

// Target is where work on an item happens: the system and the path within it.
type Target struct {
	System string `json:"system"`
	Path   string `json:"path"`
}

// Listing places a request in a listing: the listing's id, the request's part, numbered
// from 1, when the listing started, and, on its last part, whether it saw everything.
// Only a complete listing lets Qory Apiary close what it did not see.
type Listing struct {
	ID        string `json:"id"`
	Part      int    `json:"part"`
	StartedAt string `json:"started_at"`
	Complete  bool   `json:"complete"`
}

// SourceItems is POST /v1/source-items: items of one collection, as a part of a listing
// or, without one, as an event changed them.
type SourceItems struct {
	Version    int              `json:"version"`
	Collection SourceCollection `json:"collection"`
	Items      []SourceItem     `json:"items"`
	Listing    *Listing         `json:"listing,omitempty"`
}

// SourceItem is one item of work, such as an issue. StateReason is null unless the item
// is closed with a reason.
type SourceItem struct {
	Ref          string   `json:"ref"`
	URL          string   `json:"url"`
	Title        string   `json:"title"`
	Body         string   `json:"body"`
	BodyFormat   string   `json:"body_format"`
	Type         string   `json:"type"`
	State        string   `json:"state"`
	StateReason  *string  `json:"state_reason"`
	Labels       []string `json:"labels"`
	FiledBy      Author   `json:"filed_by"`
	CommentCount int      `json:"comment_count"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
	Target       Target   `json:"target"`
}

// Author is who filed an item or wrote a comment: a name and a kind, [KindPerson] or
// [KindAutomation].
type Author struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// SourceComments is POST /v1/source-items/comments: comments on one item. Complete,
// when set, says these and the item's earlier requests of this listing are every comment
// the item has, so Qory Apiary may drop one it holds that was not updated since.
type SourceComments struct {
	Version       int              `json:"version"`
	CollectionRef string           `json:"collection_ref"`
	ItemRef       string           `json:"item_ref"`
	Comments      []SourceComment  `json:"comments"`
	Complete      *CommentsListing `json:"complete,omitempty"`
}

// CommentsListing marks the last request of an item's comments in a listing: Since is
// when the listing started.
type CommentsListing struct {
	Since string `json:"since"`
}

// SourceComment is one comment on an item. Deleted says the comment is gone.
type SourceComment struct {
	Ref        string `json:"ref"`
	URL        string `json:"url"`
	Author     Author `json:"author"`
	Body       string `json:"body"`
	BodyFormat string `json:"body_format"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	Deleted    bool   `json:"deleted,omitempty"`
}

// SourceDisconnect is POST /v1/sources/disconnect: a collection the adapter no longer
// reaches, and why, one of [ReasonRemoved], [ReasonEnded] or [ReasonPaused].
type SourceDisconnect struct {
	Version       int    `json:"version"`
	CollectionRef string `json:"collection_ref"`
	Reason        string `json:"reason"`
}
