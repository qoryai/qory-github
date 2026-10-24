package github

// The requests Qory Apiary takes from a work source's adapter, the generic wire, are the
// integrations contract's Go types, package github.com/qoryai/integrations/contracts.
// Their field names and values carry no GitHub word: GitHub's names are only inside the
// opaque values, a ref, a URL, a path. Below are the values of their fields the adapter
// writes.
//
// Every time is RFC 3339 in UTC with whole seconds, contracts.TimeLayout.

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
