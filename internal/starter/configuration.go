package starter

import (
	"context"
	jsonv2 "encoding/json/v2"
	"net/http"
	"slices"

	foragercontracts "github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/server"
)

// Configuration is the configuration document Qory Apiary answers the node pool's
// access key with, Forager's configuration.schema.json, checked: signed under the pin,
// with X-Qory-Configuration, of the schema, and with a run endpoint [Apiary.PostOutcome]
// posts to.
type Configuration struct {
	// NodeID is the id of the access key's node, node pool or gateway, node_id, which
	// the document lists for display.
	NodeID string
	// Workspaces are the workspace ids the document lists: one for a node's or a node
	// pool's key, none for a gateway's.
	Workspaces []string
	// RunURL is the run endpoint, run.url: https, or http to a loopback address, with
	// no query, no fragment and no trailing slash, and holding neither qak_ nor qrk_.
	// A run's outcome is posted to it, see [Apiary.PostOutcome].
	RunURL string
}

// Configuration sends the signed GET of <URL>/.well-known/qory-configuration with the
// node pool's access key, X-Qory-Timestamp the clock's second and
// X-Qory-Contract-Version Forager's revision, and returns the configuration document
// Qory Apiary answers, once checked, see [Configuration]. It is fetched anew on every
// call. The answer is a signed 200, read up to server.MaxDocument, that carries
// X-Qory-Configuration, whose body is one JSON document, with valid UTF-8 and no member
// twice, that configuration.schema.json accepts. Its members are read by their exact
// names, and a member the schema does not define is ignored. Its run.url must pass the
// check PostOutcome makes of a run endpoint. An answer without the header, one the
// schema refuses, and one whose run endpoint fails that check are
// [ErrAnswerUnusable]. A refusal is a [*Refusal]: [ErrRateLimited], or a signed 400,
// bad_request or unsupported_contract_version, or 404, which match none of the
// refusals.
func (a *Apiary) Configuration(ctx context.Context) (Configuration, error) {
	const what = "the configuration document"
	ans, err := a.do(ctx, request{
		what: what, kind: kindConfiguration, url: a.URL + server.WellKnown, revision: foragercontracts.Revision,
		foreign: true, get: true, max: server.MaxDocument, timeout: requestTimeout,
	})
	if err != nil {
		return Configuration{}, err
	}
	if ans.status != http.StatusOK {
		return Configuration{}, a.refused(what, kindConfiguration, ans)
	}
	if ans.configuration == "" {
		return Configuration{}, unusable(what, "it carries no X-Qory-Configuration")
	}
	const schema = "configuration.schema.json"
	if err := readAnswer(foragerSchema, schema, ans.body, nil); err != nil {
		return Configuration{}, unusable(what, err.Error())
	}
	var doc server.Configuration
	if err := jsonv2.Unmarshal(ans.body, &doc); err != nil {
		return Configuration{}, unusable(what, "it breaks "+schema)
	}
	if doc.Run == nil {
		return Configuration{}, unusable(what, "it has no run endpoint, run.url")
	}
	if p := runURLProblem(doc.Run.URL); p != "" {
		return Configuration{}, unusable(what, p)
	}
	return Configuration{NodeID: doc.NodeID, Workspaces: slices.Clone(doc.Workspaces), RunURL: doc.Run.URL}, nil
}
