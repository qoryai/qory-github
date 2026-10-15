// Package github is Qory's integration with GitHub: what the program qory-github does,
// as a library.
//
// It plays one role, the gateway's credential adapter
// (https://github.com/qoryai/forager/tree/v0.7.0/contracts/forager/v1#credentials): it mints a
// GitHub App installation token for the repositories a run works on, and answers with
// the token, when it expires, and how it is used, the hosts, the schemes and the paths.
// [Mint] does that; [Answer] is the document the gateway reads.
//
// A token is one account's and covers the repositories listed and no other, with the
// permissions requested and no more: that scope, not a path rule, is what bounds a
// request whose body refers to a repository, such as a GraphQL query.
//
// [Describe] is the integration's description, the integration contract
// (https://github.com/qoryai/integrations/tree/v0.3.0/contracts/integration/v1): its name,
// the settings it takes as a JSON Schema, and the roles it plays. [ReadSettings] reads
// a settings document against that schema.
//
// The package keeps nothing. The settings, the App's private key among them, are handed
// to it on every call, by whoever has them, and nothing it is handed is written
// anywhere but [Setup]'s files: the key file, which is the key's first home, and with
// [Setup.PublicURL] the App's client secret file and webhook secret file.
package github
