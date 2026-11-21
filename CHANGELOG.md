# Changelog

Every release of `qory-github`, newest first, in the shape of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The version numbers follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0 a minor release may
change what the program does, and notes it under Upgrading.

## [Unreleased]

### Added

- A run credential call for `work` with access `read` may list several repositories in
  `resources`, all of one connection and one installation. `qory-github-server serve`
  mints one token for them, with `contents`, `metadata` and `pull_requests` `read`, and
  answers one credential with the paths of each repository. A call with access `write`
  still lists one repository. A call fails with `403 resource_not_covered` when a
  repository belongs to another installation, and with `400 invalid_request` when it
  lists a resource twice. The answer has at most 16 items of 1 to 32 paths, so at most
  512 paths together, and a host with more than 32 paths has several items. A `read`
  call adds 4 paths for each repository, and `/graphql` once, so one call covers 127
  repositories; a call for more gets `403 resource_not_covered`, and nothing is minted.
  Before, a call for `work` with other than one resource got `400 invalid_request`.
- A run credential call for a harness with more than 16 repositories now answers in
  several items of at most 32 paths. Before, it answered one item with all paths, which
  was more than Forager takes in one item.
- `qory-github-server serve` opens or updates the pull request for each `change_request`
  entry of the kind `pull-request` in Qory Apiary's change feed, in Go, over GitHub's REST
  API, with an installation token of the App for that one repository with
  `pull_requests: write` and no other permission. An entry has one target, so a change
  request for two repositories is two entries. The adapter finds the repository by the
  target's `collection`, the repository's id, so a renamed repository still gets its pull
  request; the address of the target is checked for the host and for the shape
  `owner/name` and is not what finds the repository. For each entry it sends Qory Apiary
  one reply with the address of the base commit and of each commit in `data`, the pull
  request's `address` (its `url`, and its number as `ref`), the action `created`,
  `updated` or `kept`, and in `data` the pull request's number, title and state. It
  updates the pull request at the entry's `previous.address` when the `ref` there is a
  pull request number from the entry's branch, and otherwise finds the pull request by its
  head branch and repository, and never by its base branch. Found by the branch, only an
  open pull request counts, so an entry with no `previous.address`, or with one that is
  unusable or gone, gets a new pull request, with the action `created`, when the branch
  has only closed or merged ones. It opens a pull request when it finds none, as a draft
  when `draft` is `true`, and changes only the text between the lines
  `<!-- qory:start -->` and `<!-- qory:end -->` of the description, and the title only
  while it equals `previous.title`. It never changes whether a pull request is a draft,
  and does not change a closed or merged pull request. The adapter reads the members of
  the `pull-request` artifact type (its schema in the Qory harness is the source):
  `branch`, `base_branch`, `head`, `base`, `commits`, `steps`, `earlier_commits` and
  `draft`, and checks each: a branch name that git accepts and that is one line, a full
  commit id as the address path of each commit and a collection of one line of 1 to 200
  characters, at least 1 commit and no limit from the adapter on their number (the
  contract limits an array in `data` to 1024 items, so the reply has at most 1024 commit
  addresses), a list of steps, each with a `step` of 1 to 128 characters on one line,
  `earlier_commits` as a whole number from 1, and `draft` as `true` or `false`; data that
  breaks a rule is reported as `refused`, with the code point of a stopped character in
  the `detail`. A title that has a control character, U+2028, U+2029 or a format character
  other than U+200C and U+200D, or no character that is not a space, U+200C or U+200D, is
  reported as `refused` before any request to GitHub, with a `detail` that starts with the
  fix; so is a `text` that has a line that is `<!-- qory:start -->` or
  `<!-- qory:end -->`, since the adapter writes the text between those lines. The same
  rule for characters applies to the failure `detail`, the account title of a grant and
  the author name of a comment. An entry of another `change_kind` is reported as
  `refused`, with a `detail` that starts with the fix. An entry that GitHub refuses for
  good is reported to Qory Apiary with the reason `not_permitted`, `target_gone`,
  `too_long` or `refused`, and a `detail` with the fix and GitHub's status and message;
  one that still fails when the retries end, after a day, is reported with the reason of
  the last error of its tries: `unreachable` for a failure to reach GitHub, a rate limit,
  a 408 or a 5xx, and the reason of the refusal for an answer such as a 404 or a 401 that
  kept coming. A 404, 410, 301 or 308 on the read of the repository by its id is
  `target_gone`, with the fix to check that the repository exists and the App's
  installation reaches it. A 301 or 308 on the lookup of the installation or on a pull
  request call is `target_gone` too, with the fix to link the repository by its
  new name; a 302, 307, 404 or 403 on the lookup stays `not_permitted`. The App needs the
  permission Pull requests: read and write. The title in the reply has none of the
  characters that the title rule stops.
- The description of the adapter lists the change kind `pull-request` in
  `roles.source.change_kinds`.
- The harness module `modules/github`, with the program `bin/open-draft`, declared as the
  module's `submit_program`. It is a POSIX `sh` script that uses `gh`. qory runs it on
  your machine, outside the sandbox that a run uses, once for each repository of a run
  that has no run code, after it pushed the branch. A run that has a run code runs no
  program: `qory-github-server serve` opens its draft pull request from the change feed.
  The program prints the GitHub address of each commit and, for a run with hand-off text,
  opens the draft pull request from `QORY_SUBMIT_BRANCH` or edits the one that exists,
  with the login of `gh`. The title it prints has none of the characters that the contract
  refuses; when nothing is left, it prints `QORY_SUBMIT_TITLE`, cleaned the same way. It
  finds the open pull request by its head branch and repository alone, and of several it
  takes the highest number, as the adapter does when it looks up by branch. When the
  branch has only closed or merged pull requests, it opens a new draft and never reuses
  them, since the program has no address to keep. It replaces only the text between the
  lines `<!-- qory:start -->` and `<!-- qory:end -->` of the description and keeps the
  title. It prints the result as lines (`draft_number`, `draft_url`,
  `draft_title`, `draft_state`, `draft_action`, `commit_url`). Exit 1 means a call to `gh`
  failed or did not finish within 110 seconds, exit 2 an input it cannot use, and exit 3 a
  missing login of `gh`, with ``Run `gh auth login`, then `qory run` again.`` as the first
  line on standard error. The program pushes nothing.
- The set-up pages of `qory-github-server serve`, where an instance admin creates the
  GitHub App, have Qory Apiary's set-up look: its header, the heading Set up the GitHub
  App, and the steps Start, On GitHub and Done. Start has the form. The page that opens
  GitHub lists what to do on GitHub's page. Done shows who can install the App and what
  to do next in Qory Apiary. The pages embed their stylesheet and the Geist font, and
  load nothing from another host.
- Start has the field App name. When the set-up pass has `organisation_slug`, the field
  starts with `qory-` and the slug in GitHub's shape, at most 34 characters, such as
  `qory-acme-org`; without it, the field starts empty. You can change the name on Start
  or on GitHub's page. A name of more than 34 characters, or with a control character,
  is refused before GitHub opens. With the field empty, the App's manifest has no name,
  and you name the App on GitHub's page.
- A set-up pass may have the member `organisation_slug`, the slug of the Qory Apiary
  organisation, signed with the other members: 1 to 40 lower-case letters, digits and
  hyphens, with no hyphen at either end. A pass with a slug of another shape, or with
  any other member the contract does not define, is refused as a link that is not
  valid.
- The App's bot posts on the issue, once, each comment a person writes in Qory Apiary
  when they take in the issue. The comment's first line is
  `<name> wrote in Qory Apiary:` and ends with the marker
  `<!-- qory:comment <comment_id> -->`, which GitHub does not show, even when the
  person's text leaves a code block open. The adapter sends the posted comment back to
  Qory Apiary with its `comment_id`. For a comment that the adapter cannot post, it
  sends Qory Apiary a failure report with the reason `item_gone`, `not_permitted`,
  `too_long`, or `unreachable`. The description has `comments: true` in
  `roles.source`.
- The name in the first line shows as plain text. The adapter puts a backslash before
  each Markdown character, a zero-width space after each `@`, `#`, `:`, `-`, `.`, `_`,
  `+`, and `/`, and a zero-width space after every sixth digit of a run of more than six
  hex digits, so GitHub makes no mention, issue link such as `GH-123`, emoji, web link
  such as `www.example.com`, or commit link from the name. A repository's autolink whose
  prefix ends in a letter or a digit, such as `TICKET123`, is still a link.
- The adapter reports a comment as `unreachable` at once when GitHub returns 400 for
  it, or 422 for any cause other than a body too long, or when the issue has more than
  100 pages of comments. If the failure report still fails two days after the
  comment's first failure, the adapter logs one line with the `comment_id` and moves
  past the comment.
- Qory Apiary writes a change feed entry of kind `watch` when a run stores a
  change request version. The adapter drops each `watch` entry, which changes nothing. The
  adapter moves its cursor past the entry and applies the entries after it.

### Changed

- The page that the setup shows when the connection is linked to another installation of
  the App has this text: "Disconnect the account that is connected now, on the
  integration's page in Qory Apiary, then click Install again. An organisation connects
  one GitHub account." Before, the text was: "This connection already holds another
  installation of the App, and it holds only one."
- The run credential for work with access `write` reaches only git's push: on
  `github.com`, `/owner/name.git/info/refs` and `/owner/name.git/git-receive-pack`. It
  has no item for `api.github.com`, so it reaches no REST path and not `/graphql`. Before,
  it reached every path of the repository on both hosts and `/graphql`. A call to another
  path, such as `/owner/name.git/git-upload-pack`, `/repos/owner/name/pulls` or
  `/graphql`, gets no token under it. A query string is not part of a path, so
  `/owner/name.git/info/refs` is covered for both services, `git-receive-pack` and
  `git-upload-pack`. The token minted for it has the permission `contents: write` alone;
  before, it also had `pull_requests: write`. The run credential for work with access
  `read` and the one for a harness are unchanged, and so are the App's permissions.
- The adapter applies the entries of Qory Apiary's change feed that come after a failing
  entry while it retries that entry. The adapter applies an entry for the same issue
  only after it. A collection entry and the entries of its repository apply in the
  feed's order. A grant entry applies only after every entry before it, and every later
  entry but a sync entry applies only after the grant entry. Sync entries apply in the
  feed's order. Before, every later entry waited until the failing entry passed: up to a
  day, or two days for a comment whose failure report also failed. A time in which 2 or
  more entries fail and none applies, as in an outage of GitHub, does not count toward
  that day, and the adapter stops retrying a failing entry at most 2 days after its
  first failure, not counting the time the feed cannot be read, or 3 days for a comment
  whose failure report also fails. The line logged for an entry passed has
  `retries_ended`, the limit that ended its retries.
- On the set-up pages, the optional field GitHub organisation replaces the field for the
  GitHub account. With an organisation, GitHub creates the App under it; with the field
  empty, under the GitHub user signed in on github.com. A login of a GitHub user, which
  the account field took, is refused with a line that ends "Leave the field empty to
  create the App under your account." The choice of who can install the App stays, with
  private selected first.
- Connect sends you to GitHub's page to install the App first. GitHub asks you to
  authorise the App once, after Install, and the GitHub adapter then checks that you
  administer the account you installed it on. The page that told you to press Save for
  an App installed already is gone: GitHub shows the installation's settings, and Save
  sends you back.
- The refusal pages of the set-up and of Connect are HTML in the set-up look. The
  set-up's refusal lines contain "set-up link" and "the GitHub adapter".
- The description's set-up guide and help have these steps: sign in on github.com
  first, as an owner of the GitHub organisation or as the user who will own the App,
  then check the name and create the App on GitHub.
- The description lists `egress_hosts`, the hosts a run of the integration reaches:
  `github.com` and `api.github.com`, the hosts of the credential role.
  `qory-github describe` prints them, and `description.json` lists them. The policy that
  `setup` prints takes its hosts from them and allows the same two hosts as before.
- The GitHub adapter's description has `targets: true` in `roles.source`, so Qory
  Apiary offers the repositories the GitHub App is installed on as places where a
  run's changes go.
- `setup` gives the exchange of GitHub's code for the App 30 seconds from the moment you
  approve the App. Before, the exchange had only what was left of the ten-minute wait,
  so an approval near the end of the wait could fail the exchange.
- `setup` escapes the code it exchanges for the App in the request's path. When an error
  from GitHub's API quotes the code, the error shows `[the code]` in its place.
- Building `qory-github` from source needs Go 1.27.4, up from 1.27.1: the integrations
  and Forager modules it builds against require Go 1.27.3, and Go 1.27.4 fixes
  GO-2026-6859 in the standard library. The image builds with Go 1.27.4.
- A repository is a collection with a `ref`, and its target is that `ref` with an
  optional address. `qory-github-server serve` sends each collection and each issue with
  `target` as `{"collection": "<ref>", "address": {"system": "github.com", "path":
  "owner/name"}}`. Before, `target` was `{"system": "github.com", "path": "owner/name"}`
  and had no `collection`. The `ref` is the repository's id, as before, so a rename or a
  transfer changes the `path` and keeps the `ref`. A path of 201 to 256 characters is now
  skipped, with its collection or item, as the contract allows at most 200. An empty path
  is skipped as before.
- `qory-github-server serve` reads the change feed as a reader that may be older than
  the writer. It skips an entry of a kind it does not apply, and an entry whose
  `must_understand` lists a pointer that it does not define or is not a list, and moves
  its cursor past the entry; it logs one line for each. It ignores a member of the
  feed's answer, of an entry, of `target` and of `previous` that the schemas do not
  define. A `previous` with only such members reads as empty, so an entry with
  `previous` of `{"zz": 1}` opens a new draft. Until this change, the adapter refused
  the whole answer for such a member, and an entry of an unknown kind stopped the feed.
  The calls to the adapter that the schemas check (`resolve`, `read`, `read-public` and
  the run credential) ignore such a member too. A `change_request` entry whose
  `must_understand` lists a pointer that the adapter does not define, or is not a list,
  is reported as `refused`, with a `detail` that starts with the fix. A pointer below
  `data` is defined when it points to a member of the `pull-request` data: `target`,
  `title`, `text`, `branch`, `base_branch`, `head`, `base` and each of `commits` with
  their `collection` and `address`, `steps` with `commit` and `step` for each,
  `earlier_commits`, and `draft`. An entry with a status of its kind that the adapter
  does not know still stops its answer.
- `qory-github-server serve` matches the name of a member of a document from Qory Apiary
  in exact case: the change feed and its entries, the calls to the adapter, the data of
  a change request, the connect and setup passes, the answers to the grants and to the
  secrets request, the secrets that it seals and the body of a refusal. Until this
  change, `Token` beside `token` could replace it, and a `Must_Understand` could replace
  the `must_understand` list that the document has. `Token` alone now counts as a member
  that the adapter does not define. A member that appears twice in an object, at any
  depth, stops the reading of the document, with the same value or another: a page of
  the feed stops and is read again after the feed's backoff, with its cursor where it
  was; a call is answered as a call that is not valid; a refusal has no code, so its
  status decides; and a pass, an answer or the data of a change request is not read.
  Until this change, the feed, the connect and setup passes, the answers to the grants
  and to the secrets request, the body of a refusal and the data of a change request kept
  the last value; a call was already answered as a call that is not valid.
- `qory-github-server serve` ignores a member that it does not define in the connect
  pass, the setup pass, the answer to the grants, the answer to the secrets request and
  the secrets that it seals. It does not read such a document when its `must_understand`
  lists a pointer to a member that the adapter does not define, or is malformed, and the
  reason in the log starts with the fix. It does not read a document that has data after
  the JSON object, as before, or anything before the opening brace, such as a space or a
  byte order mark. Until this change, the adapter did not read a document with any
  member that it does not define. The body of a refusal that Qory Apiary sends is read
  the same way: when the adapter does not read it, the answer has no refusal code. A 409
  `connection_ended` that the adapter reads ends the connection; a 409 or a 403 without
  a code does not. The grant report is sent again after every answer that is not final:
  a 409 `pass_unknown`, a 403 `connection_unknown`, a 409 `connection_suspended`, a 403
  or a 409 without a code, and a failure that can pass, such as an outage, a timeout or
  a 429. The waits double from 2 to 60 seconds, also while the connection is suspended,
  until the connect return expires, 300 seconds after the connect; nothing changes until
  then. When the connect return expires, the adapter stops the report and drops the
  installation's link and the records of its repositories, unless Qory Apiary's copy of
  the grants contains the grant, and the person connects again. The grant end and the
  first listing are sent again after a wait, with a backoff, on a 409 or a 403 without a
  code or a 409 `connection_suspended`, and nothing changes. A disconnect, an item or a
  comment that gets a 409 or a 403 without a code is sent again by the worker, with its
  backoff, or by the next pull round; on a 409 `connection_suspended` it keeps the
  repository's records and the next pull round sends it. A 403 without a code never
  counts toward the end of a connection. A 403 with a code, and a 400 or 413, are
  handled as before. Until this change, a 409 or a 403 without a code was a refusal for
  good, so a disconnect that met one dropped the repository's records, and a grant
  report or a first listing that met one gave up at once. The stored App entry, which
  `qory-github-server` writes, stays strict.

### Upgrading

- Deploy this `qory-github-server` together with, or before, a Qory Apiary that sends
  `organisation_slug` in its set-up pass. An earlier `qory-github-server` refuses such a
  pass as a link that is not valid.

## [0.2.1] - 2026-10-24

### Added

- The release has `description.json`, the description `qory-github describe` prints,
  and `checksums.txt` lists its SHA-256, so Qory Apiary can add the integration from
  the release. The program is unchanged.

## [0.2.0] - 2026-10-12

### Changed

- An error about settings that are not one JSON document says at which byte the document
  breaks, or that it is empty, ends too soon or has something other than white space
  after it, and never the character there.
- The description of `private_key_file` says it is the one way to hand the key in on a
  command line, no longer the way a machine hands it in.
- An error about settings quotes a name the document chose, such as a permission's, where
  it says where the settings are wrong, when the name contains a control character, a
  line or paragraph separator, a quote or a backslash, so the error stays one line.
- The line a failure writes on standard error escapes every control character but a line
  break, which it writes as a space, the Unicode line and paragraph separators, and the
  bidirectional formatting characters, U+202A to U+202E, U+2066 to U+2069, U+200E,
  U+200F and U+061C, which reorder what a terminal shows, as Go escapes them, `\r`,
  `\x7f`, `\u2028`, `\u202e`, whatever the error contains, an error message from
  GitHub's API among them: before, a line break alone was replaced.
- `api_url` takes `https://api.github.com` alone, with or without a trailing `/` or the
  port 443, and for a test `http` or `https` on a loopback host, `127.0.0.0/8`, `[::1]`
  or `localhost`, with any port: the App's token goes there, and it can mint a token for
  every installation of the App, so it never goes to a host the settings choose. Another
  `https` host, GitHub Enterprise Server among them, a path, a user, a query and a
  fragment are refused, by the settings' schema and again by `Mint` before anything is
  sent, with an error that names the rule and never the URL.
- `setup` holds `--api-url` to the same rule, since the code it exchanges there for the
  App yields the App's private key, and `--web-url` to `https://github.com` alone, with
  or without a trailing `/`, and for a test `http` or `https` on a loopback host, with
  any port: the browser posts the manifest there. Each is refused in one line, naming
  the rule and never the URL, before `setup` creates a directory, listens or opens the
  browser. Every request to the API, a mint's and `setup`'s, is held to the rule.
- A program built without `-X main.version`, by `go install ...@v0.1.0` among others,
  reports its module's version without its leading `v` as `program_version`, `0.1.0`
  in place of `v0.1.0`, and a pseudo-version such as
  `v0.2.1-0.20261006195344-0f167ba9a536` as `0.2.1-0.20261006195344-0f167ba9a536`: the
  integration contract's release version is the tag without its `v`, and a reader
  compares `program_version` with the version it asked for. Only a `v` followed by a
  digit is dropped. The version set with `-X main.version` is reported as it is given,
  and a build whose module version is `(devel)` or empty is still `dev`.
- `credential -h` says it reads no setting and no secret from its environment. Go's
  HTTP client takes a proxy from `HTTPS_PROXY` and `NO_PROXY`, and on Linux the
  system's certificates from `SSL_CERT_FILE` and `SSL_CERT_DIR`, as before.
- An error about settings never says a value: a number below or above its bound, a
  string's length and a number of permissions are no longer in it, where before
  `/installation_id: minimum: got -42, want 1` said the number. The error says the
  bound: `/installation_id: is less than 1`,
  `/private_key_file: is shorter than 1 character`,
  `/permissions: has fewer than 1 property`. A name the document chose may still appear,
  escaped, where it is the location or the property refused.
- `app_id` as a number, and `installation_id`, are at most 9007199254740991, 2^53 - 1,
  the largest integer every JSON reader holds exactly, so the settings refuse a larger id
  with `is greater than 9007199254740991`. Before, a larger `installation_id` up to
  9223372036854775807, 2^63 - 1, and a numeric `app_id` of up to 64 digits were taken
  without an error and sent to GitHub; a larger `installation_id` was refused by Go's
  JSON decoder, and an `app_id` of more than 64 digits by `Mint`, with the number in the
  error. An id written as JSON Schema reads an integer, `42.0` or `4.2e1`, is taken as
  `42`, as the schema takes it: before, such an `installation_id` was refused with the
  number in the error, and such an `app_id` went to GitHub as it was written.
- `Mint` refuses an App id that is not one, and a permission that is neither `read` nor
  `write`, without saying the id or the level.
- An error from a request to GitHub's API names the request, `minting the installation
  token`, `finding the App's installation on acme/shop` or
  `exchanging the code for the App`, and never says what was sent. When the API cannot
  be reached it says `GitHub's API could not be reached` and why, which may name the
  host and port, never the URL nor the path: before, the method, the path and the URL
  were in it, so `setup` wrote the one-time code it exchanges for the App's private key,
  twice, and `credential` the installation's id.
- An `installation_id` the settings set is checked before a token is minted: GitHub must
  say it is the App's installation on the account that owns the repositories, its login
  compared in ASCII case alone: a login with any other character is refused, so the
  Kelvin sign, U+212A, is never taken for a k. Another account's
  installation, and one GitHub does not know of the App, are refused with
  `installation_id is not the App's installation on the repositories' owner; set that
  owner's installation, or leave installation_id out`. Before, a token was requested
  with whatever installation the settings named.
- No redirect from GitHub's API is followed, whatever `http.Client` a `Client` is handed,
  so the App's token, and the code `setup` exchanges, go nowhere but where they were
  sent. A redirect answering the lookup of a repository's installation, as GitHub
  answers for a repository that moved or was renamed, fails with `GitHub answered with
  a redirect; the repository may have moved or been renamed, so name its new owner/name
  in the policy's credential argument`; one answering the check of `installation_id`
  with `checking installation_id: GitHub answered with a redirect, which is never
  followed`; one answering the mint with `minting the installation token: GitHub
  answered with a redirect, which is never followed`; and one answering `setup`'s
  exchange with `exchanging the code for the App: GitHub answered with a redirect, which
  setup never follows, so the code is sent nowhere else`. Before, Go's client followed
  it, and sent the App's token on to a target on the same host.
- The module and its tests depend on `github.com/qoryai/forager`, formerly
  `github.com/qoryai/runner`; the program imports no package of Forager or of
  `github.com/qoryai/integrations`. `go.mod` requires `github.com/qoryai/forager` v0.7.0,
  in place of `github.com/qoryai/runner` v0.6.0, and `github.com/qoryai/integrations`
  v0.3.0, in place of v0.2.0. The tests check the credential answer and the description
  against their contracts at those tags.
- The help, `setup`'s printed declaration and the README name the gateway and
  `~/.config/qory/forager.yaml`, with the integration declared under `gateway:`. Before,
  they said the runner and `runner.yaml`.
- `setup`'s local page, which posts the App's manifest to GitHub with the state
  GitHub's redirect must return, is served at a random path,
  `http://127.0.0.1:<port>/<32 hex digits>`, the URL `setup` opens and prints. A request
  to that address for any other path but the redirect's, `/` among them, is not found;
  one naming another address is refused, as before. Before, the page was at `/`, so any
  process on the machine could read the state from it.
- `setup` syncs the private key file to disk before it closes it, and then, where the
  system can, the directory it is in, so the key GitHub hands out once is on disk when
  `setup` says where it is. A file whose sync fails, `the key file could not be synced
  to disk: ...`, is removed, and the key goes beside it, as for a file that cannot be
  written. `setup` then prints that the file `could not be written or synced`. On a
  filesystem that cannot sync a file, the file is kept as it is written. Before, the
  file was closed without a sync.
- The description of `permissions` and the README say that `workflows` `write` lets a
  run change the repositories' workflows, which run with their Actions secrets, so it is
  for runs that must edit workflows alone. A run may still be granted it: GitHub refuses
  a push that touches `.github/workflows/` without it. They also say that an App
  `setup` creates lacks it until its owner adds it on GitHub.
- Two texts say plainly what they mean; what the program does is unchanged. `setup`'s
  loopback listener answers a request that names another address with `qory-github
  answers only requests to 127.0.0.1:<port>`, and the description of `api_url` begins
  `GitHub's API, where qory-github sends the App's token`.
- A private key file that grants group or others any permission is refused with `the
  private key file <path> is <mode>: group or others have permissions on it; make it
  0600`. Before, the error said others may read it, even where only the group had a
  permission, or only to write or run the file.

### Upgrading

- Settings whose `api_url` is another `https` API, such as one of GitHub Enterprise
  Server, are now refused, and so is `Client.Mint` with such an `API`. Leave `api_url`
  out to use `https://api.github.com`.
- `setup --api-url` and `--web-url` with another host, such as one of GitHub Enterprise
  Server, are now refused, and so is `Setup.Start` with such a `Web` or `Client.API`.
  Leave them out to use `https://github.com` and `https://api.github.com`.
- An `installation_id` that is not the App's installation on the account that owns the
  repositories is now refused before a token is requested; before, a token was requested
  with it. Set that owner's installation, or leave `installation_id` out to have it
  looked up from the repositories.
- With `installation_id` left out, a repository named by a former owner/name, which
  GitHub answers with a redirect, now fails with `GitHub answered with a redirect; the
  repository may have moved or been renamed, so name its new owner/name in the policy's
  credential argument`; before, the redirect was followed. Name its current owner/name
  in the policy's credential argument.
- A program built without `-X main.version`, by `go install ...@v0.2.0` among others,
  now reports `program_version` without its leading `v`, `0.2.0` in place of
  `v0.2.0`. Compare it with a tag without the tag's `v`.

## [0.1.0] - 2026-09-30

### Added

- `qory-github`, the runner's credential adapter for GitHub. `qory-github credential
  --settings <json> -- owner/name[,owner/name...]` mints a GitHub App installation token
  for one owner's repositories and prints the runner's credential document: basic with
  `x-access-token` on `github.com` for git over HTTPS under `/owner/name` and
  `/owner/name.git`, bearer on `api.github.com` for `/repos/owner/name` and `/graphql`,
  and the placeholders `GH_TOKEN` and `GITHUB_TOKEN`. The token goes to those paths
  alone, and under the runner's `enforce` they are the run's whole reach on the two
  hosts; under `observe` the runner sends a request to any other path there on without
  the token and records it. The installation is looked up from the repositories unless
  the settings contain it.
- A run's token gets the permissions the settings allow, `read` or `write`, of
  `actions`, `checks`, `contents`, `deployments`, `issues`, `metadata`, `pages`,
  `pull_requests`, `statuses` and `workflows`, and no other: `administration`,
  `secrets`, `environments`, every `organization_*` permission and `members` are
  refused by the settings schema and again when the token is minted, and so is an
  empty `permissions`, which GitHub reads as every permission the installation has.
  Absent, it is contents and pull requests `write`.
- Settings the schema refuses are refused, and so is the private key itself on the
  command line, and an `http` API unless its host is loopback, since over `http` the
  token crosses the network in the clear. The private key file is opened once and
  refused when it is a symbolic link; it is also refused unless it is a regular file of
  the user the program runs as that group and others may not read.
- `qory-github setup`, which creates the App with GitHub's manifest flow, a person
  approving it in the browser, and writes its private key to a file only its owner
  reads, only where no file exists yet; when that file cannot be written, beside it, and
  when that fails too, its error identifies the App and the page where you generate
  another key. Its loopback listener answers a request for its own address alone. It
  refuses a key file's path that is not UTF-8 or that contains a control character. It
  prints the `integrations` declaration `qory` reads, and a policy that allows GitHub's
  hosts and selects the credential the declaration expands into.
- `qory-github describe`, the integration's description under the
  [integration contract](https://github.com/qoryai/integrations/tree/main/contracts/integration/v1),
  the domain `software`, the private key marked `writeOnly`. Its `program_version` is the
  version set with `-ldflags "-X main.version=..."`, which a release sets to its own, or
  else the module's version Go records in the build, `v0.1.0` for `go install ...@v0.1.0`
  or the pseudo-version of a commit, or else `dev`.
- Each command prints a short help with examples and a link to its section of the
  README, and `qory-github` alone lists the commands. `-h` prints the help and exits 2; a
  flag a command refuses prints its usage and flags before the error line.
- Releases for Linux and macOS, amd64 and arm64, published by the workflow every
  integration calls, as `qory-github_<version>_<os>_<arch>.tar.gz` with `checksums.txt`.

### Moved

- `qory-github` has a repository of its own, moved from `github/` of
  [qoryai/integrations](https://github.com/qoryai/integrations), which keeps the
  integration contract. Its module is `github.com/qoryai/qory-github`, and
  `go install github.com/qoryai/qory-github/cmd/qory-github@latest` installs it. The App
  `setup` creates links to this repository.

[Unreleased]: https://github.com/qoryai/qory-github/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/qoryai/qory-github/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/qoryai/qory-github/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/qoryai/qory-github/releases/tag/v0.1.0
