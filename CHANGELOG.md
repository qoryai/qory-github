# Changelog

Every release of `qory-github`, newest first, in the shape of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The version numbers follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0 a minor release may
change what the program does, and notes it under Upgrading.

## [Unreleased]

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
  break, which it writes as a space, and the Unicode line and paragraph separators, as Go
  escapes them, `\r`, `\x7f`, `\u2028`, whatever the error contains, an error message
  from GitHub's API among them: before, a line break alone was replaced.
- `api_url` takes `https://api.github.com` alone, with or without a trailing `/` or the
  port 443, and for a test `http` or `https` on a loopback host, `127.0.0.0/8`, `[::1]`
  or `localhost`, with any port: the App's own token goes there, and it can mint a token
  for every installation of the App, so it never goes to a host the settings choose.
  Another `https` host, GitHub Enterprise Server among them, a path, a user, a query and
  a fragment are refused, by the settings' schema and again by `Mint` before anything is
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
  with `is greater than 9007199254740991`, where before an error from Go, or for `app_id`
  from `Mint`, said the number. An id written as JSON Schema reads an integer, `42.0` or
  `4.2e1`, is taken as `42`, as the schema takes it: before, such an `installation_id`
  was refused with the number in the error, and such an `app_id` went to GitHub as it
  was written.
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
  compared in any case. Another account's installation, and one GitHub does not know of
  the App, are refused with `installation_id is not the App's installation on the
  repositories' owner; set that owner's installation, or leave installation_id out`.
  Before, a token was minted with whatever installation the settings named.
- No redirect from GitHub's API is followed, whatever `http.Client` a `Client` is handed,
  so the App's token, and the code `setup` exchanges, go nowhere but where they were
  sent. A redirect answering a mint's request, as GitHub answers for a repository that
  moved or was renamed, fails with `GitHub answered with a redirect; the repository may
  have moved or been renamed, so name its new owner/name in the policy's credential
  argument`, and one answering `setup`'s exchange with `exchanging the code for the App:
  GitHub answered with a redirect, which setup never follows, so the code is sent
  nowhere else`. Before, Go's client followed it, and sent the App's token on to a
  target on the same host.
- The program depends on `github.com/qoryai/forager`, formerly `github.com/qoryai/runner`.
- The help, `setup`'s printed declaration and the README name the gateway and
  `~/.config/qory/forager.yaml`, with the integration declared under `gateway:`. Before,
  they said the runner and `runner.yaml`.
- `setup`'s local page, which posts the App's manifest to GitHub with the state
  GitHub's redirect must return, is served at a random path,
  `http://127.0.0.1:<port>/<32 hex digits>`, the URL `setup` opens and prints. A request
  to that address for any other path but the redirect's, `/` among them, is not found;
  one naming another address is refused, as before. Before, the page was at `/`, so any
  process on the machine could read the state from it.

### Upgrading

- Settings whose `api_url` is another `https` API, such as one of GitHub Enterprise
  Server, are now refused, and so is `Client.Mint` with such an `API`. Leave `api_url`
  out for GitHub's own.
- `setup --api-url` and `--web-url` with another host, such as one of GitHub Enterprise
  Server, are now refused, and so is `Setup.Start` with such a `Web` or `Client.API`.
  Leave them out for GitHub's own.

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

[Unreleased]: https://github.com/qoryai/qory-github/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/qoryai/qory-github/releases/tag/v0.1.0
