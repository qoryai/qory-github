# Changelog

Every release of `qory-github`, newest first, in the shape of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The version numbers follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0 a minor release may
change what the program does, and notes it under Upgrading.

## [Unreleased]

### Added

- `qory-github credential -- owner/name[,owner/name...]` reads its settings on standard
  input, as the
  [integration contract](https://github.com/qoryai/integrations/tree/main/contracts/integration/v1#settings)
  defines it: one JSON document and nothing after it but white space, 64 KiB at most.
  It reads standard input to its end, or until it has more than 64 KiB, before it checks
  the argument, reads the key or calls GitHub's API, and refuses empty input; `{}` is a
  document. It reads no setting from its environment.
- The settings may contain the private key itself, `private_key`, in place of
  `private_key_file`, the key kept on disk.
- The description's `private_key` carries `x-secret-name`, `GITHUB_APP_PRIVATE_KEY`: the
  name a control plane suggests for storing the key.
- The description names its `publisher`, `{"name": "Qory", "url": "https://qory.dev"}`,
  which the integration contract requires, and `Description` has it as `Publisher`.
- The description's credential role lists the settings the runner writes to its standard
  input, `"settings": ["app_id", "installation_id", "permissions", "private_key"]`, and
  those it needs, `"required": ["app_id", "private_key"]`, as the integration contract's
  ways define a role; `CredentialRole` has them as `Settings` and `Required`. The private
  key is listed as `private_key`, which the runner writes as `private_key` or
  `private_key_file`. `api_url` is not listed, so a document the runner writes never
  carries it; `credential` still takes it when its standard input does.

### Changed

- `credential` takes no flags, and refuses a flag in one line on standard error with
  nothing on standard output, like every other failure; before, a refused flag printed
  the usage too. `-h` still prints the help.
- Settings that contain both `private_key` and `private_key_file` are refused, before
  the schema is checked, with an error that names the two: a secret has one source.
- The settings schema has no top-level `required` and no `oneOf` over `private_key` and
  `private_key_file`, which the integration contract no longer allows at the top level.
  `ReadSettings` reads the credential role's `required` instead: settings without
  `app_id`, or with neither `private_key` nor `private_key_file`, are refused before the
  schema is checked, the key read or GitHub's API called, with an error that names what
  is missing and the role that requires it, in place of the schema's `missing property`.
- The integration contract is pinned at `github.com/qoryai/integrations`
  `0f167ba9a536`, the commit that defines ways and sources on any forge.
- An empty argument, which a connection without one passes, is refused by the rule for
  repositories, with an error that says it is empty, not as a missing argument.
- An error about settings that are not one JSON document says at which byte the document
  breaks, never the character there.
- The description of `private_key_file` says it is the key kept on disk, no longer the
  way a machine hands the key in.
- An error about settings says where they are wrong as a JSON pointer whose names are
  escaped as JSON pointers escape them, `~` as `~0` and `/` as `~1`, and quotes a name
  the document chose when it contains a control character, a line or paragraph
  separator, a quote or a backslash, so the error stays one line.
- The line a failure writes on standard error escapes every control character but a line
  break, which it writes as a space, and the Unicode line and paragraph separators, as Go
  escapes them, `\r`, `\x7f`, `\u2028`, whatever the error contains, an error message
  from GitHub's API among them: before, a line break alone was replaced.
- `ReadSettings` reads the settings from an `io.Reader`, the program's standard input,
  and takes `private_key`.
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
- `credential -h` says it reads no setting and no secret from its environment, where it
  said it read nothing there: Go's HTTP client takes a proxy from `HTTPS_PROXY` and
  `NO_PROXY`, and on Linux the system's certificates from `SSL_CERT_FILE` and
  `SSL_CERT_DIR`, as before.

### Removed

- `credential --settings <json>`, the settings on the command line.

### Upgrading

- This version needs a `qory` and a runner that start `credential` as
  `qory-github credential -- <argument>` and write the settings document to its standard
  input, `{}` when there are none. An earlier `qory` starts it with `--settings <json>`,
  which `credential` refuses, in any form, `--settings -` and `--settings=-` among them,
  as a flag it does not define: every run that selects the credential then fails.
- Code that uses the package hands `ReadSettings` a reader of the settings document in
  place of the document as a string.
- Settings whose `api_url` is another `https` API, such as one of GitHub Enterprise
  Server, are now refused, and so is `Client.Mint` with such an `API`. Leave `api_url`
  out for GitHub's own.
- `setup --api-url` and `--web-url` with another host, such as one of GitHub Enterprise
  Server, are now refused, and so is `Setup.Start` with such a `Web` or `Client.API`.
  Leave them out for GitHub's own.
- The description follows the integration contract's ways: it has `publisher`, and its
  credential role has `settings` and `required`. A `qory` or another reader of an earlier
  contract refuses both, so this version needs a reader of the contract at
  `github.com/qoryai/integrations` `0f167ba9a536` or later.
- A runner of that contract writes `credential` only the settings its role lists, and
  refuses a connection that carries another, so settings with `api_url` no longer reach
  `credential` through the runner. Leave `api_url` out for GitHub's own.

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
