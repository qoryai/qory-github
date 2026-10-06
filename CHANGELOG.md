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

### Changed

- `credential` takes no flags, and refuses a flag in one line on standard error with
  nothing on standard output, like every other failure; before, a refused flag printed
  the usage too. `-h` still prints the help.
- Settings that contain both `private_key` and `private_key_file` are refused, before
  the schema is checked, with an error that names the two: a secret has one source.
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
