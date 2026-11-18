# Qory GitHub Integration

This repository is part of [Qory](https://github.com/qoryai/qory). Its README lists every part and how to install Qory.

`qory-github` gives a Qory run a GitHub token for the repositories the run works on,
without the agent ever holding the token.

`qory-github` is a credential adapter for [Forager](https://github.com/qoryai/forager)'s gateway.
For each run it mints a
[GitHub App installation token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
limited to the run's repositories and to the permissions you allow. The gateway keeps the
token outside the agent's container and adds it to the agent's requests to GitHub. Inside
the container, `GH_TOKEN` and `GITHUB_TOKEN` hold a placeholder, so `git` and `gh` work.

## Quick start

### 1. Install

On the machine that runs `qory run`, on its `PATH`. Download
`qory-github_<version>_<os>_<arch>.tar.gz` from
[Releases](https://github.com/qoryai/qory-github/releases) (Linux and macOS, amd64 and
arm64) and verify it against `checksums.txt`, or:

```sh
go install github.com/qoryai/qory-github/cmd/qory-github@latest
```

### 2. Create the GitHub App

```sh
qory-github setup                 # under your account
qory-github setup --org acme      # under an organisation
```

Your browser opens with the App filled in. Approve it. `setup` writes the App's private
key to `~/.config/qory/github-app.pem` (mode 0600) and prints the next steps.

### 3. Install the App

Install it on the repositories your agents work on, at the URL `setup` prints.

### 4. Declare the integration

In `~/.config/qory/forager.yaml`. `setup` prints this block with your App's id and key
file:

```yaml
gateway:
  integrations:
    github:
      settings: {"app_id":123456,"private_key_file":"/home/dev/.config/qory/github-app.pem"}
```

### 5. Select it in a run's policy

List the repositories the run works on, one owner's. Add the other hosts the run needs,
such as the model's API, to `allow`:

```yaml
egress:
  mode: enforce
  allow: [github.com, api.github.com]
credentials:
  - {name: github, argument: acme/shop}
```

## Commands

`qory-github` alone lists the commands; `qory-github <command> -h` prints a command's help.

### setup

```sh
qory-github setup [--org ORG] [--name NAME] [--key-file FILE]
```

Creates the GitHub App (private, no webhook, contents and pull requests `write`, metadata
`read`) and writes its private key. Waits up to ten minutes for your approval.

| Flag | Default |
|---|---|
| `--org` | your account |
| `--name` | `qory-github-` and six random hex digits; must be unique on GitHub |
| `--key-file` | `~/.config/qory/github-app.pem` |
| `--api-url` | `https://api.github.com`; otherwise only a loopback host, for tests |
| `--web-url` | `https://github.com`; otherwise only a loopback host, for tests |

- The key file is written with mode 0600, and synced to disk before `setup` says where
  it is, on a filesystem that can sync a file. An existing file is never overwritten.
- GitHub hands out the key once. If the file cannot be written or synced to disk, the key
  goes to `<file>.<random hex>` and `setup` prints where. If that fails too, the error
  names the App and the page where you generate a new key.
- The key is never printed.
- The page `setup` opens, which posts the App's manifest to GitHub, is served on
  loopback at a random path, `http://127.0.0.1:<port>/<32 hex digits>`, the URL `setup`
  prints. A request to that address for any other path but GitHub's redirect back is
  not found, and one naming another address is refused, so a process on the machine
  that does not know the URL cannot read the page's state.
- `--api-url` takes `https://api.github.com` alone, with or without a trailing `/` or
  `:443`, and `--web-url` takes `https://github.com` alone, with or without a trailing
  `/`. For tests, each also takes `http` or `https` on a loopback host (`127.0.0.0/8`,
  `[::1]`, `localhost`) with any port. Anything else is refused before `setup` creates,
  listens on or opens anything. GitHub Enterprise Server is not supported.

### credential

```sh
qory-github credential --settings JSON -- owner/name[,owner/name...]
```

The gateway calls this for each run; you normally don't. It mints a token for the listed
repositories, all of one owner, and prints the gateway's credential document: the token,
`expires_at`, the hosts and paths it applies to, and the placeholders `GH_TOKEN` and
`GITHUB_TOKEN`. Each call mints a new token; nothing is kept.

### describe

```sh
qory-github describe
```

Prints the integration's description: the settings as a JSON Schema and the credential
role. `qory` calls it to check a declaration. No settings, no network.

### Exit status

- `0`: success. `describe` and `credential` print one JSON document on standard output.
- `1`: failure, a flag a command refuses among them. One line on standard error says
  what failed, never the token or the key. `credential` and `setup` print the flag
  parser's message and their usage before that line when they refuse a flag.
- `2`: no command, an unknown one, or `-h`. Usage or help on standard error.

## Settings

Passed as one JSON document in `--settings`, or under `settings:` in `forager.yaml`.

| Setting | Required | Meaning |
|---|---|---|
| `app_id` | yes | The App's numeric id, or its client id as a string |
| `private_key_file` | yes | Path to the App's private key. Must be a regular file owned by the user running the program, with no permission for group or others, and not a symbolic link. |
| `installation_id` | no | The App's installation on the repositories' owner. Checked with GitHub before a token is minted: an installation on another account is refused. Looked up from the repositories when absent. |
| `permissions` | no | Permissions for the token, each `read` or `write`. Default: `{"contents": "write", "pull_requests": "write"}` |
| `api_url` | no | GitHub's API, where qory-github sends the App's token, which can mint a token for any installation of the App. Only `https://api.github.com`, the default, with or without a trailing `/` or `:443`, or for tests `http` or `https` on a loopback host (`127.0.0.0/8`, `[::1]`, `localhost`), any port. No other host, path, user, query or fragment. GitHub Enterprise Server is not supported. |

The private key itself (`private_key`) is refused on the command line; use
`private_key_file`. No setting is read from the environment.

`app_id` as a number, and `installation_id`, are integers from 1 to 9007199254740991,
2^53 - 1, the largest integer every JSON reader holds exactly. An integer is read as JSON
Schema reads it, whatever its notation: `42.0` and `4.2e1` are `42`.

## Permissions

A token can get these permissions, `read` or `write`: `actions`, `checks`, `contents`,
`deployments`, `issues`, `metadata`, `pages`, `pull_requests`, `statuses`, `workflows`.

`workflows: write` lets a run change the repositories' workflows, which run with their
Actions secrets, so grant it only to runs that must edit workflows; GitHub refuses a push
that touches `.github/workflows/` without it. An App that `qory-github setup` creates is
granted contents, pull requests and metadata alone, so a token with `workflows: write`
cannot be minted until the App's owner adds the Workflows permission on GitHub.

Refused: `administration`, `secrets`, `environments`, `repository_hooks`, every
`organization_*` permission, `members`, the level `admin`, and an empty `permissions`
(GitHub reads it as "all").

A token never gets more than the App has. The App `setup` creates has contents and pull
requests `write` and metadata `read`. For more, for example `issues`, change the App's
permissions on GitHub and accept the change on the installation.

## What the token reaches

This section describes the token that the command `qory-github credential` returns. For
the token of a Qory Apiary run, see
[The token of a Qory Apiary run](#the-token-of-a-qory-apiary-run).

| Host | Auth | Paths, per repository |
|---|---|---|
| `github.com` | basic, username `x-access-token` | `/owner/name.git/*`, `/owner/name/*` (clone, fetch, push, Git LFS batch) |
| `api.github.com` | bearer | `/repos/owner/name`, `/repos/owner/name/*`, `/graphql` |

- Under `enforce`, these paths are the run's only access to the two hosts. Every other
  path, for example `/user`, `/search` or another repository, is refused before the
  request leaves the machine. Under `observe`, such a request goes out without the token
  and is recorded.
- `/graphql` has no repository in its path. The token limits it: GitHub answers only for
  the repositories the token covers.
- To allow fetch but not push, use `"permissions": {"contents": "read"}`, or limit the
  host to the fetch paths in the policy
  ([Forager contract](https://github.com/qoryai/forager/tree/v0.7.0/contracts/forager/v1#the-policy)).

### The token of a Qory Apiary run

The table in What the token reaches lists the paths of the token that
`qory-github credential` returns. The run credential that `qory-github-server` returns to
Qory Apiary has a list of paths for each purpose and access:

| Purpose and access | Host | Paths, per repository |
|---|---|---|
| `work`, `write` | `github.com` | `/owner/name.git/info/refs`, `/owner/name.git/git-receive-pack` |
| `work`, `read` | `github.com`, `api.github.com` | the paths of the table in What the token reaches |
| `harness` | `github.com` | the `github.com` paths of the table in What the token reaches |

- The `write` credential has one item, for `github.com`, and none for `api.github.com`.
  The token reaches GitHub only for git's push. A request to any other path, such as
  `/graphql`, `/owner/name.git/git-upload-pack` or `/repos/owner/name/pulls`, gets no
  token. A query string is not part of a path, so `/owner/name.git/info/refs` is covered
  for both services, `git-receive-pack` and `git-upload-pack`.
- GitHub mints the `write` token with `contents: write` and no other permission, so it
  cannot open, edit or comment on a pull request: it has no pull request permission.
  The `read` token has `contents`, `metadata` and `pull_requests` `read`, and the token
  for a harness has `contents` `read`.
- A run with the access `write-no-push` (a checkout that is writable but cannot push)
  gets the `read` credential: Qory Apiary sends the call with access `read` for it.

### What the agent sees

- `GH_TOKEN` and `GITHUB_TOKEN` hold `qory-sets-the-credential-outside-the-enclosure`, a
  placeholder so `gh` starts.
- The gateway terminates TLS for `github.com` and `api.github.com` with a
  certificate the container trusts, and sets the token on requests to the paths in the
  table in What the token reaches.
- Under `enforce`, a request to another path gets `403` and a line such as:

  ```text
  qory: GET api.github.com/user denied by policy (mode enforce): no path rule of the run's covers it
  ```

### Push and pull requests

qory pushes the commits a run leaves, in its push step after the session: it runs `git
push` over HTTPS through the run's host proxy and the gateway behind it, which sets the
token on `github.com`. Inside the container, `git` and `gh` reach GitHub through the
gateway, which sets the token on the calls below; the default permissions allow them.
The table is for the token of `qory-github credential`; the token of a Qory Apiary run has
the paths in [The token of a Qory Apiary run](#the-token-of-a-qory-apiary-run).
Tested with git 2.39 and gh 2.100:

| Command | Calls | Needs |
|---|---|---|
| `git clone`, `git fetch` | `info/refs`, `git-upload-pack` on `github.com` | `contents: read` |
| `git push` | `info/refs`, `git-receive-pack` on `github.com` | `contents: write` |
| `gh pr create`, `gh pr edit`, `gh pr comment`, `gh pr view` | `/graphql` on `api.github.com` | `pull_requests: write` to create or change |

- The remote must be HTTPS. A remote over SSH gets no token.
- The pull request must be in a repository the policy lists. A pull request from a fork
  into another owner's repository needs two owners; a run has one.

The harness module in [`modules/github`](modules/github/README.md) contains
`bin/open-draft`, a program that adds a GitHub link to each commit of a run's submission
and, after a passed round, opens or updates the draft pull request through the GitHub REST
API. It reaches GitHub through a proxy on a unix socket and sends no token. The run
credential for work with access `write` has no item for `api.github.com`, so the
program cannot reach `api.github.com` through the push proxy: the proxy refuses the
`CONNECT`. As of 2026-11-17, `qory` does not run the program.

### Draft pull requests of a submission

`qory-github-server serve` opens or updates the draft pull request for each `submission`
entry that Qory Apiary writes to its change feed, one repository at a time. It calls
GitHub's REST API with an installation token of the App for that one repository, which has
`pull_requests: write` and no other permission. The App needs the permission Pull requests:
read and write on its installation; an App that `qory-github setup` creates has it. The run
and its machine hold no token for this.

For each repository of the entry, the adapter:

- Sends Qory Apiary the address of the base commit and of each listed commit,
  `https://github.com/owner/name/commit/<commit>`. It does so for every entry, also after
  a session that did not pass, when the entry asks for no draft and the adapter makes no
  request to GitHub.
- When the entry asks for a draft, looks for the pull request from the entry's branch in
  that repository, of any state, and reads it. It finds the pull request by the head
  branch and the repository alone, never by the base branch: a pull request from a fork
  is not that pull request, and a pull request into another base branch is. The `number`
  of an `update` entry is a hint: if GitHub has no pull request with that number from the
  branch, the adapter looks by the head branch. When several pull requests have the
  head branch, the adapter takes the one with the entry's `number` when it is among them,
  otherwise the open or draft one with the highest number, and when none is open, the
  closed or merged one with the highest number.
- Opens a draft pull request from the branch into the entry's base branch when there is
  none. It never changes the base branch of an existing pull request, so a later entry
  with another `base.branch` edits the same pull request and leaves its base as the
  person set it.
- Changes nothing in a pull request that is closed or merged, and reports its state
  (`closed` or `merged`) with the action `kept`.
- Changes an open or draft pull request only where something differs, and reports
  `updated`, or `kept` when nothing differs.

The adapter sends Qory Apiary one reply for the entry, with one target for each
repository that it put on GitHub, in the entry's order, once it has dealt with every
repository of the entry. A repository that failed for good gets a failure report, as
below, and is not in the reply. While a repository fails and may succeed on a retry, for
example after a 5xx status, the adapter holds the reply and applies that repository again
without applying the others again. When the retries end, after a day of failures, it
reports that repository as `unreachable` and sends the reply for the others. If Qory
Apiary does not take the reply for a day more, the adapter reports each repository of the
reply as `unreachable`.

The description has one marked block: the line `<!-- qory:start -->`, the run's text,
and the line `<!-- qory:end -->`. GitHub does not show the two lines. A marker line may
have spaces, tabs or a carriage return after the marker. An empty description becomes
the block alone, with no blank line before it. On an update of any other description, the
adapter finds the first end line that has a start line before it, and pairs it with the
last start line before that end line. It replaces the text from the start of that start
line through the end marker with the new block, and every other character stays, the
text before and after the block and anything after the end marker on its line. The
block's line breaks are CRLF when the first line break of the description is CRLF,
otherwise LF. When no start line is followed by an end line, as when a person removed a
marker, the adapter adds a blank line and a new block at the end of the description and
changes nothing else.

The adapter changes the title to the run's title only while the pull request's title
equals the title of the previous version of the submission. A title that a person edited
stays. The description of the run is at most 20000 characters and the title at most 256;
GitHub keeps at most 65536 characters in a description, and an update that would pass
that is reported as `too_long` before GitHub is asked. The title in the reply to Qory
Apiary is the pull request's title without the control, bidirectional and invisible
characters that Qory Apiary refuses; the pull request keeps its title. When that leaves
only spaces, the reply has the run's title, cleaned the same way.

When the adapter cannot do what a repository asks for, and a retry cannot change that, it
sends Qory Apiary a failure report for that repository with one reason and a `detail`. The
other repositories of the entry are not stopped. The `detail` is one line of at most
1000 characters: the fix for that case, as a sentence that says what a person does, then
GitHub's status and message when GitHub's answer caused the failure, with no token, no
header and no address with a password.

| Reason | Cause |
|---|---|
| `not_permitted` | GitHub answered 404, a permanent redirect, or 403 for something other than a rate limit, or the App has no installation on the repository, or the installation is suspended, or GitHub answered 401 until the retries ended. The fix gives the App the Pull requests permission and access to the repository. |
| `branch_gone` | GitHub's 422 says the head branch or the base branch does not exist. The fix says which: push the branch again, or create the base branch. |
| `too_long` | The run's title or description is over 256 or 20000 characters, or the description of the pull request would pass 65536 characters, or GitHub's 422 says a text is too long. The fix says which text to shorten. |
| `forge_refused` | GitHub answered 400, or 422 for any cause other than a missing branch or a length limit, or another 4xx status that a retry does not change, also from the lookup of the installation, or an answer that could not be read, or a 422 that says a pull request exists when none is found, after the retries ended: the same request fails again. The `detail` has GitHub's status and message. |
| `unreachable` | GitHub timed out, did not connect, was busy, rate limited or answered 5xx for a day. Each repository is reported by the last error of that repository's tries. |

### Token expiry

GitHub's installation tokens expire after an hour. The gateway calls `credential` again
five minutes before `expires_at`, and after a `401`, at most once every 30 seconds. The
hosts and paths stay the same; only the token changes.

## Limits

- One owner per run: an installation token belongs to one account.
- github.com only; GitHub Enterprise Server is not supported.
- Paths are compared as spelled. Write repositories in the policy exactly as the remotes
  and API calls spell them (`acme/lib`, not `ACME/lib`).
- The argument is refused when a name is `.` or `..` or ends in `.git`, when it names two
  owners, or when it lists a repository twice.
- Git LFS objects are served from other hosts through signed URLs; allow those hosts in
  the policy.
- No redirect from GitHub's API is followed, so the App's token goes nowhere else. A
  repository that moved or was renamed is refused; name its new owner/name in the
  policy's credential argument.
- Errors are one line on standard error and never contain the token or the key.

## Development

```sh
mise install                    # Go 1.27.4
go build ./cmd/qory-github
go test ./...
```

[CONTRIBUTING.md](CONTRIBUTING.md) has the full checks and the release process. The
integration contract is in
[qoryai/integrations](https://github.com/qoryai/integrations/tree/v0.3.0/contracts/integration/v1).

## Licence

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). *Qory* is a trademark of
8wonders GmbH.
