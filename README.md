# qory-github

Gives a Qory run a GitHub token for the repositories it works on, without the agent ever
holding the token.

`qory-github` is a credential adapter for the [Qory runner](https://github.com/qoryai/runner).
For each run it mints a
[GitHub App installation token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
limited to the run's repositories and to the permissions you allow. The runner keeps the
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

In `~/.config/qory/runner.yaml`. `setup` prints this block with your App's id and key
file:

```yaml
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

- The key file is written with mode 0600. An existing file is never overwritten.
- GitHub hands out the key once. If the file cannot be written, the key goes to
  `<file>.<random hex>` and `setup` prints where. If that fails too, the error names the
  App and the page where you generate a new key.
- The key is never printed.
- `--api-url` takes `https://api.github.com` alone, with or without a trailing `/` or
  `:443`, and `--web-url` takes `https://github.com` alone, with or without a trailing
  `/`. For tests, each also takes `http` or `https` on a loopback host (`127.0.0.0/8`,
  `[::1]`, `localhost`) with any port. Anything else is refused before `setup` creates,
  listens on or opens anything. GitHub Enterprise Server is not supported.

### credential

```sh
qory-github credential -- owner/name[,owner/name...] < settings.json
```

The runner calls this for each run; you normally don't. It reads the settings on
standard input, mints a token for the listed repositories, all of one owner, and prints
the runner's credential document: the token, `expires_at`, the hosts and paths it
applies to, and the placeholders `GH_TOKEN` and `GITHUB_TOKEN`. Each call mints a new
token; nothing is kept.

- The settings are one JSON document on standard input, nothing after it but white
  space, 64 KiB (65536 bytes) at most. Empty input is refused; `{}` is a document.
- Standard input is read to its end, or until it has more than 64 KiB, before the
  argument is checked, before the key is read and before any network call.
- The settings must contain `app_id` and the private key, as `private_key` or as
  `private_key_file`, one of them: settings with neither of them, or with both, are
  refused before the key is read and before any network call.
- One argument follows `--`. An empty one is refused as not `owner/name`.
- `credential` takes no flags. A flag is refused in one line, like any other failure.

### describe

```sh
qory-github describe
```

Prints the integration's description: its publisher, Qory, the settings as a JSON Schema,
and the credential role, with the settings the runner hands it and those it requires
([Settings](#settings)). `qory` calls it to check a declaration. No settings, no network.

### Exit status

- `0`: success. `describe` and `credential` print one JSON document on standard output.
- `1`: failure, a flag a command refuses among them. One line on standard error that
  says what failed, never the token or the key. `setup` prints its usage before that
  line when it refuses a flag.
- `2`: no command, an unknown one, or `-h`. Usage or help on standard error.

## Settings

One JSON document, on the standard input of `credential`; in `runner.yaml`, under
`settings:`.

| Setting | Required | Meaning |
|---|---|---|
| `app_id` | yes | The App's numeric id, or its client id as a string |
| `private_key_file` | this or `private_key` | Path to the App's private key, the key kept on disk. Must be a regular file owned by the user running the program, not readable by group or others, and not a symbolic link. |
| `private_key` | this or `private_key_file` | The App's private key itself, the PEM. A secret. |
| `installation_id` | no | The App's installation on the repositories' owner. Checked with GitHub before a token is minted: an installation on another account is refused. Looked up from the repositories when absent. |
| `permissions` | no | Permissions for the token, each `read` or `write`. Default: `{"contents": "write", "pull_requests": "write"}` |
| `api_url` | no | GitHub's API, where the App's own token goes. Only `https://api.github.com`, the default, with or without a trailing `/` or `:443`, or for tests `http` or `https` on a loopback host (`127.0.0.0/8`, `[::1]`, `localhost`), any port. No other host, path, user, query or fragment. GitHub Enterprise Server is not supported. Not in the credential role's settings. |

Settings without `app_id`, or with neither `private_key` nor `private_key_file`, are
refused, and so are settings that contain both: a secret has one source. No setting is
read from the environment or the command line.

`app_id` as a number, and `installation_id`, are integers from 1 to 9007199254740991,
2^53 - 1, the largest integer every JSON reader holds exactly. An integer is read as JSON
Schema reads it, whatever its notation: `42.0` and `4.2e1` are `42`.

The description's credential role lists the settings the runner writes to the standard
input of `credential`, as the
[integration contract](https://github.com/qoryai/integrations/tree/main/contracts/integration/v1#roles)
defines a role's `settings` and `required`:

```json
"settings": ["app_id", "installation_id", "permissions", "private_key"],
"required": ["app_id", "private_key"]
```

The private key is listed as `private_key`, and the runner writes it as `private_key` or
as `private_key_file`; either satisfies `required`. `api_url` is not listed, so a
document the runner writes never carries it; `credential` takes it when the document on
its standard input does.

## Permissions

A token can get these permissions, `read` or `write`: `actions`, `checks`, `contents`,
`deployments`, `issues`, `metadata`, `pages`, `pull_requests`, `statuses`, `workflows`.

Refused: `administration`, `secrets`, `environments`, `repository_hooks`, every
`organization_*` permission, `members`, the level `admin`, and an empty `permissions`
(GitHub reads it as "all").

A token never gets more than the App has. The App `setup` creates has contents and pull
requests `write` and metadata `read`. For more, for example `issues`, change the App's
permissions on GitHub and accept the change on the installation.

## What the token reaches

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
  ([runner contract](https://github.com/qoryai/runner/tree/main/contracts/runner/v1#the-policy)).

### What the agent sees

- `GH_TOKEN` and `GITHUB_TOKEN` hold `qory-sets-the-credential-outside-the-enclosure`, a
  placeholder so `gh` starts.
- The runner's proxy terminates TLS for `github.com` and `api.github.com` with a
  certificate the container trusts, and sets the token on requests to the paths above.
- Under `enforce`, a request to another path gets `403` and a line such as:

  ```text
  qory: GET api.github.com/user denied by policy (mode enforce): no path rule of the run's covers it
  ```

### Push and pull requests

The agent pushes and opens pull requests itself with `git` and `gh`; the default
permissions allow it. Tested with git 2.39 and gh 2.100:

| Command | Calls | Needs |
|---|---|---|
| `git clone`, `git fetch` | `info/refs`, `git-upload-pack` on `github.com` | `contents: read` |
| `git push` | `info/refs`, `git-receive-pack` on `github.com` | `contents: write` |
| `gh pr create`, `gh pr edit`, `gh pr comment`, `gh pr view` | `/graphql` on `api.github.com` | `pull_requests: write` to create or change |

- The remote must be HTTPS. A remote over SSH gets no token.
- The pull request must be in a repository the policy lists. A pull request from a fork
  into another owner's repository needs two owners; a run has one.

### Token expiry

GitHub's installation tokens expire after an hour. The runner calls `credential` again
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
- No redirect from GitHub's API is followed, so the App's own token goes nowhere else. A
  repository that moved or was renamed is refused; name its new owner/name.
- Errors are one line on standard error and never contain the token or the key.

## Development

```sh
mise install                    # Go 1.27.1
go build ./cmd/qory-github
go test ./...
```

[CONTRIBUTING.md](CONTRIBUTING.md) has the full checks and the release process. The
integration contract is in
[qoryai/integrations](https://github.com/qoryai/integrations/tree/main/contracts/integration/v1).

## Licence

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). *Qory* is a trademark of
8wonders GmbH.
