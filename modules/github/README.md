# The module github

A Qory harness module with one program, `bin/open-draft`, declared as the module's
`submit_program` in `qory-module.yaml`. The program adds GitHub commit links to a run's
submission file and, after a passed round, opens or updates the draft pull request of each
GitHub repository in it.

`bin/open-draft` is a Node script (Node 24) that uses Node's built-in modules only.

## Inputs

| Variable | Value |
|---|---|
| `QORY_SUBMISSION_FILE` | The path of `submission.json`, in the shape of the harness type `submission`. The program writes `<file>.tmp` in the same folder and renames it. |
| `QORY_SUBMIT_BASES` | The path of a JSON list `[{"system": "github.com", "path": "owner/name", "base": "main"}]`, where `base` is the base branch of the pull request. Read only when the program opens or updates drafts. |
| `QORY_PROXY_SOCKET` | The unix socket of an HTTP proxy that accepts `CONNECT api.github.com:443`. |
| `QORY_PROXY_PASSWORD` | The proxy password, sent as `Proxy-Authorization: Basic` with the user `qory`. |
| `SSL_CERT_FILE` | Optional. A PEM bundle of the certificate authorities that the program trusts for `api.github.com`. Without it, the program trusts Node's default store. |

The program sends no token and no `Authorization` header, runs no `git`, and connects to
nothing but the socket in `QORY_PROXY_SOCKET`. The proxy of a push allows only the hosts
of the push credential's items. The run credential for work with access `write` has no
item for `api.github.com`, so the program cannot reach `api.github.com` through that
proxy: the proxy refuses the `CONNECT`.

## What the program does

1. It reads the submission file and checks its structure: `ref`, `verdict`, and in each
   entry of `repositories`, `system`, `path`, `commit`, `draft`, `base` and `commits`.
2. In each entry whose `system` is `github.com`, it sets `commit_url`, `base.commit_url`
   and each `commits[].commit_url` to `https://github.com/<path>/commit/<commit>`, and
   writes the file. It changes no entry of another system.
3. If `verdict` is `passed` and the submission has `text`, it checks what the drafts
   need: `text`, the bases file, the socket, the password and the CA bundle. Then, for
   each `github.com` repository:
   - `GET /repos/<path>/pulls?head=<owner>:<ref>&state=open&per_page=100` lists open
     pull requests. The program uses only those whose head branch is `ref`, whose head
     repository is `<path>` in any case, and whose base branch is the one in
     `QORY_SUBMIT_BASES`.
   - With none, `POST /repos/<path>/pulls` opens a draft with `text.title`,
     `text.description`, the head `ref` and the base branch.
   - With one, `PATCH /repos/<path>/pulls/<number>` sets its title and description only.
     With more than one, the call counts as failed.
   - The program sets the entry's `draft` to `{number, url, title, state, action}` and
     writes the file. `url` is `https://github.com/<path>/pull/<number>`; a response with
     another link, compared without regard to case, counts as a failed call. `title` is
     the title GitHub returned. `state` is `draft`, or `open` when the pull request is no
     longer a draft. `action` is `opened` or `updated`.

   Otherwise, `draft` stays as it is, and the program makes no call.

Every call to GitHub ends by 100 seconds after the program starts, and has no retry.

## Exit status and output

| Exit | Meaning | The submission file |
|---|---|---|
| 0 | Done. | Every commit link, and each draft. |
| 1 | A call to GitHub failed: a refused connection, a proxy status other than 200, an HTTP status of 300 or more, a response that is not the expected JSON, more than one matching pull request, or the 100 s limit. The program still calls GitHub for the other repositories. Or a write of the file failed; the program then stops. | Every commit link and each draft written before the program ended. Unchanged when writing the commit links failed. |
| 2 | The input is wrong. | Unchanged when the structure is wrong: a missing `QORY_SUBMISSION_FILE`, a file that is missing or does not parse, a member of the wrong shape, or a `github.com` path that is not `owner/name`. Only the commit links written when an input of the drafts is wrong: `text`, the bases file or a repository with no base branch in it, the socket, the password or the CA bundle. |

stdout has one line per repository whose draft the program opened or updated:

```text
https://github.com/owner/name/pull/34 opened
https://github.com/owner/name/pull/34 updated
```

stderr has one line per error, and the line starts with the fix. For a repository path
of up to 21 characters, a line with no file path in it has at most 100 characters. After
a 422 or another 4xx status without a specific fix, the line ends with GitHub's error
message in parentheses, cut to fit. A 429, or a 403 with no requests left or with a
message about the rate limit, gets the line that starts `Wait for GitHub's rate limit to
reset for`:

```text
Give the GitHub App pull_requests: write on owner/name: POST pulls returned 403
Add owner/name to the run documents' targets: no base branch for it in QORY_SUBMIT_BASES
```

The program writes neither the proxy password nor a token to its output.
