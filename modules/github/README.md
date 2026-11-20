# The module github

A Qory harness module with one program, `bin/open-draft`, declared as the module's
`submit_program` in `qory-module.yaml`. After `qory run` pushed the branch of a run that
has no run code, qory runs the program once for each repository on your machine, outside
the sandbox that a run uses. The program prints the GitHub address of each commit and, when the run has
hand-off text, opens the draft pull request of the branch or edits the one that exists.
It uses the login of `gh` that you made, pushes nothing, and gives no token to anything
but `gh`. A run that starts from a run code runs no program: `qory-github-server serve`
opens its draft pull request.

`bin/open-draft` is a POSIX `sh` script. It uses `gh`, and `sed`, `awk`, `grep`, `tr`,
`head`, `tail`, `cut`, `wc`, `cat`, `cmp`, `mktemp` and `rm`. It needs no `jq` or Python.

To try the program, set the variables under Inputs and run `bin/open-draft`.

## Requirements

- `gh`, logged in to `github.com` (`gh auth login`). The program calls
  `gh auth token --hostname`, `gh api --hostname ... --jq` and `gh pr create --repo --draft
  --head --base --title --body-file`. The help of `gh` 2.102.0 lists each of them. The earliest
  version that has each is not checked, so use a current `gh`.
- A login that can open and edit pull requests in the repository.

If `gh auth token` finds no login, the program exits with status 3 and prints as the first line on
standard error: ``Run `gh auth login`, then `qory run` again.`` A `gh` call that GitHub
answers with HTTP 401 gets the same exit status and line. Without `gh` on `PATH`, the
program exits with status 1.

## Inputs

qory sets these environment variables, as the submit program contract of the integrations
repository lists them (`contracts/run/v1/submit-program/README.md`). Standard input is
empty.

| Variable | Value |
|---|---|
| `QORY_SUBMIT_SYSTEM` | `github.com`. Any other host is refused. |
| `QORY_SUBMIT_PATH` | `owner/name`. |
| `QORY_SUBMIT_BRANCH` | The branch that qory pushed, the head of the draft. |
| `QORY_SUBMIT_BASE_BRANCH` | The base branch of a new draft. Needed when `QORY_SUBMIT_DRAFT` is `open`. |
| `QORY_SUBMIT_BASE_COMMIT` | The commit that the run started at: 40 or 64 lower-case hexadecimal digits. |
| `QORY_SUBMIT_COMMITS` | 1 to 100 commit ids, joined by single spaces. |
| `QORY_SUBMIT_DRAFT` | `open`, or `none` to print the addresses only. |
| `QORY_SUBMIT_TITLE` | The title of a new draft, 1 to 256 characters on one line. |
| `QORY_SUBMIT_DESCRIPTION_FILE` | The path of a file with the description text, at most 20000 characters. |

`gh` reads `GH_TOKEN` and `GH_HOST` from the environment. The program prints neither.

## What the program does

1. It checks the inputs of the commits: the system, the path, the branch, `QORY_SUBMIT_DRAFT`,
   the base commit and the commits. A value that it cannot use ends the program with
   status 2 before it prints a line.
2. It prints `commit_url <commit> https://github.com/<owner>/<name>/commit/<commit>` for
   the base commit and each commit.
3. With `QORY_SUBMIT_DRAFT` `open`, it checks the inputs of the draft: the title, the base
   branch and the description file. A value that it cannot use ends the program with
   status 2, after the commit lines. With `none`, it ends here and runs no `gh`.
4. It runs `gh auth token --hostname github.com`, which reads the login from the credential
   store of `gh` and calls no server. It discards the token.
5. It searches for the pull requests of the repository with the head branch, in any
   state (`gh api repos/<owner>/<name>/pulls` with `head=<owner>:<branch>` and
   `state=all`). It ignores the base branch, the branch of a fork with the same name,
   and a pull request whose head repository is gone. Of several it takes the one
   with the highest number that is not closed and not merged, otherwise the one with the
   highest number.
6. With none, it runs `gh pr create --draft` with the branch, the base branch, the title
   and the description. The description is the block alone.
7. With one that is closed or merged, it changes nothing and prints its state with the
   action `kept`.
8. With one that is open or a draft, it keeps the title and replaces the text between
   the lines `<!-- qory:start -->` and `<!-- qory:end -->` of the description with the
   text of the file, through `gh api` with the method `PATCH`. It sends nothing when the
   description stays the same, and prints the action `kept`.

The first end line that has a start line before it ends the block, and the last start
line before that end line starts it. A line is a marker line when the marker is followed
by nothing but spaces, tabs or a carriage return. When a person removed a marker, the
description stays whole and the block follows after a blank line, or stands alone when
the description is empty. The block uses the line ending of the first line of the
description, CRLF or LF. This is the rule that the adapter applies
(`contracts.MarkedDescription`).

## Output and exit status

Standard output has one line for each fact, each ending in a line feed. The program
prints the commit lines first and, after a draft, the five draft lines together:

```text
commit_url 3e2d1c0b9a8f7e6d5c4b3a291807f6e5d4c3b2a1 https://github.com/acme/shop/commit/3e2d1c0b9a8f7e6d5c4b3a291807f6e5d4c3b2a1
draft_number 34
draft_url https://github.com/acme/shop/pull/34
draft_title Show delivery dates at checkout
draft_state draft
draft_action opened
```

`draft_state` is `draft`, `open`, `closed` or `merged`, and `draft_action` is `opened`,
`updated` or `kept`. The title is the one that GitHub has after the call, without the
characters that `draft_title` may not have: the control characters (category
Cc), U+2028, U+2029, and the format characters (category Cf) except U+200C and U+200D,
which emoji sequences need. The program keeps U+200C and U+200D in the title, and a title
of nothing but spaces, U+200C and U+200D counts as empty. When the title is empty, it is
`QORY_SUBMIT_TITLE`, cleaned the same way.

The program has the removed characters as 24 ranges in `FORBIDDEN_RANGES`, the format
characters of Unicode 17.0.0. The tests compare the ranges with the rule of
`qory-github-server` for every code point, so a later Unicode version fails them until
you update the ranges.

| Exit | Meaning |
|---|---|
| 0 | Done. |
| 1 | A call to `gh` failed, `gh` is missing, or the `gh` call did not finish within 110 seconds. The commit lines are printed; no draft line is. |
| 2 | An input cannot be used. Nothing is printed on standard output when the input is one of the commits; the commit lines are printed when it is one of the draft. |
| 3 | `gh` has no login, or GitHub rejected it. |

Standard error has one line. It starts with the fix. For a failed call, it ends with the
first line of the message that `gh` printed, cut to 200 characters, with the tokens of
the environment masked:

```text
Check your gh login and its access to owner/name, then run `qory run` again: the update of pull request 34 failed: gh: Resource not accessible by integration (HTTP 403)
```

qory stops the program after 120 seconds and then reads no line. The program ends itself
after 110 seconds when `gh` has not finished: it ends the `gh` call, prints
``Run `qory run` again: the `gh` call did not finish within 110 seconds.`` on standard
error, and exits with status 1, so the commit lines that it printed are read. SIGHUP, SIGINT and
SIGTERM end the timer, the work and `gh` the same way, with status 1. A SIGKILL of the
program leaves its timer, a `sleep`, running for up to 110 seconds. The tests set
`OPEN_DRAFT_WATCHDOG_SECONDS`, from 1 to 110, to shorten the limit; the program takes no
larger value.
