# Contributing

Thank you for considering a contribution.

## Where contributions go

- **A fix**, with the test that shows it.
- **What the integration does for a run**: a permission, or a host GitHub serves a run
  from. The integration speaks the
  [integration contract](https://github.com/qoryai/integrations/tree/main/contracts/integration/v1)
  and, for the credential role, the runner's
  [§Credentials](https://github.com/qoryai/runner/tree/main/contracts/runner/v1#credentials);
  a change to either contract goes to its own repository first.

The repository holds one integration: its README, its program's command under
`cmd/qory-github/`, the package `github` at the root, its description, `description.json`,
and its tests.

## Contributor Licence Agreement

Copyright in this project is held by a single owner: **8wonders GmbH, and its successors and
assigns**. To keep that true, every contribution is made under the Contributor Licence
Agreement in [CLA.md](CLA.md): a perpetual, worldwide, irrevocable licence to the
contribution, including the right to relicense it, and a patent grant on the same terms as
the Apache License, Version 2.0. You keep your copyright.

Opening a pull request against this repository is your acceptance of the agreement, for that
contribution and every later one. The pull request is the record of your acceptance. Read
[CLA.md](CLA.md) before your first pull request.

The agreement names the owner with successors-and-assigns wording, so that if the
project moves into a dedicated entity, existing grants travel with it and nobody signs again.

Why a CLA at all: the licensing decisions of the project are only executable with a sole
copyright holder. Declaring it before a community exists is what makes it a kept promise
rather than a takeback.

## Licence

By contributing, you agree that your contribution is licensed under the Apache License,
Version 2.0 (see [LICENSE](LICENSE)) in addition to the CLA grant above.

## Development

The toolchain is pinned in `mise.toml`; `mise install` provides it. Go 1.27.

```sh
go build ./cmd/qory-github
go test ./...
gofmt -l .              # must print nothing
go vet ./...
go run github.com/mgechev/revive@v1.16.0 -config revive.toml ./...
```

A test is hermetic: `t.TempDir` for files, a loopback listener for GitHub's API, keys
generated in the test. No test reaches the network or reads the machine's configuration,
and no fixture contains a real secret, a real account or a real repository of anyone's.
What the program prints is checked with the `conformance` package of
[qoryai/integrations](https://github.com/qoryai/integrations): the description against the
integration contract, the credential answer against the runner's schema, and every failure
against the exit status the contract's commands share. What `describe` prints is pinned in
`testdata/describe.json`.

A program never prints a token, a private key or any other secret anywhere but the answer
its contract requires, and never writes one to a file others can read. Its errors describe
what failed, not what was sent.

## Doc comments

Every package and every exported name has a doc comment, and CI fails without one. The
first sentence starts with the name and is a complete sentence. Say what the code does,
including what it refuses, what it overwrites and what it leaves behind. Wrap at 90
columns.

## Releases

A release is a tag on a branch named after it, `v0.1.0`, opened as one pull request. That
branch adds the release's section to `CHANGELOG.md`, `[X.Y.Z] - YYYY-MM-DD` with the day
the tag lands; a fix that goes to `main` outside a release branch goes under
`[Unreleased]` until the next one. The tag's workflow publishes the program's archives and
`checksums.txt`, by the rule every integration follows
([§Release rule](https://github.com/qoryai/integrations#release-rule)).

Commit messages state what changed and why it was needed, in the imperative.
