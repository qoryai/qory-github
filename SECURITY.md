# Security

## Reporting a vulnerability

Write to **info@8wonders.de**. Do not open a public issue or pull request for it.

Say what you found, the program's version, and how to see it happen: the command, its
flags with every secret taken out, and what it did that it should not.

You get an answer within three working days. We tell you what we found, fix what is a
vulnerability in a new release, and publish an advisory that credits you unless you
would rather it did not.

## Supported versions

The latest release. Below 1.0 a fix is a new release and is not carried back to an
earlier one.

## What is a vulnerability here

The README says what `qory-github` promises. For example:

- `qory-github` writes a token, a private key or a secret of the App anywhere but its
  answer on standard output, or the key to a file others can read;
- `qory-github credential` answers with a host, a path or a repository the command did
  not ask for, or a token with more than the permissions it was given;
- `qory-github setup` writes over a file that exists, or answers a callback that does
  not carry the state it sent.

## What is not

- What a token may do on the paths a run was given is the token's grant: the App's
  permissions and the repositories it is installed on.
- The gateway, and what it does with the answer, are
  [Forager's](https://github.com/qoryai/forager/blob/main/SECURITY.md).
- The integration contract and the workflows that build the release are
  [qoryai/integrations'](https://github.com/qoryai/integrations/blob/main/SECURITY.md).

If you are not sure which side something falls on, write anyway.
