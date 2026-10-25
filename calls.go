package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrNotInstalled is the error of [Client.RepositoryInstallation] when GitHub returns
// 404 or a redirect: the App has no installation that reaches the repository by that
// owner/name, or the name moved.
var ErrNotInstalled = errors.New("GitHub has no installation of the App on the repository")

// ErrVersionNotFound is the error of [Client.CommitAt] when GitHub returns 404, 409 for
// an empty repository, or 422: the repository has no commit, branch or tag by the name
// asked for.
var ErrVersionNotFound = errors.New("the repository has no such commit, branch or tag on GitHub")

// ErrNotText is the error of [Client.ReadDocument] for a path that is a directory, a
// submodule or a symbolic link, or a file larger than the limit, not UTF-8, or with a NUL.
var ErrNotText = errors.New("the path is not a UTF-8 text file within the limit")

// shaShape is a commit's id as GitHub writes it: 40 lower-case hexadecimal digits, or 64
// in a repository that uses SHA-256.
var shaShape = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// maxDocumentAnswer is the largest answer [Client.ReadDocument] reads, in bytes: GitHub
// puts a file's content in the answer, in base64, only for a file of 1 MB at most.
const maxDocumentAnswer = 2 << 20

// RepositoryInstallation reads from GitHub, with the App's token, the installation of
// the App that reaches the repository by owner/name, GET
// /repos/{owner}/{repo}/installation, and returns its id and its account's login. A
// 404 or a redirect is [ErrNotInstalled]. The redirect is never followed.
func (c Client) RepositoryInstallation(ctx context.Context, appID string, key *rsa.PrivateKey, repo Repository) (int64, string, error) {
	const what = "finding the App's installation on a repository"
	if !ownerShape.MatchString(repo.Owner) || !nameShape.MatchString(repo.Name) || repo.Name == "." || repo.Name == ".." {
		return 0, "", errors.New(what + ": the repository is not owner/name")
	}
	if key == nil {
		return 0, "", errors.New("no private key")
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	jwt, err := AppJWT(appID, key, now())
	if err != nil {
		return 0, "", err
	}
	var got struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
	}
	err = c.call(ctx, what, http.MethodGet, "/repos/"+repo.String()+"/installation", jwt, nil, http.StatusOK, &got)
	var answered *answerError
	switch {
	case errors.As(err, &answered) && (answered.redirect() || answered.status == http.StatusNotFound):
		return 0, "", ErrNotInstalled
	case err != nil:
		return 0, "", err
	case got.ID <= 0 || !ownerShape.MatchString(got.Account.Login):
		return 0, "", errors.New(what + ": GitHub's answer has no installation id or no account login")
	}
	return got.ID, got.Account.Login, nil
}

// RepositoryID reads the id of the repository by owner/name with an installation token,
// GET /repos/{owner}/{repo}, and the repository's owner/name as GitHub writes it. A 404,
// a 410 or a redirect wraps [ErrRepositoryGone]: the token does not reach the repository
// by that name, or the name moved.
func (c Client) RepositoryID(ctx context.Context, token string, repo Repository) (int64, Repository, error) {
	const what = "reading a repository by its name"
	if !ownerShape.MatchString(repo.Owner) || !nameShape.MatchString(repo.Name) || repo.Name == "." || repo.Name == ".." {
		return 0, Repository{}, errors.New(what + ": the repository is not owner/name")
	}
	var r ghRepo
	if _, err := c.get(ctx, nil, false, what, "/repos/"+repo.String(), token, &r); err != nil {
		return 0, Repository{}, repositoryGone(err)
	}
	name, ok := nameOf(r)
	if r.ID <= 0 || !ok {
		return 0, Repository{}, errors.New(what + ": GitHub's answer has no id or no owner/name")
	}
	return r.ID, name, nil
}

// CommitAt reads the commit that at is or points to in the repository whose id is
// repository, with an installation token: at is a commit's id, a branch or a tag. It
// reads the newest commit of the history at that name, GET
// /repositories/{id}/commits?sha={at}&per_page=1, and returns its id. A 404, a 409 or a 422, or an empty list, is [ErrVersionNotFound].
func (c Client) CommitAt(ctx context.Context, token string, repository int64, at string) (string, error) {
	const what = "reading the commit of a version"
	if repository <= 0 {
		return "", errors.New(what + ": the repository's id is not one")
	}
	path := "/repositories/" + strconv.FormatInt(repository, 10) + "/commits?" + url.Values{"sha": {at}, "per_page": {"1"}}.Encode()
	var got []struct {
		SHA string `json:"sha"`
	}
	_, err := c.get(ctx, nil, false, what, path, token, &got)
	var answered *answerError
	switch {
	case errors.As(err, &answered) && (answered.status == http.StatusNotFound || answered.status == http.StatusConflict || answered.status == http.StatusUnprocessableEntity):
		return "", fmt.Errorf("%w: %w", ErrVersionNotFound, err)
	case err != nil:
		return "", err
	case len(got) == 0:
		return "", ErrVersionNotFound
	case !shaShape.MatchString(got[0].SHA):
		return "", errors.New(what + ": GitHub's answer has no commit id")
	}
	return got[0].SHA, nil
}

// ReadDocument reads the file at path in the repository whose id is repository, at the
// commit commit, with an installation token: GET /repositories/{id}/contents/{path}. It
// returns the file's text, or false when GitHub returns 404, as for a path the commit has
// no file at. A directory, a submodule, a symbolic link GitHub does not resolve to a file,
// a file larger than max bytes, and content that is not UTF-8 or has a NUL are
// [ErrNotText]. path is parts joined by /, none empty, . or ..; each part is escaped.
func (c Client) ReadDocument(ctx context.Context, token string, repository int64, path, commit string, max int) (string, bool, error) {
	const what = "reading a file at a commit"
	if repository <= 0 || !shaShape.MatchString(commit) {
		return "", false, errors.New(what + ": the repository's id or the commit's id is not one")
	}
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if p == "" || p == "." || p == ".." {
			return "", false, errors.New(what + ": the path has an empty part, or a part . or ..")
		}
		parts[i] = url.PathEscape(p)
	}
	target := "/repositories/" + strconv.FormatInt(repository, 10) + "/contents/" + strings.Join(parts, "/") + "?" + url.Values{"ref": {commit}}.Encode()
	a, err := c.sendBounded(ctx, nil, false, what, http.MethodGet, target, token, nil, maxDocumentAnswer)
	if err != nil {
		return "", false, err
	}
	switch a.status {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", false, nil
	default:
		return "", false, a.err(what)
	}
	// A directory is a JSON list, which does not decode into the object.
	var got struct {
		Type     string `json:"type"`
		Size     int    `json:"size"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
	}
	if json.Unmarshal(a.body, &got) != nil || got.Type != "file" || got.Size > max || got.Encoding != "base64" {
		return "", false, ErrNotText
	}
	// GitHub breaks the base64 into lines.
	b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(got.Content, "\n", ""))
	if err != nil {
		return "", false, fmt.Errorf("%s: GitHub's content is not base64", what)
	}
	if len(b) > max || !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return "", false, ErrNotText
	}
	return string(b), true, nil
}
