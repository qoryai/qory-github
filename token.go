package github

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// InstallationToken is a token GitHub minted for one installation of the App, and when
// it expires. It is a secret: String, GoString, JSON and an error never say it.
// Repositories are the repositories GitHub's answer to the mint lists, by id, each as
// GitHub names it: the ones a token limited to repositories covers, and none for a token
// that names no repository.
type InstallationToken struct {
	Token        string `json:"-"`
	ExpiresAt    time.Time
	Repositories map[int64]Repository `json:"-"`
}

// String says when the token expires, never the token, so a token printed by mistake
// is not given away.
func (t InstallationToken) String() string {
	return "an installation token that expires at " + t.ExpiresAt.UTC().Format(time.RFC3339)
}

// GoString is String, so %#v does not give the token away either.
func (t InstallationToken) GoString() string { return t.String() }

// MintInstallationToken requests from GitHub a token for the installation the request
// names, req.InstallationID, which must be set, limited to the request's repositories,
// named by owner/name or by id, and to its permissions, which must be set too, such as
// issues read: the calls the adapter makes to GitHub, not a run's, go with it. Each
// permission is one a run's token may be granted, [RunPermissions], read or write. The
// installation is checked with GitHub first, as [Client.Mint] checks it, so a token is
// never one of another account's: a repository named by owner/name must be the
// installation's account's, and one named by id GitHub mints for only when the
// installation reaches it, answering 422 otherwise. It keeps nothing: a caller that
// calls again before the expiry keeps the token itself.
func (c Client) MintInstallationToken(ctx context.Context, req Request) (InstallationToken, error) {
	if err := CheckAPIURL(c.base()); err != nil {
		return InstallationToken{}, err
	}
	if !appIDShape.MatchString(req.AppID) {
		return InstallationToken{}, errors.New("the App id is not an id, 1 to 64 letters, digits or dots")
	}
	if req.Key == nil {
		return InstallationToken{}, errors.New("no private key")
	}
	if req.InstallationID <= 0 {
		return InstallationToken{}, errors.New("no installation; an installation token is one installation's")
	}
	if len(req.Repositories) == 0 && len(req.RepositoryIDs) == 0 {
		return InstallationToken{}, errors.New("no repository")
	}
	for _, r := range req.Repositories {
		if !ownerShape.MatchString(r.Owner) || !nameShape.MatchString(r.Name) || r.Name == "." || r.Name == ".." {
			return InstallationToken{}, fmt.Errorf("%q is not owner/name", r.String())
		}
	}
	for _, id := range req.RepositoryIDs {
		if id <= 0 {
			return InstallationToken{}, errors.New("a repository's id is not one")
		}
	}
	if len(req.Permissions) == 0 {
		return InstallationToken{}, errors.New("no permission is set, which GitHub reads as every permission the installation has; set the ones the token needs")
	}
	for name, level := range req.Permissions {
		if !slices.Contains(RunPermissions, name) {
			return InstallationToken{}, fmt.Errorf("%q is not a permission an installation token may be granted; those are %s", name, strings.Join(RunPermissions, ", "))
		}
		if level != "read" && level != "write" {
			return InstallationToken{}, fmt.Errorf("the permission %s is neither read nor write", name)
		}
	}
	return c.mintFor(ctx, req)
}

// MintListingToken requests from GitHub a token for the installation installationID
// that reads which repositories it reaches and what they hold, and nothing more:
// metadata read and contents read, on every repository the installation reaches, named
// by no repository_ids, which [Lister.ListRepositories] lists with it, reading each
// repository's environment definition. The installation is checked with GitHub first,
// as [Client.MintInstallationToken] checks it. It keeps nothing.
func (c Client) MintListingToken(ctx context.Context, appID string, key *rsa.PrivateKey, installationID int64) (InstallationToken, error) {
	if err := CheckAPIURL(c.base()); err != nil {
		return InstallationToken{}, err
	}
	if !appIDShape.MatchString(appID) {
		return InstallationToken{}, errors.New("the App id is not an id, 1 to 64 letters, digits or dots")
	}
	if key == nil {
		return InstallationToken{}, errors.New("no private key")
	}
	if installationID <= 0 {
		return InstallationToken{}, errors.New("no installation; an installation token is one installation's")
	}
	return c.mintFor(ctx, Request{AppID: appID, Key: key, InstallationID: installationID, Permissions: map[string]string{"metadata": "read", "contents": "read"}})
}

// ErrMintRefused is wrapped in the error of a mint GitHub refuses for good: GitHub
// answers the installation's check 404, see [ErrInstallationGone], the installation is
// not the App's on the repositories' owner, or GitHub answers the mint 404 or 422, as it answers for an installation gone or a repository it no longer
// reaches: deleted, removed from the installation, or transferred to an account the
// installation is not on, whether the mint names it by owner/name or by its id, as
// repository_ids; or, for a repository the mint names by owner/name, renamed. A rename
// keeps the id and the installation's reach, so it never brings that answer to a mint
// by the id. Asking again does not change it.
var ErrMintRefused = errors.New("GitHub refuses to mint the installation token")

// ErrInstallationGone is wrapped, after [ErrMintRefused], in the error of a mint whose
// check of the installation, GET /app/installations/{id} with the App's token, GitHub
// answers 404, as it answers for an installation deleted or one that is not the App's.
// GitHub answers 401 to a token it does not take, so the 404 is its answer that the App
// has no installation by the id. No token is asked for.
var ErrInstallationGone = errors.New("GitHub answers 404 for the installation under the App's token, as for an installation deleted")

// ErrSuspended is the error of a mint whose check of the installation GitHub answers
// with suspended_at set: no token is asked for. It does not wrap [ErrMintRefused], since
// a suspension is lifted by the account that made it.
var ErrSuspended = errors.New("GitHub answers that the installation is suspended, so no installation token is minted for it")

// ErrRepositoryRefused is wrapped, after [ErrMintRefused], in the error of a mint that
// names repositories by id, repository_ids, and that GitHub answers 422, as it answers
// for a repository the installation does not reach, deleted, removed from the
// installation or transferred, or for a permission the installation does not grant. The
// answer alone does not say which.
var ErrRepositoryRefused = errors.New("GitHub answers 422 to a token for the repository alone, as for a repository the installation does not reach, or a permission it does not grant")

// errNotTheInstallation is [errNotTheOwners] for a token the adapter mints, whose
// installation no setting names.
var errNotTheInstallation = errors.New("the installation is not the App's installation on the repositories' owner")

// mintFor mints the token req asks for, once its installation is checked: limited to
// its repositories, by name and by id, or to none when it names none, and to its
// permissions. req is checked already. A mint refused for good wraps [ErrMintRefused],
// and with it [ErrInstallationGone] for a check GitHub answers 404, or
// [ErrRepositoryRefused] for a mint by repository_ids GitHub answers 422. An
// installation GitHub answers as suspended is [ErrSuspended], and no token is asked for.
// A 403 to the mint is GitHub's answer alone: GitHub answers 403 for a secondary rate
// limit too, so it is never taken for a suspension.
func (c Client) mintFor(ctx context.Context, req Request) (InstallationToken, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	jwt, err := AppJWT(req.AppID, req.Key, now())
	if err != nil {
		return InstallationToken{}, err
	}
	suspended, err := c.checkInstallation(ctx, jwt, req.InstallationID, req.Repositories)
	switch {
	case err == ErrInstallationGone:
		return InstallationToken{}, fmt.Errorf("%w: %w", ErrMintRefused, ErrInstallationGone)
	case err == errNotTheOwners:
		return InstallationToken{}, fmt.Errorf("%w: %w", ErrMintRefused, errNotTheInstallation)
	case err != nil:
		return InstallationToken{}, err
	case suspended:
		return InstallationToken{}, ErrSuspended
	}
	var got struct {
		Token        string   `json:"token"`
		ExpiresAt    string   `json:"expires_at"`
		Repositories []ghRepo `json:"repositories"`
	}
	body := map[string]any{"permissions": req.Permissions}
	if len(req.Repositories) > 0 {
		names := make([]string, len(req.Repositories))
		for i, r := range req.Repositories {
			names[i] = r.Name
		}
		body["repositories"] = names
	}
	if len(req.RepositoryIDs) > 0 {
		body["repository_ids"] = req.RepositoryIDs
	}
	const minting = "minting the installation token"
	if err := c.call(ctx, minting, http.MethodPost, "/app/installations/"+strconv.FormatInt(req.InstallationID, 10)+"/access_tokens", jwt, body, http.StatusCreated, &got); err != nil {
		var answered *answerError
		if errors.As(err, &answered) && answered.redirect() {
			return InstallationToken{}, errMintRedirected
		}
		switch {
		case errors.As(err, &answered) && answered.status == http.StatusUnprocessableEntity && len(req.RepositoryIDs) > 0:
			err = fmt.Errorf("%w: %w: %w", ErrMintRefused, ErrRepositoryRefused, err)
		case errors.As(err, &answered) && (answered.status == http.StatusNotFound || answered.status == http.StatusUnprocessableEntity):
			err = fmt.Errorf("%w: %w", ErrMintRefused, err)
		}
		return InstallationToken{}, err
	}
	if got.Token == "" {
		return InstallationToken{}, errors.New(minting + ": GitHub answered without a token")
	}
	expires, err := time.Parse(time.RFC3339, got.ExpiresAt)
	if err != nil {
		return InstallationToken{}, fmt.Errorf("%s: the expiry %q is not a time", minting, got.ExpiresAt)
	}
	t := InstallationToken{Token: got.Token, ExpiresAt: expires.UTC()}
	for _, r := range got.Repositories {
		if name, ok := nameOf(r); ok && r.ID > 0 {
			if t.Repositories == nil {
				t.Repositories = map[int64]Repository{}
			}
			t.Repositories[r.ID] = name
		}
	}
	return t, nil
}
