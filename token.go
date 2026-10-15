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
type InstallationToken struct {
	Token     string `json:"-"`
	ExpiresAt time.Time
}

// String says when the token expires, never the token, so a token printed by mistake
// is not given away.
func (t InstallationToken) String() string {
	return "an installation token that expires at " + t.ExpiresAt.UTC().Format(time.RFC3339)
}

// GoString is String, so %#v does not give the token away either.
func (t InstallationToken) GoString() string { return t.String() }

// MintInstallationToken requests from GitHub a token for the installation the request
// names, req.InstallationID, which must be set, limited to the request's repositories
// and to its permissions, which must be set too, such as issues read: the calls the
// adapter makes to GitHub, not a run's, go with it. Each permission is one a run's token may be
// granted, [RunPermissions], read or write. The installation is checked with GitHub
// first, as [Client.Mint] checks it, so a token is never one of another account's. It
// keeps nothing: a caller that calls again before the expiry keeps the token itself.
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
	if len(req.Repositories) == 0 {
		return InstallationToken{}, errors.New("no repository")
	}
	for _, r := range req.Repositories {
		if !ownerShape.MatchString(r.Owner) || !nameShape.MatchString(r.Name) || r.Name == "." || r.Name == ".." {
			return InstallationToken{}, fmt.Errorf("%q is not owner/name", r.String())
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
// that reads which repositories it reaches and nothing more: metadata read, on every
// repository the installation reaches, which [Lister.ListRepositories] lists with it.
// The installation is checked with GitHub first, as [Client.MintInstallationToken]
// checks it. It keeps nothing.
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
	return c.mintFor(ctx, Request{AppID: appID, Key: key, InstallationID: installationID, Permissions: map[string]string{"metadata": "read"}})
}

// mintFor mints the token req asks for, once its installation is checked: limited to
// its repositories, or to none when it names none, and to its permissions. req is
// checked already.
func (c Client) mintFor(ctx context.Context, req Request) (InstallationToken, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	jwt, err := AppJWT(req.AppID, req.Key, now())
	if err != nil {
		return InstallationToken{}, err
	}
	if err := c.checkInstallation(ctx, jwt, req.InstallationID, req.Repositories); err != nil {
		return InstallationToken{}, err
	}
	var got struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	body := map[string]any{"permissions": req.Permissions}
	if len(req.Repositories) > 0 {
		names := make([]string, len(req.Repositories))
		for i, r := range req.Repositories {
			names[i] = r.Name
		}
		body["repositories"] = names
	}
	const minting = "minting the installation token"
	if err := c.call(ctx, minting, http.MethodPost, "/app/installations/"+strconv.FormatInt(req.InstallationID, 10)+"/access_tokens", jwt, body, http.StatusCreated, &got); err != nil {
		var answered *answerError
		if errors.As(err, &answered) && answered.redirect() {
			return InstallationToken{}, errMintRedirected
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
	return InstallationToken{Token: got.Token, ExpiresAt: expires.UTC()}, nil
}
