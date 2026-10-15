package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestMintInstallationTokenAsksForTheRepositoriesAndPermissionsAlone mints a token that
// reads issues and checks the request GitHub receives: the installation checked first,
// then the mint at the installation, its body the repositories' names and the
// permissions and nothing else, both with the App's token.
func TestMintInstallationTokenAsksForTheRepositoriesAndPermissionsAlone(t *testing.T) {
	f := &fakeGitHub{accounts: map[int64]string{7: "acme"}}
	c := serve(t, f)
	repos, _ := ParseRepositories("acme/widgets,acme/gadgets")
	tok, err := c.MintInstallationToken(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos, Permissions: map[string]string{"issues": "read"}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(f.mint)
	if string(got) != `{"permissions":{"issues":"read"},"repositories":["widgets","gadgets"]}` {
		t.Errorf("the mint requested %s", got)
	}
	if strings.Join(f.checks, " ") != "/app/installations/7" || f.mintPath != "/app/installations/7/access_tokens" || len(f.lookups) != 0 {
		t.Errorf("checks %v, mint %s, lookups %v", f.checks, f.mintPath, f.lookups)
	}
	for _, h := range f.auth {
		verifyJWT(t, strings.TrimPrefix(h, "Bearer "))
	}
	if tok.Token != fakeToken || !tok.ExpiresAt.Equal(time.Date(2026, 9, 25, 21, 0, 0, 0, time.UTC)) {
		t.Errorf("token %+v", tok)
	}
	for _, s := range []string{tok.String(), fmt.Sprint(tok), fmt.Sprintf("%v", tok), fmt.Sprintf("%+v", tok), fmt.Sprintf("%#v", tok), fmt.Sprintf("%#v", &tok)} {
		if strings.Contains(s, fakeToken) || s != "an installation token that expires at 2026-09-25T21:00:00Z" {
			t.Errorf("printed: %s", s)
		}
	}
	b, err := json.Marshal(tok)
	if err != nil || strings.Contains(string(b), fakeToken) || string(b) != `{"ExpiresAt":"2026-09-25T21:00:00Z"}` {
		t.Errorf("JSON %s, %v", b, err)
	}
}

// TestMintInstallationTokenRefusesBeforeAnythingIsSent checks every request the
// function refuses, and that none reaches GitHub.
func TestMintInstallationTokenRefusesBeforeAnythingIsSent(t *testing.T) {
	f := &fakeGitHub{accounts: map[int64]string{7: "acme"}}
	c := serve(t, f)
	repos, _ := ParseRepositories("acme/widgets")
	issues := map[string]string{"issues": "read"}
	for _, tc := range []struct {
		name string
		req  Request
		want string
	}{
		{"no installation", Request{AppID: appID, Key: key(t), Repositories: repos, Permissions: issues}, "no installation; an installation token is one installation's"},
		{"no repository", Request{AppID: appID, Key: key(t), InstallationID: 7, Permissions: issues}, "no repository"},
		{"a dot segment", Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: []Repository{{"acme", ".."}}, Permissions: issues}, `"acme/.." is not owner/name`},
		{"no permission", Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos}, "no permission is set, which GitHub reads as every permission the installation has; set the ones the token needs"},
		{"admin", Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos, Permissions: map[string]string{"issues": "admin"}}, "the permission issues is neither read nor write"},
		{"administration", Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos, Permissions: map[string]string{"administration": "read"}}, `"administration" is not a permission`},
		{"no key", Request{AppID: appID, InstallationID: 7, Repositories: repos, Permissions: issues}, "no private key"},
	} {
		_, err := c.MintInstallationToken(context.Background(), tc.req)
		if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %s", tc.name, err, tc.want)
		}
	}
	if len(f.auth) != 0 {
		t.Errorf("%d requests reached GitHub", len(f.auth))
	}
}

// TestAMintGitHubRefusesForGoodWrapsErrMintRefused has GitHub answer the mint 404 and
// 422, as for an installation gone or a repository it no longer reaches, and checks the
// error wraps ErrMintRefused, and that a 401 or a 500 does not.
func TestAMintGitHubRefusesForGoodWrapsErrMintRefused(t *testing.T) {
	repos, _ := ParseRepositories("acme/widgets")
	for status, want := range map[int]bool{404: true, 422: true, 401: false, 500: false} {
		f := &fakeGitHub{accounts: map[int64]string{7: "acme"}, status: status}
		c := serve(t, f)
		_, err := c.MintInstallationToken(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos, Permissions: map[string]string{"issues": "read"}})
		if err == nil || errors.Is(err, ErrMintRefused) != want {
			t.Errorf("%d: err %v", status, err)
		}
	}
}

// TestMintInstallationTokenChecksTheInstallationAndNeverSaysTheToken mints for an
// installation of another account, which is refused before the mint, and with a mint
// GitHub refuses, whose error carries no secret.
func TestMintInstallationTokenChecksTheInstallationAndNeverSaysTheToken(t *testing.T) {
	repos, _ := ParseRepositories("acme/widgets")
	f := &fakeGitHub{accounts: map[int64]string{7: "otherlogin"}}
	c := serve(t, f)
	_, err := c.MintInstallationToken(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos, Permissions: map[string]string{"issues": "write"}})
	if err == nil || err.Error() != "GitHub refuses to mint the installation token: the installation is not the App's installation on the repositories' owner" || !errors.Is(err, ErrMintRefused) || f.mintPath != "" {
		t.Errorf("err %v, minted at %q", err, f.mintPath)
	}
	f = &fakeGitHub{accounts: map[int64]string{7: "acme"}, status: 401}
	c = serve(t, f)
	_, err = c.MintInstallationToken(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos, Permissions: map[string]string{"issues": "write"}})
	if err == nil || err.Error() != "minting the installation token: GitHub answered 401: Bad credentials" {
		t.Errorf("err %v", err)
	}
}

// TestMintListingTokenAsksForMetadataAlone mints the token a listing of the
// installation's repositories reads with, and checks the mint names no repository and
// asks for metadata read alone, after the installation is checked.
func TestMintListingTokenAsksForMetadataAlone(t *testing.T) {
	f := &fakeGitHub{accounts: map[int64]string{7: "acme"}}
	c := serve(t, f)
	tok, err := c.MintListingToken(context.Background(), appID, key(t), 7)
	if err != nil || tok.Token != fakeToken {
		t.Fatalf("%v %v", tok, err)
	}
	got, _ := json.Marshal(f.mint)
	if string(got) != `{"permissions":{"metadata":"read"}}` || strings.Join(f.checks, " ") != "/app/installations/7" {
		t.Errorf("the mint requested %s, checks %v", got, f.checks)
	}
	for _, id := range []int64{0, -1} {
		if _, err := c.MintListingToken(context.Background(), appID, key(t), id); err == nil {
			t.Errorf("installation %d: no error", id)
		}
	}
	if _, err := c.MintListingToken(context.Background(), appID, nil, 7); err == nil || err.Error() != "no private key" {
		t.Errorf("err %v", err)
	}
}
