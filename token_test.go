package github

import (
	"context"
	"encoding/json"
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
	for _, s := range []string{tok.String(), fmt.Sprint(tok), fmt.Sprintf("%v", tok)} {
		if strings.Contains(s, fakeToken) || s != "an installation token that expires at 2026-09-25T21:00:00Z" {
			t.Errorf("printed: %s", s)
		}
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

// TestMintInstallationTokenChecksTheInstallationAndNeverSaysTheToken mints for an
// installation of another account, which is refused before the mint, and with a mint
// GitHub refuses, whose error carries no secret.
func TestMintInstallationTokenChecksTheInstallationAndNeverSaysTheToken(t *testing.T) {
	repos, _ := ParseRepositories("acme/widgets")
	f := &fakeGitHub{accounts: map[int64]string{7: "otherlogin"}}
	c := serve(t, f)
	_, err := c.MintInstallationToken(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos, Permissions: map[string]string{"issues": "write"}})
	if err != errNotTheOwners || f.mintPath != "" {
		t.Errorf("err %v, minted at %q", err, f.mintPath)
	}
	f = &fakeGitHub{accounts: map[int64]string{7: "acme"}, status: 401}
	c = serve(t, f)
	_, err = c.MintInstallationToken(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos, Permissions: map[string]string{"issues": "write"}})
	if err == nil || err.Error() != "minting the installation token: GitHub answered 401: Bad credentials" {
		t.Errorf("err %v", err)
	}
}
