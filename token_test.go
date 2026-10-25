package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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

// TestMintInstallationTokenAsksForRepositoriesByID mints a token for a repository the
// adapter knows by its id alone, and checks the installation is checked first and the
// mint's body names the repository by id, repository_ids, with the permissions and no
// repositories by name.
func TestMintInstallationTokenAsksForRepositoriesByID(t *testing.T) {
	f := &fakeGitHub{accounts: map[int64]string{7: "acme"}}
	c := serve(t, f)
	tok, err := c.MintInstallationToken(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, RepositoryIDs: []int64{1296269}, Permissions: map[string]string{"issues": "write"}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(f.mint)
	if string(got) != `{"permissions":{"issues":"write"},"repository_ids":[1296269]}` {
		t.Errorf("the mint requested %s", got)
	}
	if strings.Join(f.checks, " ") != "/app/installations/7" || f.mintPath != "/app/installations/7/access_tokens" || len(f.lookups) != 0 || tok.Token != fakeToken {
		t.Errorf("checks %v, mint %s, lookups %v, token %v", f.checks, f.mintPath, f.lookups, tok)
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
		{"a repository id of 0", Request{AppID: appID, Key: key(t), InstallationID: 7, RepositoryIDs: []int64{0}, Permissions: issues}, "a repository's id is not one"},
		{"a negative repository id", Request{AppID: appID, Key: key(t), InstallationID: 7, RepositoryIDs: []int64{-1}, Permissions: issues}, "a repository's id is not one"},
		{"a repository id that is not one among ones that are", Request{AppID: appID, Key: key(t), InstallationID: 7, RepositoryIDs: []int64{1296269, 0}, Permissions: issues}, "a repository's id is not one"},
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

// TestMintListingTokenAsksForMetadataAndContentsRead mints the token a listing of the
// installation's repositories reads with, and checks the mint names no repository, no
// repository_ids among them, and asks for metadata read and contents read alone, after
// the installation is checked.
func TestMintListingTokenAsksForMetadataAndContentsRead(t *testing.T) {
	f := &fakeGitHub{accounts: map[int64]string{7: "acme"}}
	c := serve(t, f)
	tok, err := c.MintListingToken(context.Background(), appID, key(t), 7)
	if err != nil || tok.Token != fakeToken {
		t.Fatalf("%v %v", tok, err)
	}
	got, _ := json.Marshal(f.mint)
	if string(got) != `{"permissions":{"contents":"read","metadata":"read"}}` || strings.Join(f.checks, " ") != "/app/installations/7" {
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

// TestACheckGitHubAnswers404ForWrapsErrInstallationGone has GitHub answer the
// installation's check 404, and checks a mint for a repository and a listing's mint
// each wrap ErrMintRefused and ErrInstallationGone, say so, and ask for no token; that a
// 401 to the check wraps neither; and that a run's token, [Client.Mint], still says the
// installation is not the owners'.
func TestACheckGitHubAnswers404ForWrapsErrInstallationGone(t *testing.T) {
	const gone = "GitHub refuses to mint the installation token: GitHub answers 404 for the installation under the App's token, as for an installation deleted"
	f := &fakeGitHub{accounts: map[int64]string{}}
	c := serve(t, f)
	_, err := c.MintInstallationToken(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, RepositoryIDs: []int64{1296269}, Permissions: map[string]string{"issues": "read"}})
	if err == nil || err.Error() != gone || !errors.Is(err, ErrMintRefused) || !errors.Is(err, ErrInstallationGone) || errors.Is(err, ErrSuspended) || f.mintPath != "" {
		t.Errorf("a repository's token: err %v, minted at %q", err, f.mintPath)
	}
	_, err = c.MintListingToken(context.Background(), appID, key(t), 7)
	if err == nil || err.Error() != gone || !errors.Is(err, ErrMintRefused) || !errors.Is(err, ErrInstallationGone) || f.mintPath != "" {
		t.Errorf("a listing's token: err %v, minted at %q", err, f.mintPath)
	}
	repos, _ := ParseRepositories("acme/widgets")
	if _, err := c.Mint(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos}); err == nil || err != errNotTheOwners || errors.Is(err, ErrInstallationGone) {
		t.Errorf("a run's token: err %v", err)
	}
	f = &fakeGitHub{accounts: map[int64]string{7: "acme"}, checkStatus: 401}
	c = serve(t, f)
	_, err = c.MintListingToken(context.Background(), appID, key(t), 7)
	if err == nil || err.Error() != "checking installation_id: GitHub answered 401: Bad credentials" || errors.Is(err, ErrMintRefused) || errors.Is(err, ErrInstallationGone) || !Unauthorized(err) || f.mintPath != "" {
		t.Errorf("a 401: err %v, minted at %q", err, f.mintPath)
	}
}

// TestASuspendedInstallationIsRefusedBeforeTheMint has GitHub answer the installation's
// check with suspended_at set, and checks a mint for a repository and a listing's mint
// each fail with ErrSuspended, which does not wrap ErrMintRefused, and ask for no token;
// that an installation whose suspended_at is null is minted for; and that a run's token,
// [Client.Mint], still goes on to GitHub's mint.
func TestASuspendedInstallationIsRefusedBeforeTheMint(t *testing.T) {
	const suspended = "GitHub answers that the installation is suspended, so no installation token is minted for it"
	f := &fakeGitHub{accounts: map[int64]string{7: "acme", 8: "acme"}, suspended: map[int64]bool{7: true}}
	c := serve(t, f)
	_, err := c.MintInstallationToken(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, RepositoryIDs: []int64{1296269}, Permissions: map[string]string{"issues": "read"}})
	if err == nil || err.Error() != suspended || !errors.Is(err, ErrSuspended) || errors.Is(err, ErrMintRefused) || f.mintPath != "" {
		t.Errorf("a repository's token: err %v, minted at %q", err, f.mintPath)
	}
	_, err = c.MintListingToken(context.Background(), appID, key(t), 7)
	if !errors.Is(err, ErrSuspended) || errors.Is(err, ErrMintRefused) || f.mintPath != "" {
		t.Errorf("a listing's token: err %v, minted at %q", err, f.mintPath)
	}
	if tok, err := c.MintListingToken(context.Background(), appID, key(t), 8); err != nil || tok.Token != fakeToken || f.mintPath != "/app/installations/8/access_tokens" {
		t.Errorf("not suspended: %v, %v, minted at %q", tok, err, f.mintPath)
	}
	repos, _ := ParseRepositories("acme/widgets")
	if ans, err := c.Mint(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos}); err != nil || ans.Token != fakeToken || f.mintPath != "/app/installations/7/access_tokens" {
		t.Errorf("a run's token: %v, minted at %q", err, f.mintPath)
	}
}

// TestAMintByIDGitHubAnswers422WrapsErrRepositoryRefused has GitHub answer a mint 422,
// 404 and 403, and checks only a 422 to a mint by repository_ids wraps
// ErrRepositoryRefused, after ErrMintRefused, with GitHub's message after it; a 422 to a
// mint by name and a 404 by id wrap ErrMintRefused alone; and a 403 wraps neither, nor
// ErrSuspended.
func TestAMintByIDGitHubAnswers422WrapsErrRepositoryRefused(t *testing.T) {
	const message = "There is at least one repository that does not exist or is not accessible to the parent installation."
	repos, _ := ParseRepositories("acme/widgets")
	byID := Request{AppID: appID, Key: key(t), InstallationID: 7, RepositoryIDs: []int64{1296269}, Permissions: map[string]string{"issues": "read"}}
	byName := Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos, Permissions: map[string]string{"issues": "read"}}
	for _, tc := range []struct {
		name            string
		req             Request
		status          int
		refused, byRepo bool
	}{
		{"422 by id", byID, 422, true, true},
		{"422 by name", byName, 422, true, false},
		{"404 by id", byID, 404, true, false},
		{"403 by id", byID, 403, false, false},
	} {
		f := &fakeGitHub{accounts: map[int64]string{7: "acme"}, status: tc.status, message: message}
		c := serve(t, f)
		_, err := c.MintInstallationToken(context.Background(), tc.req)
		if err == nil || errors.Is(err, ErrMintRefused) != tc.refused || errors.Is(err, ErrRepositoryRefused) != tc.byRepo || errors.Is(err, ErrSuspended) || errors.Is(err, ErrInstallationGone) {
			t.Errorf("%s: err %v", tc.name, err)
		}
		if tc.byRepo && err.Error() != "GitHub refuses to mint the installation token: GitHub answers 422 to a token for the repository alone, as for a repository the installation does not reach, or a permission it does not grant: minting the installation token: GitHub answered 422: "+message {
			t.Errorf("%s: err %v", tc.name, err)
		}
		if tc.status == 403 && !Forbidden(err) || tc.status != 403 && Forbidden(err) {
			t.Errorf("%s: Forbidden says %v", tc.name, Forbidden(err))
		}
	}
}

// TestCheckedSaysEach200ToTheInstallationsCheck has GitHub answer the installation's
// check 200, then the mint 500; the check 200 with suspended_at set; the check 200 for
// an installation of another account; the check 404; and the check 401: Checked is
// called with the installation's id for each 200 alone, whatever follows it.
func TestCheckedSaysEach200ToTheInstallationsCheck(t *testing.T) {
	repos, _ := ParseRepositories("acme/widgets")
	for _, tc := range []struct {
		name    string
		f       *fakeGitHub
		checked bool
	}{
		{"a 200, then a mint's 500", &fakeGitHub{accounts: map[int64]string{7: "acme"}, status: 500}, true},
		{"a suspension", &fakeGitHub{accounts: map[int64]string{7: "acme"}, suspended: map[int64]bool{7: true}}, true},
		{"another account's", &fakeGitHub{accounts: map[int64]string{7: "otherlogin"}}, true},
		{"a 404", &fakeGitHub{accounts: map[int64]string{}}, false},
		{"a 401", &fakeGitHub{accounts: map[int64]string{7: "acme"}, checkStatus: 401}, false},
	} {
		c := serve(t, tc.f)
		var got []int64
		c.Checked = func(id int64) { got = append(got, id) }
		c.MintInstallationToken(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos, Permissions: map[string]string{"issues": "read"}})
		if want := map[bool][]int64{true: {7}, false: nil}[tc.checked]; !slices.Equal(got, want) {
			t.Errorf("%s: Checked with %v", tc.name, got)
		}
	}
}
