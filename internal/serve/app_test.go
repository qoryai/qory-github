package serve

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qoryai/qory-github"
)

// testKeptApp is what appFile says of the App the tests keep.
func testKeptApp() keptApp {
	return keptApp{AppID: setupAppID, AppSlug: setupSlug, ClientID: setupClientID, Owner: "acme", OwnerKind: github.AccountOrganization, WebhookActive: true, WebhookSecretConfirmed: true}
}

// keepTestApp keeps the test App in a new state directory, and returns it.
func keepTestApp(t *testing.T, k keptApp) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := keepApp(dir, k, []byte(strings.TrimSpace(appKeyPEM())), []byte(setupHookSecret), []byte(setupClientSecret)); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestAKeptAppIsReadBackWhole keeps an App and reads it back as a start does: every
// file 0600, app.json last, and each value as it was kept.
func TestAKeptAppIsReadBackWhole(t *testing.T) {
	dir := keepTestApp(t, testKeptApp())
	a, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.id != "777001" || a.numericID != setupAppID || a.slug != setupSlug || a.clientID != setupClientID || !a.key.Equal(appKey()) || string(a.webhookSecret) != setupHookSecret ||
		string(a.clientSecret) != setupClientSecret || !a.webhookActive || !a.confirmed || !a.kept || a.owner != "acme" || a.ownerKind != github.AccountOrganization {
		t.Errorf("read back %+v", a)
	}
	for _, name := range []string{appFile, appKeyFile, appWebhookFile, appClientFile} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", name, info, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, appFile))
	if strings.Contains(string(b), setupHookSecret) || strings.Contains(string(b), setupClientSecret) || strings.Contains(string(b), "PRIVATE") {
		t.Errorf("app.json holds a secret: %s", b)
	}
	if got := a.settingsURL("https://github.com"); got != "https://github.com/organizations/acme/settings/apps/qory-acme" {
		t.Errorf("the settings page is %s", got)
	}
	// A rewrite of app.json that did not finish leaves app.json.tmp beside it, which a
	// start removes.
	writeFile(t, filepath.Join(dir, appTemp), "{", 0o600)
	if _, err := loadApp(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, appTemp)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s is left: %v", appTemp, err)
	}
	// The confirmation of the webhook secret writes app.json again, that alone changed.
	k := testKeptApp()
	k.WebhookSecretConfirmed = false
	dir = keepTestApp(t, k)
	if a, _ := loadApp(dir); a.confirmed {
		t.Fatal("confirmed before the confirmation")
	}
	if err := confirmWebhookSecret(dir); err != nil {
		t.Fatal(err)
	}
	if a, err := loadApp(dir); err != nil || !a.confirmed || string(a.webhookSecret) != setupHookSecret {
		t.Errorf("after the confirmation %+v %v", a, err)
	}
}

// TestAKeptAppThatDoesNotHoldWhatItNamesIsRefused pins the start's refusals of a kept
// App: a secret's file missing or changed, and an app.json not as serve writes it.
func TestAKeptAppThatDoesNotHoldWhatItNamesIsRefused(t *testing.T) {
	for _, name := range []string{appKeyFile, appWebhookFile, appClientFile} {
		dir := keepTestApp(t, testKeptApp())
		os.Remove(filepath.Join(dir, name))
		want := "the App file app.json names " + name + " in the state directory, which is missing or does not hold what app.json names"
		if _, err := loadApp(dir); err == nil || err.Error() != want {
			t.Errorf("%s missing: %v", name, err)
		}
		writeFile(t, filepath.Join(dir, name), "something else\n", 0o600)
		if _, err := loadApp(dir); err == nil || err.Error() != want {
			t.Errorf("%s changed: %v", name, err)
		}
	}
	dir := keepTestApp(t, testKeptApp())
	b, _ := os.ReadFile(filepath.Join(dir, appFile))
	for _, bad := range []string{
		"", "{}", "[]", strings.Replace(string(b), `"app_id": 777001`, `"app_id": 0`, 1),
		strings.Replace(string(b), `"owner_kind": "Organization"`, `"owner_kind": "Bot"`, 1),
		strings.Replace(string(b), `"webhook_active": true,`, ``, 1),
		strings.Replace(string(b), `{`, `{"extra": 1,`, 1),
		string(b) + "{}",
	} {
		os.Remove(filepath.Join(dir, appFile))
		writeFile(t, filepath.Join(dir, appFile), bad, 0o600)
		if _, err := loadApp(dir); err == nil || err.Error() != "the App file app.json does not hold app_id, app_slug, client_id, owner, owner_kind, webhook_active, webhook_secret_confirmed, private_key_sha256, webhook_secret_sha256, client_secret_sha256 as serve writes them" {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// A kept secret that holds what looks like an access key secret or a run key is
	// refused, the file named.
	access := newKey(t)
	for name, tc := range map[string]struct{ hook, client, want string }{
		appWebhookFile: {access.Secret(), setupClientSecret, "the file " + appWebhookFile + " in the state directory holds what looks like an access key secret, qak_, which belongs only where serve keeps its access key: the access key secret setting, or the state directory"},
		appClientFile:  {setupHookSecret, "qrk_-a-pasted-run-key", "the file " + appClientFile + " in the state directory holds what looks like a run key, qrk_, which belongs nowhere in serve's state directory"},
	} {
		d := filepath.Join(t.TempDir(), "state")
		os.Mkdir(d, 0o700)
		if err := keepApp(d, testKeptApp(), []byte(appKeyPEM()), []byte(tc.hook), []byte(tc.client)); err != nil {
			t.Fatal(err)
		}
		if _, err := loadApp(d); err == nil || err.Error() != tc.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	os.Chmod(filepath.Join(dir, appFile), 0o644)
	if _, err := loadApp(dir); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Errorf("an app.json others may read: %v", err)
	}
}

// TestASetupThatDidNotFinishIsCleanedUp pins how a start resolves what a crash in a
// setup's commit left: app.json.tmp half written, or whole beside some of the
// secrets' files, are removed, with the line that says to delete the App on GitHub,
// naming it when app.json.tmp says it; an empty state directory gives no line.
func TestASetupThatDidNotFinishIsCleanedUp(t *testing.T) {
	whole := keepTestApp(t, testKeptApp())
	tmp, _ := os.ReadFile(filepath.Join(whole, appFile))
	for name, tc := range map[string]struct {
		files map[string]string
		named bool
	}{
		"nothing":                         {nil, false},
		"app.json.tmp half written":       {map[string]string{appTemp: string(tmp[:20])}, false},
		"app.json.tmp whole, no secret":   {map[string]string{appTemp: string(tmp)}, true},
		"app.json.tmp and the key":        {map[string]string{appTemp: string(tmp), appKeyFile: appKeyPEM()}, true},
		"app.json.tmp and every secret":   {map[string]string{appTemp: string(tmp), appKeyFile: appKeyPEM(), appWebhookFile: "x\n", appClientFile: "y\n"}, true},
		"a secret's file alone, half one": {map[string]string{appKeyFile: "-----BEGIN"}, false},
	} {
		dir := t.TempDir()
		for f, content := range tc.files {
			writeFile(t, filepath.Join(dir, f), content, 0o600)
		}
		log := &syncBuffer{}
		if err := dropUnfinished(dir, "https://github.com", slog.New(slog.NewJSONHandler(log, nil))); err != nil {
			t.Fatal(err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("%s: left %v", name, entries)
		}
		const line = `"msg":"a setup that did not finish left files in the state directory, which are removed: delete the App it created on GitHub"`
		switch {
		case tc.files == nil && log.String() != "":
			t.Errorf("%s: logged %s", name, log.String())
		case tc.files != nil && !strings.Contains(log.String(), line):
			t.Errorf("%s: the log %s", name, log.String())
		case tc.named != strings.Contains(log.String(), `"app_id":777001,"slug":"qory-acme","settings_url":"https://github.com/organizations/acme/settings/apps/qory-acme"`):
			t.Errorf("%s: names the App %v: %s", name, tc.named, log.String())
		}
		noSetupLeak(t, log.String())
	}
}

// TestAFailedCommitKeepsNoApp pins that a commit that fails at its rename, the step
// that keeps the App, or because app.json is there already, leaves no file of it.
func TestAFailedCommitKeepsNoApp(t *testing.T) {
	dir := t.TempDir()
	rename = func(string, string) error { return errors.New("no rename") }
	err := keepApp(dir, testKeptApp(), []byte(appKeyPEM()), []byte(setupHookSecret), []byte(setupClientSecret))
	rename = os.Rename
	if err == nil {
		t.Fatal("kept")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("left %v", entries)
	}
	dir = keepTestApp(t, testKeptApp())
	before, _ := os.ReadFile(filepath.Join(dir, appFile))
	k := testKeptApp()
	k.AppSlug = "qory-other"
	if err := keepApp(dir, k, []byte(appKeyPEM()), []byte("another webhook secret"), []byte("another client secret")); err == nil {
		t.Fatal("kept over app.json")
	}
	if after, _ := os.ReadFile(filepath.Join(dir, appFile)); string(after) != string(before) {
		t.Errorf("app.json changed: %s", after)
	}
	// The kept App's secrets' files are as they were: a start reads it whole.
	if a, err := loadApp(dir); err != nil || a.slug != setupSlug || string(a.webhookSecret) != setupHookSecret || string(a.clientSecret) != setupClientSecret {
		t.Errorf("the kept App after a refused commit: %+v %v", a, err)
	}
}

// TestTheRenameKeepsTheAppAndComesLast pins keepApp's order: app.json.tmp, then the
// three secrets' files, then the rename onto app.json, the step that keeps the App;
// a write that fails after app.json.tmp leaves no file, so the next start waits for a
// setup.
func TestTheRenameKeepsTheAppAndComesLast(t *testing.T) {
	var steps []string
	writeKept = func(path string, b []byte, what string) error {
		steps = append(steps, "write "+filepath.Base(path))
		return writeNew(path, b, what)
	}
	rename = func(from, to string) error {
		steps = append(steps, "rename "+filepath.Base(from)+" "+filepath.Base(to))
		return os.Rename(from, to)
	}
	t.Cleanup(func() { writeKept, rename = writeNew, os.Rename })
	dir := t.TempDir()
	if err := keepApp(dir, testKeptApp(), []byte(appKeyPEM()), []byte(setupHookSecret), []byte(setupClientSecret)); err != nil {
		t.Fatal(err)
	}
	want := []string{"write " + appTemp, "write " + appKeyFile, "write " + appWebhookFile, "write " + appClientFile, "rename " + appTemp + " " + appFile}
	if strings.Join(steps, "; ") != strings.Join(want, "; ") {
		t.Errorf("the steps %v", steps)
	}
	for _, failing := range []string{appKeyFile, appWebhookFile, appClientFile} {
		writeKept = func(path string, b []byte, what string) error {
			if filepath.Base(path) == failing {
				return errors.New("no write")
			}
			return writeNew(path, b, what)
		}
		dir := t.TempDir()
		if err := keepApp(dir, testKeptApp(), []byte(appKeyPEM()), []byte(setupHookSecret), []byte(setupClientSecret)); err == nil {
			t.Fatalf("%s: kept", failing)
		}
		if hasApp(dir) {
			t.Errorf("%s: app.json is left", failing)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("%s: left %v", failing, entries)
		}
	}
}

// TestAnAppKeptAtTheRenameIsLeftAsItIs pins that keepApp, finding app.json there at
// the rename, refuses, removes app.json.tmp, and leaves app.json and the secrets'
// files as they are.
func TestAnAppKeptAtTheRenameIsLeftAsItIs(t *testing.T) {
	dir := t.TempDir()
	const kept = "the kept App's app.json"
	writeKept = func(path string, b []byte, what string) error {
		if err := writeNew(path, b, what); err != nil {
			return err
		}
		if filepath.Base(path) == appClientFile {
			// Another commit keeps an App meanwhile.
			writeFile(t, filepath.Join(dir, appFile), kept, 0o600)
		}
		return nil
	}
	t.Cleanup(func() { writeKept = writeNew })
	if err := keepApp(dir, testKeptApp(), []byte(appKeyPEM()), []byte(setupHookSecret), []byte(setupClientSecret)); !errors.Is(err, os.ErrExist) {
		t.Fatalf("kept over app.json: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, appFile)); string(b) != kept {
		t.Errorf("app.json is %q", b)
	}
	for _, name := range []string{appKeyFile, appWebhookFile, appClientFile} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, appTemp)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s is left: %v", appTemp, err)
	}
}
