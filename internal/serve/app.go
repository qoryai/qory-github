package serve

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/ownerfile"
)

// The files of the App serve keeps in the state directory once its App setup has
// created one, see [appSetup], each 0600 and the user's that serve runs as: appFile
// holds what is known of the App, which no secret is, and the SHA-256 of each of the
// three files that hold its secrets, appKeyFile its private key, appWebhookFile its
// webhook secret and appClientFile its client secret, each with one line break at its
// end, as the settings' files hold them. appTemp is appFile while the App is kept,
// written before the secrets' files and renamed onto appFile after them, so appFile
// is there only once every file is whole, and appTemp names, after a crash, the App a
// setup that did not finish created on GitHub, see [dropUnfinished]. The App belongs
// to the GitHub account it was created for and to the state directory, not to the
// adapter's record in Qory Apiary: a re-enrolment that makes the adapter a new record
// keeps them, see [recordState].
const (
	appFile        = "app.json"
	appTemp        = "app.json.tmp"
	appKeyFile     = "app-private-key.pem"
	appWebhookFile = "app-webhook-secret"
	appClientFile  = "app-client-secret"
)

// maxAppFile is the most appFile may hold; one byte more is read to tell a larger file
// apart. What serve writes there is far shorter.
const maxAppFile = 64 << 10

// app is the GitHub App serve runs with: the one the settings give, or the one kept in
// the state directory, see [loadApp].
type app struct {
	// id is the App's id as the settings give it, its numeric id or its client id;
	// slug, clientID, key, webhookSecret and clientSecret are its slug, client id,
	// private key, webhook secret and client secret.
	id            string
	slug          string
	clientID      string
	key           *rsa.PrivateKey
	webhookSecret []byte
	clientSecret  []byte
	// webhookActive is whether the App's webhook was created active: true for the
	// settings' App, which serve does not know otherwise.
	webhookActive bool
	// kept is whether the App is kept in the state directory. For a kept App,
	// numericID is its numeric id, owner and ownerKind the account that owns it, its
	// login and [github.AccountOrganization] or [github.AccountUser], and confirmed
	// whether GitHub confirmed its webhook secret, see [appSetup.created].
	kept      bool
	numericID int64
	owner     string
	ownerKind string
	confirmed bool
}

// settingsURL is the kept App's settings page on GitHub's website web, see
// [github.AppSettingsURL].
func (a *app) settingsURL(web string) string {
	return github.AppSettingsURL(web, orgOf(a.owner, a.ownerKind), a.slug)
}

// orgOf is the organisation the account login of kind is, or nothing for a user.
func orgOf(login, kind string) string {
	if kind == github.AccountOrganization {
		return login
	}
	return ""
}

// keptApp is appFile's JSON: the App's numeric id, slug and client id, the account
// that owns it, whether its webhook was created active and whether GitHub confirmed
// its webhook secret, and the SHA-256 of each of its secrets' files, in hex.
type keptApp struct {
	AppID                  int64  `json:"app_id"`
	AppSlug                string `json:"app_slug"`
	ClientID               string `json:"client_id"`
	Owner                  string `json:"owner"`
	OwnerKind              string `json:"owner_kind"`
	WebhookActive          bool   `json:"webhook_active"`
	WebhookSecretConfirmed bool   `json:"webhook_secret_confirmed"`
	PrivateKeySHA256       string `json:"private_key_sha256"`
	WebhookSecretSHA256    string `json:"webhook_secret_sha256"`
	ClientSecretSHA256     string `json:"client_secret_sha256"`
}

// The shapes of appFile's members: a GitHub account's login, 39 characters at most,
// letters and digits with single hyphens between them, and a SHA-256 in lower-case
// hex.
var (
	loginShape  = regexp.MustCompile(`^[A-Za-z0-9]+(-[A-Za-z0-9]+)*$`)
	digestShape = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// errAppShape is the error of an appFile that does not hold what serve writes there.
var errAppShape = errors.New("the App file app.json does not hold app_id, app_slug, client_id, owner, owner_kind, webhook_active, webhook_secret_confirmed, private_key_sha256, webhook_secret_sha256, client_secret_sha256 as serve writes them")

// parseKeptApp reads appFile's JSON b: one object with every member of [keptApp] and
// no other, each of its shape.
func parseKeptApp(b []byte) (keptApp, error) {
	var doc struct {
		AppID                  *int64  `json:"app_id"`
		AppSlug                *string `json:"app_slug"`
		ClientID               *string `json:"client_id"`
		Owner                  *string `json:"owner"`
		OwnerKind              *string `json:"owner_kind"`
		WebhookActive          *bool   `json:"webhook_active"`
		WebhookSecretConfirmed *bool   `json:"webhook_secret_confirmed"`
		PrivateKeySHA256       *string `json:"private_key_sha256"`
		WebhookSecretSHA256    *string `json:"webhook_secret_sha256"`
		ClientSecretSHA256     *string `json:"client_secret_sha256"`
	}
	if !strictObject(b, &doc) || doc.AppID == nil || doc.AppSlug == nil || doc.ClientID == nil || doc.Owner == nil || doc.OwnerKind == nil ||
		doc.WebhookActive == nil || doc.WebhookSecretConfirmed == nil || doc.PrivateKeySHA256 == nil || doc.WebhookSecretSHA256 == nil || doc.ClientSecretSHA256 == nil {
		return keptApp{}, errAppShape
	}
	k := keptApp{
		AppID: *doc.AppID, AppSlug: *doc.AppSlug, ClientID: *doc.ClientID, Owner: *doc.Owner, OwnerKind: *doc.OwnerKind,
		WebhookActive: *doc.WebhookActive, WebhookSecretConfirmed: *doc.WebhookSecretConfirmed,
		PrivateKeySHA256: *doc.PrivateKeySHA256, WebhookSecretSHA256: *doc.WebhookSecretSHA256, ClientSecretSHA256: *doc.ClientSecretSHA256,
	}
	if k.AppID <= 0 || github.CheckSlug(k.AppSlug) != nil || !appIDShape.MatchString(k.ClientID) || len(k.Owner) > 39 || !loginShape.MatchString(k.Owner) ||
		(k.OwnerKind != github.AccountOrganization && k.OwnerKind != github.AccountUser) ||
		!digestShape.MatchString(k.PrivateKeySHA256) || !digestShape.MatchString(k.WebhookSecretSHA256) || !digestShape.MatchString(k.ClientSecretSHA256) {
		return keptApp{}, errAppShape
	}
	return k, nil
}

// digest is the SHA-256 of b in lower-case hex.
func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// hasApp reports whether the state directory dir holds appFile, or something at its
// name that [loadApp] then reads, and refuses when it is no such file.
func hasApp(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, appFile))
	return !errors.Is(err, fs.ErrNotExist)
}

// loadApp reads the App kept in the state directory dir: appFile, read as
// [ownerfile.ReadFile] reads a file, and each of the three files that hold its secrets,
// read as the settings' files that hold them are, each of which must be there and hold
// the bytes whose SHA-256 appFile names, or the error names it; then the private key,
// the webhook secret and the client secret are each checked as the settings' are. An
// appTemp beside appFile is a rewrite of appFile that did not finish, see [rewriteApp],
// which [confirmWebhookSecret] and [keepSlug] make, and is removed.
func loadApp(dir string) (*app, error) {
	b, err := ownerfile.ReadFile(filepath.Join(dir, appFile), maxAppFile, "the App file", "an App")
	if err != nil {
		return nil, err
	}
	k, err := parseKeptApp(b)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(filepath.Join(dir, appTemp)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("the state directory: %w", err)
	}
	read := func(name string, max int, holds, sum string) ([]byte, secretSource, error) {
		c := secretSource{file: filepath.Join(dir, name), in: "the file " + name + " in the state directory", put: "the file", state: true}
		if _, err := os.Lstat(c.file); errors.Is(err, fs.ErrNotExist) {
			return nil, c, fmt.Errorf("the App file app.json names %s in the state directory, which is missing or does not hold what app.json names", name)
		}
		b, err := c.read(max, holds)
		if err != nil {
			return nil, c, err
		}
		if digest(b) != sum {
			return nil, c, fmt.Errorf("the App file app.json names %s in the state directory, which is missing or does not hold what app.json names", name)
		}
		return b, c, nil
	}
	a := &app{
		id: strconv.FormatInt(k.AppID, 10), slug: k.AppSlug, clientID: k.ClientID, webhookActive: k.WebhookActive,
		kept: true, numericID: k.AppID, owner: k.Owner, ownerKind: k.OwnerKind, confirmed: k.WebhookSecretConfirmed,
	}
	pemBytes, c, err := read(appKeyFile, github.MaxKeyFile, "a key", k.PrivateKeySHA256)
	if err != nil {
		return nil, err
	}
	if err := c.noKeyIn(pemBytes); err != nil {
		return nil, err
	}
	if a.key, err = github.ParseKey(pemBytes); err != nil {
		return nil, err
	}
	b, c, err = read(appWebhookFile, maxSecretFile, "a webhook secret", k.WebhookSecretSHA256)
	if err != nil {
		return nil, err
	}
	if a.webhookSecret, err = checkWebhookSecret(b, c); err != nil {
		return nil, err
	}
	b, c, err = read(appClientFile, maxClientSecretFile, "a client secret", k.ClientSecretSHA256)
	if err != nil {
		return nil, err
	}
	if a.clientSecret, err = checkClientSecret(b, c); err != nil {
		return nil, err
	}
	return a, nil
}

// unfinishedFiles are the files a setup that did not finish may leave in the state
// directory without appFile, in the order they are written.
var unfinishedFiles = []string{appTemp, appKeyFile, appWebhookFile, appClientFile}

// dropUnfinished removes, from the state directory dir that holds no appFile, the files
// a setup that did not finish left there, if any, and logs on log that the App it
// created on GitHub is to be deleted: by its id, slug and settings page on GitHub's
// website web when appTemp, which is written first, was written whole.
func dropUnfinished(dir, web string, log *slog.Logger) error {
	var found bool
	for _, name := range unfinishedFiles {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, fs.ErrNotExist) {
			found = true
		}
	}
	if !found {
		return nil
	}
	var attrs []any
	if b, err := ownerfile.ReadFile(filepath.Join(dir, appTemp), maxAppFile, "the App file", "an App"); err == nil {
		if k, err := parseKeptApp(b); err == nil {
			a := app{slug: k.AppSlug, owner: k.Owner, ownerKind: k.OwnerKind}
			attrs = append(attrs, slog.Int64("app_id", k.AppID), slog.String("slug", k.AppSlug), slog.String("settings_url", a.settingsURL(web)))
		}
	}
	log.Warn("a setup that did not finish left files in the state directory, which are removed: delete the App it created on GitHub", attrs...)
	return removeUnfinished(dir)
}

// removeUnfinished removes the files of [unfinishedFiles] from the state directory dir,
// those that are there, and syncs it.
func removeUnfinished(dir string) error {
	for _, name := range unfinishedFiles {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("the state directory: %w", err)
		}
	}
	syncDir(dir)
	return nil
}

// writeKept writes each file of an App [keepApp] keeps, as [writeNew] does.
var writeKept = writeNew

// keepApp keeps the App k describes in the state directory dir, its private key in PEM
// pemBytes, its webhook secret and its client secret, when dir keeps no App: it
// removes what a setup that did not finish left, then writes appTemp, then the three
// files that hold the secrets, each with one line break at its end, k naming the
// SHA-256 of each file's bytes, then syncs the directory and renames appTemp onto
// appFile, the step that keeps the App and the last, and syncs the directory again.
// Every file is written as [writeNew] writes one. When a write or the rename fails, it
// removes the files it wrote, and no App is kept. When appFile is there at the rename,
// it refuses and removes appTemp alone: the files that hold the secrets, which this
// call wrote, have the names of the files appFile names, and it leaves them as they
// are.
func keepApp(dir string, k keptApp, pemBytes, webhookSecret, clientSecret []byte) error {
	if hasApp(dir) {
		return fmt.Errorf("%s: %w", appFile, fs.ErrExist)
	}
	if err := removeUnfinished(dir); err != nil {
		return err
	}
	files := []struct {
		name string
		b    []byte
	}{
		{appKeyFile, append(append([]byte(nil), pemBytes...), '\n')},
		{appWebhookFile, append(append([]byte(nil), webhookSecret...), '\n')},
		{appClientFile, append(append([]byte(nil), clientSecret...), '\n')},
	}
	k.PrivateKeySHA256, k.WebhookSecretSHA256, k.ClientSecretSHA256 = digest(files[0].b), digest(files[1].b), digest(files[2].b)
	doc, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return err
	}
	fail := func(err error) error {
		removeUnfinished(dir)
		return err
	}
	if err := writeKept(filepath.Join(dir, appTemp), append(doc, '\n'), "the App file"); err != nil {
		return fail(err)
	}
	for _, f := range files {
		if err := writeKept(filepath.Join(dir, f.name), f.b, "the file "+f.name+" in the state directory"); err != nil {
			return fail(err)
		}
	}
	syncDir(dir)
	if hasApp(dir) {
		os.Remove(filepath.Join(dir, appTemp))
		return fmt.Errorf("%s: %w", appFile, fs.ErrExist)
	}
	if err := rename(filepath.Join(dir, appTemp), filepath.Join(dir, appFile)); err != nil {
		return fail(err)
	}
	syncDir(dir)
	return nil
}

// confirmWebhookSecret records in the state directory dir that GitHub confirmed the
// kept App's webhook secret: appFile written again, as [rewriteApp] writes it, with
// webhook_secret_confirmed true and nothing else changed.
func confirmWebhookSecret(dir string) error {
	return rewriteApp(dir, func(k *keptApp) { k.WebhookSecretConfirmed = true })
}

// rewriteApp writes appFile in the state directory dir again with what change changes
// in it: appFile read and parsed as [loadApp] reads it, then written to appTemp, a new
// file written as [writeNew] writes one, which is renamed onto appFile, and the
// directory synced. When the write or the rename fails, appFile is left as it was.
func rewriteApp(dir string, change func(*keptApp)) error {
	b, err := ownerfile.ReadFile(filepath.Join(dir, appFile), maxAppFile, "the App file", "an App")
	if err != nil {
		return err
	}
	k, err := parseKeptApp(b)
	if err != nil {
		return err
	}
	change(&k)
	doc, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return err
	}
	temp := filepath.Join(dir, appTemp)
	os.Remove(temp)
	if err := writeNew(temp, append(doc, '\n'), "the App file"); err != nil {
		return err
	}
	if err := rename(temp, filepath.Join(dir, appFile)); err != nil {
		os.Remove(temp)
		return err
	}
	syncDir(dir)
	return nil
}
