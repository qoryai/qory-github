package serve

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
)

// The secrets serve stores in Qory Apiary, by the names the source role of the
// description lists under secrets: secretApp is the JSON of [appEntry], what is known
// of the App besides its secrets, and the other three are the App's private key in
// PEM, its webhook secret and its client secret. serve keeps none of them in the state
// directory: the App setup uploads them, see [Apiary.UploadSecrets], and each start
// reads them back, see [Apiary.Secrets], and keeps them in memory alone.
const (
	secretApp           = "app"
	secretPrivateKey    = "private-key"
	secretWebhookSecret = "webhook-secret"
	secretClientSecret  = "client-secret"
)

// appSecretNames are the names of [secretApp] and the three secrets after it, in the
// order an upload lists them. The source role of the description lists the same names.
var appSecretNames = []string{secretApp, secretPrivateKey, secretWebhookSecret, secretClientSecret}

// app is the GitHub App serve runs with: the one the App setup creates, or the one
// Qory Apiary delivers at a start, see [appOf]. Every value is kept in memory alone.
type app struct {
	// id is numericID in decimal, the App's id as a token's iss contains it; slug and
	// clientID are its slug and client id.
	id        string
	numericID int64
	slug      string
	clientID  string
	// pem is the private key in PEM as GitHub issued it, which an upload sends again,
	// and key the key parsed from it. webhookSecret and clientSecret are the App's
	// webhook secret and client secret.
	pem           []byte
	key           *rsa.PrivateKey
	webhookSecret []byte
	clientSecret  []byte
	// webhookActive is whether the App's webhook was created active. owner and
	// ownerKind are the account that owns the App, its login and
	// [github.AccountOrganization] or [github.AccountUser]. confirmed is whether GitHub
	// confirmed the App's webhook secret, see [appSetup.keep].
	webhookActive bool
	owner         string
	ownerKind     string
	confirmed     bool
}

// Format prints the App as its id and slug alone, with every verb, so no secret of it
// reaches a log line, an error or a test's output.
func (a app) Format(f fmt.State, _ rune) {
	fmt.Fprintf(f, "the App with app_id %s, %s", a.id, a.slug)
}

// settingsURL is the App's settings page on GitHub's website web, see
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

// appEntry is the value of the secret [secretApp], as JSON: the App's numeric id, slug
// and client id, the account that owns it, whether its webhook was created active, and
// whether GitHub confirmed its webhook secret.
type appEntry struct {
	AppID                  int64  `json:"app_id"`
	AppSlug                string `json:"app_slug"`
	ClientID               string `json:"client_id"`
	Owner                  string `json:"owner"`
	OwnerKind              string `json:"owner_kind"`
	WebhookActive          bool   `json:"webhook_active"`
	WebhookSecretConfirmed bool   `json:"webhook_secret_confirmed"`
}

// loginShape is a GitHub account's login, 39 characters at most: letters and digits
// with single hyphens between them.
var loginShape = regexp.MustCompile(`^[A-Za-z0-9]+(-[A-Za-z0-9]+)*$`)

// errAppEntry is the error of a value of [secretApp] that is not what serve uploads.
var errAppEntry = errors.New("the secret app in Qory Apiary does not contain app_id, app_slug, client_id, owner, owner_kind, webhook_active and webhook_secret_confirmed as serve uploads them")

// parseAppEntry reads the value b of [secretApp]: one object with every member of
// [appEntry] and no other, each of its shape.
func parseAppEntry(b []byte) (appEntry, error) {
	var doc struct {
		AppID                  *int64  `json:"app_id"`
		AppSlug                *string `json:"app_slug"`
		ClientID               *string `json:"client_id"`
		Owner                  *string `json:"owner"`
		OwnerKind              *string `json:"owner_kind"`
		WebhookActive          *bool   `json:"webhook_active"`
		WebhookSecretConfirmed *bool   `json:"webhook_secret_confirmed"`
	}
	if !strictObject(b, &doc) || doc.AppID == nil || doc.AppSlug == nil || doc.ClientID == nil || doc.Owner == nil || doc.OwnerKind == nil ||
		doc.WebhookActive == nil || doc.WebhookSecretConfirmed == nil {
		return appEntry{}, errAppEntry
	}
	e := appEntry{
		AppID: *doc.AppID, AppSlug: *doc.AppSlug, ClientID: *doc.ClientID, Owner: *doc.Owner, OwnerKind: *doc.OwnerKind,
		WebhookActive: *doc.WebhookActive, WebhookSecretConfirmed: *doc.WebhookSecretConfirmed,
	}
	if e.AppID <= 0 || github.CheckSlug(e.AppSlug) != nil || !appIDShape.MatchString(e.ClientID) || len(e.Owner) > 39 || !loginShape.MatchString(e.Owner) ||
		(e.OwnerKind != github.AccountOrganization && e.OwnerKind != github.AccountUser) {
		return appEntry{}, errAppEntry
	}
	return e, nil
}

// plaintext is what an upload of the App seals: the four secrets of [appSecretNames].
func (a *app) plaintext() (contracts.AdapterSecretsPlaintext, error) {
	entry, err := json.Marshal(appEntry{
		AppID: a.numericID, AppSlug: a.slug, ClientID: a.clientID, Owner: a.owner, OwnerKind: a.ownerKind,
		WebhookActive: a.webhookActive, WebhookSecretConfirmed: a.confirmed,
	})
	if err != nil {
		return contracts.AdapterSecretsPlaintext{}, err
	}
	return contracts.AdapterSecretsPlaintext{Version: contracts.Version, Secrets: []contracts.SecretEntry{
		{Name: secretApp, Value: string(entry)},
		{Name: secretPrivateKey, Value: string(a.pem)},
		{Name: secretWebhookSecret, Value: string(a.webhookSecret)},
		{Name: secretClientSecret, Value: string(a.clientSecret)},
	}}, nil
}

// with is a copy of a with change applied to the copy, so an App in use is never
// changed under a reader.
func (a *app) with(change func(*app)) *app {
	c := *a
	change(&c)
	return &c
}

// maxClientSecret is the most bytes a client secret has, one less than 4 KiB. GitHub's
// client secret is 40 characters.
const maxClientSecret = 4<<10 - 1

// appOf is the App in the secrets p that Qory Apiary delivered, or nil when p has
// none, as before the App setup. p must have the four secrets of [appSecretNames] and
// no other. Each is checked as the App setup checks GitHub's answer, see
// [appSetup.keep]: the private key is an RSA key in PEM, the webhook secret is
// [github.MinWebhookSecret] bytes at least, the client secret is not empty, neither
// secret has white space or a control character, and none of the three contains what
// looks like an access key secret or a run key. An error names the secret and never
// contains a value.
func appOf(p contracts.AdapterSecretsPlaintext) (*app, error) {
	if len(p.Secrets) == 0 {
		return nil, nil
	}
	values := map[string]string{}
	for _, s := range p.Secrets {
		if !slices.Contains(appSecretNames, s.Name) {
			return nil, fmt.Errorf("Qory Apiary stores the secret %s, which serve does not upload", s.Name)
		}
		values[s.Name] = s.Value
	}
	for _, name := range appSecretNames {
		if _, ok := values[name]; !ok {
			return nil, fmt.Errorf("Qory Apiary stores no secret %s for the GitHub App", name)
		}
	}
	e, err := parseAppEntry([]byte(values[secretApp]))
	if err != nil {
		return nil, err
	}
	a := &app{
		id: strconv.FormatInt(e.AppID, 10), numericID: e.AppID, slug: e.AppSlug, clientID: e.ClientID,
		webhookActive: e.WebhookActive, owner: e.Owner, ownerKind: e.OwnerKind, confirmed: e.WebhookSecretConfirmed,
	}
	pemBytes := []byte(values[secretPrivateKey])
	if err := noKeyInSecret(secretPrivateKey, pemBytes); err != nil {
		return nil, err
	}
	if len(pemBytes) > github.MaxKeyFile {
		return nil, fmt.Errorf("the secret %s in Qory Apiary is larger than a key", secretPrivateKey)
	}
	if a.key, err = github.ParseKey(pemBytes); err != nil {
		return nil, fmt.Errorf("the secret %s in Qory Apiary: %w", secretPrivateKey, err)
	}
	a.pem = pemBytes
	webhook := []byte(values[secretWebhookSecret])
	if err := noKeyInSecret(secretWebhookSecret, webhook); err != nil {
		return nil, err
	}
	if len(webhook) < minSecret || bytes.ContainsFunc(webhook, unkeepable) {
		return nil, fmt.Errorf("the secret %s in Qory Apiary is shorter than %d bytes, or has white space or a control character in it", secretWebhookSecret, minSecret)
	}
	a.webhookSecret = webhook
	client := []byte(values[secretClientSecret])
	if err := noKeyInSecret(secretClientSecret, client); err != nil {
		return nil, err
	}
	if len(client) > maxClientSecret || bytes.ContainsFunc(client, unkeepable) {
		return nil, fmt.Errorf("the secret %s in Qory Apiary is larger than %d bytes, or has white space or a control character in it", secretClientSecret, maxClientSecret)
	}
	a.clientSecret = client
	return a, nil
}

// noKeyInSecret refuses the value b of the secret name when it contains what looks like
// an access key secret or a run key, as [secretIn] finds one. The error quotes nothing.
func noKeyInSecret(name string, b []byte) error {
	switch err := secretIn(b); {
	case err == nil:
		return nil
	case errors.Is(err, errRunKeyInSettings):
		return fmt.Errorf("the secret %s in Qory Apiary contains what looks like a run key, qrk_, which belongs nowhere in it", name)
	}
	return fmt.Errorf("the secret %s in Qory Apiary contains what looks like an access key secret, qak_, which belongs nowhere in it", name)
}
