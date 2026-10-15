package serve

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/qory-github"
)

// Settings are what serve runs with: one JSON document in a file, --settings FILE. They
// are not part of the integration's description, which describes credential's
// settings alone. A secret is never in them: each is in a file they name, which only
// its owner may read.
type Settings struct {
	// AppID is the App's numeric id or its client id.
	AppID string
	// PrivateKeyFile is a file that contains the App's private key, read as
	// [github.ReadKeyFile] reads one, with errors that name the setting and never the
	// path.
	PrivateKeyFile string
	// WebhookSecretFile is a file that contains the App's webhook secret, read with
	// [ReadWebhookSecret].
	WebhookSecretFile string
	// Listen is the address and port serve listens on for GitHub's webhook deliveries,
	// plain HTTP: the operator's proxy terminates TLS.
	Listen string
	// StateDir is the directory the store is in, see [store.Open].
	StateDir string
	// AppSlug is the App's slug: its bot, slug[bot], writes the work item comment.
	AppSlug string
	// APIURL is GitHub's API, which [github.CheckAPIURL] takes; the field may be left
	// out for [github.APIURL].
	APIURL string
	// ApiaryURL is Qory Apiary's origin, https, or for a test http on a loopback host:
	// every request to Qory Apiary goes there, and nowhere else.
	ApiaryURL string
	// PublicURL is where serve is reached from outside, https: Qory Apiary sends a
	// person to connect GitHub to its connect page under it.
	PublicURL string
	// AccessKeyID is the adapter's access key's id in Qory Apiary, ak_ and 16
	// characters.
	AccessKeyID string
	// AccessKeySecretFile is a file that contains the access key's secret, qak_ and
	// 43 characters, read with [ReadAccessKeySecret]. One adapter key serves one serve.
	AccessKeySecretFile string
	// ApiaryPublicKey is the pin: Qory Apiary's public keys, a list of {"alg":
	// "ed25519", "public_key": "<base64url>"}, which every answer of Qory Apiary is
	// checked under before it is used.
	ApiaryPublicKey accesskey.Pin
}

// fields are the settings' fields, in the order an error lists the missing ones. A
// field that is added later is added here and in [ReadSettings]'s switch.
var fields = []string{"app_id", "private_key_file", "webhook_secret_file", "listen", "state_dir", "app_slug", "api_url", "apiary_url", "public_url", "access_key_id", "access_key_secret_file", "apiary_public_key"}

// optional are the fields that may be left out, each with its default.
var optional = []string{"api_url"}

// maxSettingsFile is the most a settings file may hold, far more than its fields need.
const maxSettingsFile = 1 << 20

// appIDShape is an App's id as credential's settings take it: its numeric id or its
// client id.
var appIDShape = regexp.MustCompile(`^[A-Za-z0-9.]{1,64}$`)

// ReadSettings reads the settings file at path, one JSON object with nothing after it
// but white space. Every field is required but api_url, which is GitHub's API when it is
// left out, and a field it does not know is refused. An error says where the settings
// are wrong and what is wrong there, never a value: a field's name is quoted as Go
// quotes a string. Settings that hold what looks like a secret anywhere, qak_ or qrk_ in
// any case, in a value or a member's name, are refused before anything else, with an
// error that quotes nothing, and so is a file's setting whose value holds a control
// character or a PEM block.
func ReadSettings(path string) (Settings, error) {
	f, err := os.Open(path)
	if err != nil {
		return Settings{}, fmt.Errorf("the settings file: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSettingsFile+1))
	if err != nil {
		return Settings{}, fmt.Errorf("the settings file: %w", err)
	}
	if len(b) > maxSettingsFile {
		return Settings{}, fmt.Errorf("the settings file %s is larger than 1 MiB", path)
	}
	return parseSettings(b)
}

// errSecretInSettings and errRunKeyInSettings refuse settings that hold what looks like
// a secret, as [accesskey.SecretInDocument] finds one, its prefix in any case, and quote
// nothing.
var (
	errSecretInSettings = errors.New("the settings contain what looks like an access key secret, qak_, which belongs in the file access_key_secret_file names and nowhere else")
	errRunKeyInSettings = errors.New("the settings contain what looks like a run key, qrk_, which belongs nowhere in them")
)

// secretIn is the error of settings b that hold what looks like a secret, as their
// bytes and, when they decode, their member names and values hold one, or nil.
func secretIn(b []byte) error {
	err := accesskey.SecretInDocument(string(b))
	var doc any
	if err == nil && json.Unmarshal(b, &doc) == nil {
		err = accesskey.SecretInDocument(doc)
	}
	// A run key's error is also an access key secret's, errors.Is says, so it is told
	// apart first.
	switch {
	case err == nil:
		return nil
	case errors.Is(err, accesskey.ErrRunKeyInDocument):
		return errRunKeyInSettings
	}
	return errSecretInSettings
}

// parseSettings reads the settings document b.
func parseSettings(b []byte) (Settings, error) {
	if err := secretIn(b); err != nil {
		return Settings{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var doc map[string]json.RawMessage
	err := dec.Decode(&doc)
	var syntax *json.SyntaxError
	switch {
	case errors.Is(err, io.EOF):
		return Settings{}, errors.New("the settings are empty")
	case errors.As(err, &syntax):
		return Settings{}, fmt.Errorf("the settings are not one JSON document: it breaks at byte %d", syntax.Offset)
	case err != nil || doc == nil:
		return Settings{}, errors.New("the settings are not one JSON object")
	}
	if strings.Trim(string(b[dec.InputOffset():]), " \t\r\n") != "" {
		return Settings{}, errors.New("the settings are not one JSON document: something other than white space follows it")
	}
	var unknown, missing []string
	for name := range doc {
		if !slices.Contains(fields, name) {
			unknown = append(unknown, strconv.Quote(name))
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		return Settings{}, fmt.Errorf("the settings are invalid: unknown fields %s", strings.Join(unknown, ", "))
	}
	for _, name := range fields {
		if _, ok := doc[name]; !ok && !slices.Contains(optional, name) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return Settings{}, fmt.Errorf("the settings are invalid: missing fields %s", strings.Join(missing, ", "))
	}
	s := Settings{APIURL: github.APIURL}
	for _, name := range fields {
		raw, ok := doc[name]
		if !ok {
			continue
		}
		var err error
		switch name {
		case "app_id":
			s.AppID, err = appID(raw)
		case "private_key_file":
			s.PrivateKeyFile, err = filePath(raw)
		case "webhook_secret_file":
			s.WebhookSecretFile, err = filePath(raw)
		case "listen":
			if s.Listen, err = text(raw); err == nil {
				err = checkListen(s.Listen)
			}
		case "state_dir":
			s.StateDir, err = text(raw)
		case "app_slug":
			if s.AppSlug, err = text(raw); err == nil {
				err = github.CheckSlug(s.AppSlug)
			}
		case "api_url":
			if s.APIURL, err = text(raw); err == nil {
				err = github.CheckAPIURL(s.APIURL)
			}
		case "apiary_url":
			if s.ApiaryURL, err = text(raw); err == nil {
				s.ApiaryURL, err = checkOrigin(s.ApiaryURL)
			}
		case "public_url":
			if s.PublicURL, err = text(raw); err == nil {
				s.PublicURL, err = checkPublicURL(s.PublicURL)
			}
		case "access_key_id":
			if s.AccessKeyID, err = text(raw); err == nil && accesskey.CheckID(s.AccessKeyID) != nil {
				err = errors.New("is not ak_ and 16 lower-case Crockford base32 characters")
			}
		case "access_key_secret_file":
			s.AccessKeySecretFile, err = filePath(raw)
		case "apiary_public_key":
			s.ApiaryPublicKey, err = pin(raw)
		}
		if err != nil {
			return Settings{}, fmt.Errorf("the settings are invalid: /%s: %w", name, err)
		}
	}
	return s, nil
}

// text is a field that is a string that is not empty.
func text(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || s == "" {
		return "", errors.New("is not a string that is not empty")
	}
	return s, nil
}

// filePath is a field that names a file: a string that is not empty, with no control
// character and no PEM block, so a key pasted in place of its file is refused. An error
// here names the setting alone, and serve reads the file as ownerfile.ReadNamed reads
// it, with errors that name the setting and never the path, so a secret pasted on one
// line in place of the path is not quoted either.
func filePath(raw json.RawMessage) (string, error) {
	s, err := text(raw)
	switch {
	case err != nil:
		return "", err
	case strings.ContainsFunc(s, unicode.IsControl):
		return "", errors.New("holds a control character, so it is not a file's path")
	case strings.Contains(s, "-----BEGIN"):
		return "", errors.New("holds a PEM block, which belongs in the file it names")
	}
	return s, nil
}

// appID is the App's id: a positive integer, or a string of 1 to 64 letters, digits or
// dots, its numeric id or its client id, as credential's settings take it.
func appID(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if !appIDShape.MatchString(s) {
			return "", errors.New("is not an App's id, 1 to 64 letters, digits or dots")
		}
		return s, nil
	}
	r, ok := new(big.Rat).SetString(string(raw))
	if !ok || !r.IsInt() || !r.Num().IsInt64() || r.Num().Sign() <= 0 {
		return "", errors.New("is neither a positive 64-bit integer nor an App's client id")
	}
	return strconv.FormatInt(r.Num().Int64(), 10), nil
}

// checkOrigin takes Qory Apiary's origin, a scheme and a host with a port or none:
// https, or for a test http on a loopback host, localhost, 127.0.0.1 or [::1], as
// Forager's server URL is. A trailing slash is dropped.
func checkOrigin(s string) (string, error) {
	const rule = "is neither an https origin nor, for a test, http on a loopback host"
	if accesskey.ContainsSecret(s) {
		return "", errors.New(rule)
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New(rule)
	}
	switch host := u.Hostname(); {
	case u.Scheme == "https":
	case u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1"):
	default:
		return "", errors.New(rule)
	}
	return strings.TrimSuffix(s, "/"), nil
}

// checkPublicURL takes where serve is reached from outside: https, a host, and a path
// or none, without a user, a query or a fragment. A trailing slash is dropped.
func checkPublicURL(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || accesskey.ContainsSecret(s) {
		return "", errors.New("is not an https URL without a user, a query or a fragment")
	}
	return strings.TrimSuffix(s, "/"), nil
}

// pin is the apiary_public_key field: Qory Apiary's public keys, as
// [accesskey.ParsePin] reads them, none of them a published fixture key, whose secret
// anyone can read.
func pin(raw json.RawMessage) (accesskey.Pin, error) {
	p, err := accesskey.ParsePin(raw)
	if errors.Is(err, accesskey.ErrSecretInDocument) {
		return nil, err
	}
	if err != nil {
		return nil, errors.New(`is not a list of {"alg": "ed25519", "public_key": "<32 bytes, base64url>"}, each a key that can be used, none twice`)
	}
	if p.Fixture() {
		return nil, errors.New("lists a published fixture key, whose secret anyone can read")
	}
	return p, nil
}

// checkListen takes an address and a port, host:port, [::1]:port or :port, the port a
// number from 0 to 65535; 0 is a port the system picks.
func checkListen(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("is not an address and a port, host:port")
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || strconv.FormatUint(n, 10) != port {
		return errors.New("has a port that is not a number from 0 to 65535")
	}
	return nil
}
