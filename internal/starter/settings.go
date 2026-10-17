// Package starter is qory-github-starter's: the settings it serves a node pool of Qory
// Apiary with, which start GitHub Actions workflow runs for the pool's runs.
package starter

import (
	"bytes"
	"crypto/rsa"
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
	"github.com/qoryai/qory-github/internal/ownerfile"
)

// Settings are what the starter runs with: one JSON document in a file. A secret is
// never in them: each is in a file they name, which only its owner may read.
type Settings struct {
	// ApiaryURL is Qory Apiary's origin, https, or for a test http on a loopback host:
	// every request to Qory Apiary goes there, and nowhere else.
	ApiaryURL string
	// AccessKeyID is the node pool's access key's id in Qory Apiary, ak_ and 16
	// characters, which access-key enrol prints.
	AccessKeyID string
	// AccessKeySecretFile is a file that contains the access key's secret, qak_ and
	// 43 characters, read with [ReadAccessKeySecret]. One node pool's key serves one
	// starter.
	AccessKeySecretFile string
	// ApiaryPublicKey is the pin: Qory Apiary's public keys, a list of {"alg":
	// "ed25519", "public_key": "<base64url>"}, which every answer of Qory Apiary is
	// checked under before it is used.
	ApiaryPublicKey accesskey.Pin
	// PoolID is the node pool the access key is enrolled in, np_ and 16 characters,
	// which access-key enrol prints. It may be left out: a claim then covers the key's
	// node pool.
	PoolID string
	// Listen is the address and port the starter listens on, plain HTTP: the
	// operator's proxy terminates TLS.
	Listen string
	// PublicURL is where the starter is reached from outside, https.
	PublicURL string
	// StateDir is the directory the starter keeps its state in.
	StateDir string
	// AppID is the GitHub App's numeric id or its client id.
	AppID string
	// PrivateKeyFile is a file that contains the App's private key, read with
	// [ReadPrivateKey].
	PrivateKeyFile string
	// APIURL is GitHub's API, which [github.CheckAPIURL] takes; the field may be left
	// out for [github.APIURL].
	APIURL string
	// Repository is the repository, owner/name, whose workflow the starter runs.
	Repository string
	// Workflow is the file name of the workflow in the repository's .github/workflows
	// the starter runs, such as qory-runner.yml.
	Workflow string
	// Ref is the branch or tag the workflow runs on.
	Ref string
	// WorkflowSHA is the commit, 40 lower-case hexadecimal digits, the workflow's run
	// must be at. It may be left out.
	WorkflowSHA string
}

// fields are the settings' fields, in the order an error lists the missing ones. A
// field that is added later is added here and in [parseSettings]'s switch.
var fields = []string{
	"apiary_url", "access_key_id", "access_key_secret_file", "apiary_public_key", "pool_id",
	"listen", "public_url", "state_dir",
	"app_id", "private_key_file", "api_url", "repository", "workflow", "ref", "workflow_sha",
}

// optional are the fields that may be left out: api_url, which is then GitHub's API,
// and pool_id and workflow_sha, which are then empty.
var optional = []string{"pool_id", "api_url", "workflow_sha"}

// maxSettingsFile is the most a settings file may hold, far more than its fields need.
const maxSettingsFile = 1 << 20

var (
	// appIDShape is an App's id as a string: its numeric id or its client id.
	appIDShape = regexp.MustCompile(`^[A-Za-z0-9.]{1,64}$`)
	// poolIDShape is a node pool's id, the provisioner contract's pool_id.
	poolIDShape = regexp.MustCompile(`^np_[0-9a-hjkmnp-tv-z]{16}$`)
	// shaShape is a commit's SHA-1, as GitHub writes it.
	shaShape = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// ReadSettings reads the settings file at path, one JSON object with nothing after it
// but white space. Every field is required but pool_id, api_url and workflow_sha, and a
// field it does not know is refused. An error says where the settings are wrong and what
// is wrong there, never a value: a field's name is quoted as Go quotes a string.
// Settings that hold what looks like a secret anywhere, qak_ or qrk_ in any case, in a
// value or a member's name, are refused before anything else, with an error that quotes
// nothing, and so is a file's setting whose value holds a control character or a PEM
// block. The files the settings name are not read here: [ReadAccessKeySecret] and
// [ReadPrivateKey] read them.
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
		case "apiary_url":
			if s.ApiaryURL, err = text(raw); err == nil {
				s.ApiaryURL, err = checkOrigin(s.ApiaryURL)
			}
		case "access_key_id":
			if s.AccessKeyID, err = text(raw); err == nil && accesskey.CheckID(s.AccessKeyID) != nil {
				err = errors.New("is not ak_ and 16 lower-case Crockford base32 characters")
			}
		case "access_key_secret_file":
			s.AccessKeySecretFile, err = filePath(raw)
		case "apiary_public_key":
			s.ApiaryPublicKey, err = pin(raw)
		case "pool_id":
			if s.PoolID, err = text(raw); err == nil && !poolIDShape.MatchString(s.PoolID) {
				err = errors.New("is not np_ and 16 lower-case Crockford base32 characters")
			}
		case "listen":
			if s.Listen, err = text(raw); err == nil {
				err = checkListen(s.Listen)
			}
		case "public_url":
			if s.PublicURL, err = text(raw); err == nil {
				s.PublicURL, err = checkPublicURL(s.PublicURL)
			}
		case "state_dir":
			s.StateDir, err = text(raw)
		case "app_id":
			s.AppID, err = appID(raw)
		case "private_key_file":
			s.PrivateKeyFile, err = filePath(raw)
		case "api_url":
			if s.APIURL, err = text(raw); err == nil {
				err = github.CheckAPIURL(s.APIURL)
			}
		case "repository":
			if s.Repository, err = text(raw); err == nil {
				err = checkRepository(s.Repository)
			}
		case "workflow":
			if s.Workflow, err = text(raw); err == nil {
				err = github.CheckWorkflowFile(s.Workflow)
			}
		case "ref":
			if s.Ref, err = text(raw); err == nil {
				err = github.CheckRef(s.Ref)
			}
		case "workflow_sha":
			if s.WorkflowSHA, err = text(raw); err == nil && !shaShape.MatchString(s.WorkflowSHA) {
				err = errors.New("is not a commit's SHA, 40 lower-case hexadecimal digits")
			}
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
// here names the setting alone, and the file is read as ownerfile.ReadNamed reads it,
// with errors that name the setting and never the path, so a secret pasted on one line
// in place of the path is not quoted either.
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
// dots, its numeric id or its client id.
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

// checkPublicURL takes where the starter is reached from outside as
// [github.CheckPublicURL] takes it, and refuses one that holds what looks like a secret.
func checkPublicURL(s string) (string, error) {
	if accesskey.ContainsSecret(s) {
		return "", github.ErrPublicURL
	}
	return github.CheckPublicURL(s)
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

// checkRepository takes one repository, owner/name, as [github.ParseRepositories] takes
// each. The error names the rule, never the value.
func checkRepository(s string) error {
	if strings.Contains(s, ",") {
		return errors.New("is not one repository, owner/name")
	}
	if _, err := github.ParseRepositories(s); err != nil {
		return errors.New("is not one repository, owner/name")
	}
	return nil
}

// maxAccessKeyFile is the most an access key secret file may hold; one byte more is
// read to tell a larger file apart. A secret is qak_ and 43 characters, and a line end.
const maxAccessKeyFile = 4 << 10

// ReadAccessKeySecret reads the access key's secret from the file access_key_secret_file
// names: a regular file of the user the program runs as that grants group and others no
// permission, not a symbolic link, as [ownerfile.ReadNamed] reads it, holding the secret
// and at most one line end. An error names the setting, never the path, and never says
// what the file holds.
func ReadAccessKeySecret(path string) (*accesskey.Key, error) {
	b, err := ownerfile.ReadNamed(path, maxAccessKeyFile, "the file access_key_secret_file names", "an access key secret")
	if err != nil {
		return nil, err
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	k, err := accesskey.ParseSecret(string(b))
	if err != nil {
		return nil, fmt.Errorf("the file access_key_secret_file names: %w", err)
	}
	if k.PublicKey().Fixture() {
		return nil, errors.New("the file access_key_secret_file names holds a published fixture key, whose secret anyone can read")
	}
	return k, nil
}

// ReadPrivateKey reads the App's private key from the file private_key_file names, as
// [ownerfile.ReadNamed] reads it, and parses it as [github.ParseKey] does. An error names
// the setting, never the path.
func ReadPrivateKey(path string) (*rsa.PrivateKey, error) {
	b, err := ownerfile.ReadNamed(path, github.MaxKeyFile, "the file private_key_file names", "a key")
	if err != nil {
		return nil, err
	}
	return github.ParseKey(b)
}
