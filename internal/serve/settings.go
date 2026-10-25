package serve

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
)

// Settings are what serve runs with, from one of two sources and never both: one JSON
// document in a file, --settings FILE, which [ReadSettings] reads, or environment
// variables, which [ReadEnvironment] reads. They are not part of the integration's
// description, which describes credential's settings alone. The access key's secret
// is never in the file: it is in a file the settings name, which only its owner may
// read. The environment gives it as its value or as such a file. The GitHub App is in
// no setting: Qory Apiary stores it, see [Run].
type Settings struct {
	// Listen is the address and port serve listens on for GitHub's webhook deliveries,
	// plain HTTP: the instance admin's proxy terminates TLS.
	Listen string
	// StateDir is the directory the store is in, see [store.Open].
	StateDir string
	// APIURL is GitHub's API, which [github.CheckAPIURL] takes; the field may be left
	// out for [github.APIURL].
	APIURL string
	// ApiaryURL is Qory Apiary's origin, https, or for a test http on a loopback host:
	// every request to Qory Apiary goes there, and nowhere else.
	ApiaryURL string
	// ApiaryPublicURL is Qory Apiary's origin as a person's browser reaches it, https:
	// the connect page sends the browser back to Qory Apiary there. It may be left
	// out, empty, for ApiaryURL.
	ApiaryPublicURL string
	// PublicURL is where serve is reached from outside: an https origin, the adapter's
	// host name and a port or none, with no path, such as https://github.example.com,
	// 2037 characters at most. Qory Apiary sends a person to connect GitHub to
	// PublicURL/v1/connect, and an instance admin to set the App up to
	// PublicURL/setup. The bound keeps both addresses within the contract's 2048
	// characters. serve serves /v1/connect, /setup, /v1/events and /health at the
	// root of PublicURL's host, so the proxy in front must pass each path on unchanged.
	PublicURL string
	// AccessKeyID is the adapter's access key's id in Qory Apiary, ak_ and 16
	// characters.
	AccessKeyID string
	// AccessKeySecretFile is a file that contains the access key's secret, qak_ and
	// 43 characters, read with [ReadAccessKeySecret]. One adapter key serves one serve.
	// AccessKeySecret is the secret itself, which the environment gives in place of the
	// file.
	AccessKeySecretFile string
	AccessKeySecret     SecretValue
	// ApiaryPublicKey is the pin: Qory Apiary's public keys, a list of {"alg":
	// "ed25519", "public_key": "<base64url>"}, which every answer of Qory Apiary is
	// checked under before it is used, and every connect pass.
	ApiaryPublicKey accesskey.Pin
	// AdapterID is the id Qory Apiary enrolled the access key in, na_ and 16
	// characters, which access-key enrol prints: a connect pass must name it.
	AdapterID string
	// EnrolmentCodeFile is a file that holds an adapter's enrolment code on one line,
	// as Qory Apiary writes it for an adapter installed with it, checked as the other
	// paths are. It may be left out. When the settings give no enrolment and the state
	// directory holds none, serve enrols at its first start with the code it reads
	// there, and keeps the key and Qory Apiary's answer in the state directory. With
	// the enrolment kept there, serve looks at the file again at each start and after
	// each 401, and a code it finds enrols a new key, see [reenroller]. With the
	// enrolment in the settings, it never reads the file.
	EnrolmentCodeFile string
	// PublicAddress is public_address: whether GitHub reaches PublicURL, so the App
	// serve's App setup creates has its webhook active there. nil, left out, is true.
	// false makes that App's webhook inactive, and serve declares to Qory Apiary that it
	// learns of changes on GitHub by pulling, see [Settings.publicAddress].
	PublicAddress *bool
	// UploadRetrySeconds is upload_retry_seconds: how long the App setup tries again to
	// store the App in Qory Apiary when its first upload fails, 60 to 86400 seconds;
	// 0, left out, is [defaultUploadRetry]. See [appSetup.retry].
	UploadRetrySeconds int
	// CallURL is where Qory Apiary sends its calls to serve, https, with no query and no
	// fragment, its path ending with /: PublicURL followed by /v1/calls/, such as
	// https://github.example.com/v1/calls/. It may be left out: serve then declares no
	// call_url, and answers no call.
	CallURL string

	// env is whether the settings come from the environment, so an error names a
	// setting by its variable.
	env bool
}

// SecretValue is a secret a setting gives as its value. It prints, encodes as JSON or
// text and logs as [secret], or as an empty string when it is empty, so settings
// printed, encoded or logged whole never show it.
type SecretValue []byte

// String is [secret], or nothing for an empty value.
func (v SecretValue) String() string {
	if len(v) == 0 {
		return ""
	}
	return "[secret]"
}

// GoString is [SecretValue.String].
func (v SecretValue) GoString() string { return v.String() }

// Format writes [SecretValue.String] whatever the verb.
func (v SecretValue) Format(f fmt.State, _ rune) { io.WriteString(f, v.String()) }

// MarshalJSON is [SecretValue.String] as a JSON string.
func (v SecretValue) MarshalJSON() ([]byte, error) { return json.Marshal(v.String()) }

// MarshalText is [SecretValue.String].
func (v SecretValue) MarshalText() ([]byte, error) { return []byte(v.String()), nil }

// LogValue is [SecretValue.String], so a logger never writes the secret.
func (v SecretValue) LogValue() slog.Value { return slog.StringValue(v.String()) }

// fields are the settings' fields, in the order an error lists the missing ones. A
// field that is added later is added here and in [settingsOf]'s switch.
var fields = []string{"listen", "state_dir", "api_url", "apiary_url", "apiary_public_url", "public_url", "access_key_id", "access_key_secret_file", "apiary_public_key", "adapter_id", "enrolment_code_file", "public_address", "upload_retry_seconds", "call_url"}

// required are the fields the settings always give. api_url may be left out for
// GitHub's API, apiary_public_url for apiary_url, enrolment_code_file and call_url,
// which have no default, public_address for true, and upload_retry_seconds for
// [defaultUploadRetry]; the others are in a group, see [groups].
var required = []string{"listen", "state_dir", "apiary_url", "public_url"}

// secretFields are the fields that name a file that contains a secret, which the
// environment may give as the secret's value in place of the file, see [valueName].
var secretFields = []string{"access_key_secret_file"}

// The bounds of upload_retry_seconds, and the value serve takes when it is left out:
// ten minutes.
const (
	defaultUploadRetry = 600
	minUploadRetry     = 60
	maxUploadRetry     = 86400
)

// group is fields the settings give all of or none of: name names the group in an
// error, and members are its fields.
type group struct {
	name    string
	members []string
}

// groups are the settings' groups: the adapter's enrolment in Qory Apiary. Settings
// that give part of a group are refused when they are read. Run refuses settings that
// give no enrolment when serve has no way to one, see [Settings.checkEnrolmentSource].
var groups = []group{
	{"enrolment in Qory Apiary", []string{"access_key_id", "access_key_secret_file", "apiary_public_key", "adapter_id"}},
}

// envPrefix begins the name of each environment variable serve's settings are read
// from: a field's name in upper case follows it, see [envName].
const envPrefix = "QORY_GITHUB_"

// envName is the environment variable of the field, QORY_GITHUB_ and the field's name
// in upper case, such as QORY_GITHUB_LISTEN for listen.
func envName(field string) string { return envPrefix + strings.ToUpper(field) }

// valueName is the environment variable that gives the secret of a field in
// [secretFields] as its value: the field's variable without _FILE, such as
// QORY_GITHUB_ACCESS_KEY_SECRET for access_key_secret_file.
func valueName(field string) string { return strings.TrimSuffix(envName(field), "_FILE") }

// source is where settings come from, which their errors name: the file --settings
// names, or the environment when env is set.
type source struct{ env bool }

// what names the settings in an error.
func (src source) what() string {
	if src.env {
		return "the settings in the environment"
	}
	return "the settings"
}

// name is a field as an error names it: the field's name, or its variable.
func (src source) name(field string) string {
	if src.env {
		return envName(field)
	}
	return field
}

// listed is a field as a list of missing fields names it: [source.name], and for a
// secret in the environment both its variables, QORY_GITHUB_ACCESS_KEY_SECRET or
// QORY_GITHUB_ACCESS_KEY_SECRET_FILE say.
func (src source) listed(field string) string {
	if src.env && slices.Contains(secretFields, field) {
		return valueName(field) + " or " + envName(field)
	}
	return src.name(field)
}

// pointer is a field as an error about its value names it: /field in the file, as a
// JSON pointer, or its variable.
func (src source) pointer(field string) string {
	if src.env {
		return envName(field)
	}
	return "/" + field
}

// missing is the error of settings that lack names, the fields in [fields]' order.
func (src source) missing(names []string) error {
	listed := make([]string, len(names))
	for i, name := range names {
		listed[i] = src.listed(name)
	}
	kind := "fields"
	if src.env {
		kind = "variables"
	}
	return fmt.Errorf("%s are invalid: missing %s %s", src.what(), kind, strings.Join(listed, ", "))
}

// missingIn are the members of g that given says are not given, in g's order.
func missingIn(g group, given func(field string) bool) []string {
	var missing []string
	for _, field := range g.members {
		if !given(field) {
			missing = append(missing, field)
		}
	}
	return missing
}

// halfGiven are the fields of the groups given in part that given says are not given,
// in [fields]' order.
func halfGiven(given func(field string) bool) []string {
	var half []string
	for _, g := range groups {
		if m := missingIn(g, given); len(m) < len(g.members) {
			half = append(half, m...)
		}
	}
	slices.SortFunc(half, func(a, b string) int { return slices.Index(fields, a) - slices.Index(fields, b) })
	return half
}

// given is whether the settings give the field: a value for it, or for a secret's file
// the secret's value in its place.
func (s Settings) given(field string) bool {
	switch field {
	case "access_key_id":
		return s.AccessKeyID != ""
	case "access_key_secret_file":
		return s.AccessKeySecretFile != "" || len(s.AccessKeySecret) > 0
	case "apiary_public_key":
		return len(s.ApiaryPublicKey) > 0
	case "adapter_id":
		return s.AdapterID != ""
	}
	return false
}

// GivesEnrolment is whether the settings give the adapter's enrolment in Qory Apiary:
// access_key_id, the access key's secret, as a file or a value, apiary_public_key and
// adapter_id.
func (s Settings) GivesEnrolment() bool { return len(missingIn(groups[0], s.given)) == 0 }

// check refuses settings that give part of a group, naming the members they lack, as
// they are refused when they are read. Settings that give no enrolment are taken here:
// serve then uses the one kept in the state directory, or enrols with the code in the
// file enrolment_code_file names, see [Settings.checkEnrolmentSource].
func (s Settings) check() error {
	if half := halfGiven(s.given); len(half) > 0 {
		return source{s.env}.missing(half)
	}
	return nil
}

// publicAddress is public_address: true when the settings leave it out.
func (s Settings) publicAddress() bool { return s.PublicAddress == nil || *s.PublicAddress }

// uploadFor is upload_retry_seconds as a duration: [defaultUploadRetry] seconds when the
// settings leave it out.
func (s Settings) uploadFor() time.Duration {
	if s.UploadRetrySeconds == 0 {
		return defaultUploadRetry * time.Second
	}
	return time.Duration(s.UploadRetrySeconds) * time.Second
}

// maxSettingsFile is the most a settings file may hold, far more than its fields need.
const maxSettingsFile = 1 << 20

// appIDShape is an App's client id, as Qory Apiary stores it in the secret app: 1 to
// 64 letters, digits or dots.
var appIDShape = regexp.MustCompile(`^[A-Za-z0-9.]{1,64}$`)

// adapterIDShape is the id of an adapter Qory Apiary enrolled, the contract's pattern
// for a connect pass's adapter_id.
var adapterIDShape = regexp.MustCompile(`^na_[0-9a-hjkmnp-tv-z]{16}$`)

// ReadSettings reads the settings file at path, one JSON object with nothing after it
// but white space. listen, state_dir, apiary_url and public_url are required. api_url
// may be left out for GitHub's API, apiary_public_url for apiary_url,
// enrolment_code_file, call_url, public_address, a JSON boolean, for true, and
// upload_retry_seconds, a JSON integer, for [defaultUploadRetry]. The enrolment's
// fields, access_key_id, access_key_secret_file, apiary_public_key and adapter_id, are
// given all or none. Run refuses
// settings that give no enrolment when the state directory holds none and
// enrolment_code_file is not set. A field it does not know is refused. An error says
// where the settings are wrong and what is wrong there, never a value: a field's name
// is quoted as Go quotes a string. Settings that hold what looks like a secret
// anywhere, qak_ or qrk_ in any case, in a value or a member's name, are refused before
// anything else, with an error that quotes nothing, and so is a file's setting whose
// value holds a control character or a PEM block.
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

// ReadEnvironment reads the settings from environment variables, each looked up with
// lookup, as [os.LookupEnv] looks one up: a field's variable is QORY_GITHUB_ and its
// name in upper case, such as QORY_GITHUB_LISTEN, and an empty variable counts as one
// not set. Each value is the field's string; QORY_GITHUB_APIARY_PUBLIC_KEY is the
// pin's JSON, QORY_GITHUB_PUBLIC_ADDRESS is true or false, and
// QORY_GITHUB_UPLOAD_RETRY_SECONDS is an integer. The access key's secret is given as
// its value, QORY_GITHUB_ACCESS_KEY_SECRET, or as the file
// QORY_GITHUB_ACCESS_KEY_SECRET_FILE names, and both set is refused. Every field is
// checked as [ReadSettings] checks it, with errors that name the variable and never a
// value. Before anything else, every field's variable it reads, a _FILE variable among
// them, is scanned for what looks like a secret, qak_ or qrk_ in any case, and one
// that contains it is refused with an error that names the variable and quotes
// nothing. Only QORY_GITHUB_ACCESS_KEY_SECRET is not scanned: it contains the access
// key's secret, qak_, and is read as [ReadAccessKeySecret] reads its file.
func ReadEnvironment(lookup func(string) (string, bool)) (Settings, error) {
	src := source{env: true}
	get := func(name string) string { v, _ := lookup(name); return v }
	scanned := make([]string, 0, len(fields)+len(secretFields))
	for _, field := range fields {
		scanned = append(scanned, envName(field))
	}
	for _, field := range secretFields {
		if field != "access_key_secret_file" {
			scanned = append(scanned, valueName(field))
		}
	}
	for _, name := range scanned {
		if v := get(name); v != "" {
			if err := secretInVariable(name, v); err != nil {
				return Settings{}, err
			}
		}
	}
	doc := map[string]json.RawMessage{}
	for _, field := range fields {
		name, v := envName(field), get(envName(field))
		if v == "" {
			continue
		}
		if !utf8.ValidString(v) {
			return Settings{}, fmt.Errorf("%s are invalid: %s: is not UTF-8 text", src.what(), name)
		}
		if field == "apiary_public_key" || field == "public_address" || field == "upload_retry_seconds" {
			doc[field] = json.RawMessage(v)
			continue
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return Settings{}, err
		}
		doc[field] = raw
	}
	values := map[string]SecretValue{}
	for _, field := range secretFields {
		v := get(valueName(field))
		if v == "" {
			continue
		}
		if _, ok := doc[field]; ok {
			return Settings{}, fmt.Errorf("%s are invalid: both %s and %s are set; set one of them", src.what(), valueName(field), envName(field))
		}
		values[field] = SecretValue(v)
	}
	return settingsOf(doc, values, src)
}

// accessKeyBelongs says where an access key secret found where it does not belong
// belongs: serve takes its access key from the settings, or keeps the key it enrolled
// in the state directory.
const accessKeyBelongs = "which belongs only where serve keeps its access key: the access key secret setting, or the state directory"

// errSecretInSettings and errRunKeyInSettings refuse settings that hold what looks like
// a secret, as [accesskey.SecretInDocument] finds one, its prefix in any case, and quote
// nothing.
var (
	errSecretInSettings = errors.New("the settings contain what looks like an access key secret, qak_, " + accessKeyBelongs)
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

// secretInVariable is the error of the environment variable name whose value v holds
// what looks like a secret, as [secretIn] finds one in v, or nil. It names the
// variable and quotes nothing.
func secretInVariable(name, v string) error {
	switch err := secretIn([]byte(v)); {
	case err == nil:
		return nil
	case errors.Is(err, errRunKeyInSettings):
		return fmt.Errorf("the environment variable %s holds what looks like a run key, qrk_, which belongs nowhere in serve's settings", name)
	}
	return fmt.Errorf("the environment variable %s holds what looks like an access key secret, qak_, %s", name, accessKeyBelongs)
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
	var unknown []string
	for name := range doc {
		if !slices.Contains(fields, name) {
			unknown = append(unknown, strconv.Quote(name))
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		return Settings{}, fmt.Errorf("the settings are invalid: unknown fields %s", strings.Join(unknown, ", "))
	}
	return settingsOf(doc, nil, source{})
}

// settingsOf reads the settings doc gives, each field's JSON by its name, and values,
// the secrets the environment gives as values by the field of their file, from src.
// It refuses settings that lack a required field or part of a group, naming each field
// they lack, then checks each field given.
func settingsOf(doc map[string]json.RawMessage, values map[string]SecretValue, src source) (Settings, error) {
	given := func(field string) bool {
		_, ok := doc[field]
		return ok || len(values[field]) > 0
	}
	var missing []string
	for _, field := range fields {
		if !given(field) && slices.Contains(required, field) {
			missing = append(missing, field)
		}
	}
	if half := halfGiven(given); len(half) > 0 || len(missing) > 0 {
		missing = append(missing, half...)
		slices.SortFunc(missing, func(a, b string) int { return slices.Index(fields, a) - slices.Index(fields, b) })
		return Settings{}, src.missing(missing)
	}
	s := Settings{APIURL: github.APIURL, env: src.env}
	for _, name := range fields {
		raw, ok := doc[name]
		if !ok {
			continue
		}
		var err error
		switch name {
		case "listen":
			if s.Listen, err = text(raw); err == nil {
				err = checkListen(s.Listen)
			}
		case "state_dir":
			s.StateDir, err = text(raw)
		case "api_url":
			if s.APIURL, err = text(raw); err == nil {
				err = github.CheckAPIURL(s.APIURL)
			}
		case "apiary_url":
			if s.ApiaryURL, err = text(raw); err == nil {
				s.ApiaryURL, err = checkOrigin(s.ApiaryURL)
			}
		case "apiary_public_url":
			if s.ApiaryPublicURL, err = text(raw); err == nil {
				s.ApiaryPublicURL, err = checkBrowserOrigin(s.ApiaryPublicURL)
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
		case "adapter_id":
			if s.AdapterID, err = text(raw); err == nil && !adapterIDShape.MatchString(s.AdapterID) {
				err = errors.New("is not na_ and 16 lower-case Crockford base32 characters")
			}
		case "enrolment_code_file":
			s.EnrolmentCodeFile, err = filePath(raw)
		case "public_address":
			b := string(raw) == "true"
			if !b && string(raw) != "false" {
				err = errors.New("is neither true nor false")
			}
			s.PublicAddress = &b
		case "upload_retry_seconds":
			s.UploadRetrySeconds, err = uploadRetry(raw)
		case "call_url":
			if s.CallURL, err = text(raw); err == nil {
				err = checkCallURL(s.CallURL)
			}
		}
		if err != nil && name == "public_url" {
			return Settings{}, fmt.Errorf("Set %s %s: %s are invalid: %s: %w", src.name(name), publicURLFix, src.what(), src.pointer(name), err)
		}
		if err != nil {
			return Settings{}, fmt.Errorf("%s are invalid: %s: %w", src.what(), src.pointer(name), err)
		}
	}
	s.AccessKeySecret = values["access_key_secret_file"]
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

// uploadRetry is upload_retry_seconds: an integer from [minUploadRetry] to
// [maxUploadRetry].
func uploadRetry(raw json.RawMessage) (int, error) {
	r, ok := new(big.Rat).SetString(string(raw))
	if !ok || !r.IsInt() || !r.Num().IsInt64() || r.Num().Int64() < minUploadRetry || r.Num().Int64() > maxUploadRetry {
		return 0, fmt.Errorf("is not an integer from %d to %d", minUploadRetry, maxUploadRetry)
	}
	return int(r.Num().Int64()), nil
}

// checkOrigin takes Qory Apiary's origin, a scheme and a host with a port or none:
// https, or for a test http on a loopback host, localhost, 127.0.0.1 or [::1], as
// Forager's server URL is. A # or a ? anywhere is refused, an empty fragment among
// them, which url.Parse leaves no trace of; it notes an empty query as ForceQuery. A
// trailing slash is dropped.
func checkOrigin(s string) (string, error) {
	const rule = "is neither an https origin nor, for a test, http on a loopback host"
	if accesskey.ContainsSecret(s) || strings.ContainsAny(s, "#?") {
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

// checkBrowserOrigin takes Qory Apiary's origin as a person's browser reaches it, as
// [checkOrigin] takes an origin, but https alone: serve's connect page sends a person's
// browser there, so http on a loopback host, which only a browser on the same machine
// reaches, is refused. A trailing slash is dropped.
func checkBrowserOrigin(s string) (string, error) {
	const rule = "is not an https origin, a scheme and a host with a port or none"
	origin, err := checkOrigin(s)
	if err != nil {
		return "", errors.New(rule)
	}
	if u, err := url.Parse(origin); err != nil || u.Scheme != "https" {
		return "", errors.New(rule)
	}
	return origin, nil
}

// maxPublicURL is the most characters public_url has, as [github.CheckPublicURL]
// returns it: the contract's 2048 for a URL, less /v1/connect, the longest path serve
// declares after it.
const maxPublicURL = 2048 - len(connectPath)

// publicURLFix is the fix every error about public_url starts with, after "Set " and
// the setting's name.
const publicURLFix = "to the adapter's host name only, such as https://github.example.com"

// checkPublicURL takes where serve is reached from outside as [github.CheckPublicURL]
// takes it, an origin, and refuses one that holds what looks like a secret, and one
// longer than [maxPublicURL] characters as CheckPublicURL returns it.
func checkPublicURL(s string) (string, error) {
	if accesskey.ContainsSecret(s) {
		return "", github.ErrPublicURL
	}
	u, err := github.CheckPublicURL(s)
	if err == nil && utf8.RuneCountInString(u) > maxPublicURL {
		return "", fmt.Errorf("is longer than %d characters", maxPublicURL)
	}
	return u, err
}

// callURLShape is the contract's pattern for a URL, definitions.schema.json's url, which
// adapter.schema.json's call_url refers to.
var callURLShape = sync.OnceValue(func() *regexp.Regexp {
	doc, err := contracts.Document("definitions.schema.json")
	if err != nil {
		panic(err)
	}
	defs, _ := doc.(map[string]any)["$defs"].(map[string]any)
	u, _ := defs["url"].(map[string]any)
	pattern, _ := u["pattern"].(string)
	return regexp.MustCompile(pattern)
})

// errCallURL is the error of a call_url the contract refuses. It quotes nothing.
var errCallURL = errors.New("is not an https URL with no query and no fragment whose path ends with /, at most 2048 characters")

// checkCallURL takes call_url as adapter.schema.json takes it: an https URL of at most
// 2048 characters, as the contract writes one, with no query and no fragment, whose path
// ends with /. One that holds what looks like a secret is refused too.
func checkCallURL(s string) error {
	if accesskey.ContainsSecret(s) || len(s) > 2048 || strings.ContainsAny(s, "?#") || !strings.HasSuffix(s, "/") || !callURLShape().MatchString(s) {
		return errCallURL
	}
	return nil
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
