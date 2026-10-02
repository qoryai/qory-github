package github

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// description is the integration's description without the program's version, which
// the build sets.
//
//go:embed description.json
var description []byte

// Description is the integration's description, contracts/integration/v1: its name,
// the domains it serves, the settings it takes as a JSON Schema, and the roles it plays.
type Description struct {
	Version     int    `json:"version"`
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	// Domains are the domains the integration serves, software for GitHub.
	Domains        []string `json:"domains,omitempty"`
	ProgramVersion string   `json:"program_version"`
	// Settings is the settings schema, the private key marked writeOnly, the secret.
	Settings json.RawMessage `json:"settings"`
	Roles    Roles           `json:"roles"`
}

// Roles are the roles the program plays.
type Roles struct {
	Credential *CredentialRole `json:"credential,omitempty"`
}

// CredentialRole is the runner's credential adapter: the argument a policy defines, and
// the hosts an answer is for.
type CredentialRole struct {
	Argument string   `json:"argument"`
	Hosts    []string `json:"hosts"`
}

// Describe is the description, with the program's version.
func Describe(programVersion string) Description {
	var d Description
	if err := json.Unmarshal(description, &d); err != nil {
		panic(err)
	}
	d.ProgramVersion = programVersion
	return d
}

// settingsSchema is the settings schema, compiled once.
var settingsSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(Describe("").Settings))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	if err := c.AddResource("settings.schema.json", doc); err != nil {
		return nil, err
	}
	return c.Compile("settings.schema.json")
})

// Settings are what minting needs, the document the description's settings schema
// declares. The package keeps none of them: they are handed in on every call.
type Settings struct {
	// AppID is the App's numeric id or its client id.
	AppID string
	// InstallationID is the App's installation; zero looks it up.
	InstallationID int64
	// Permissions are what a token may do; nil is [DefaultPermissions].
	Permissions map[string]string
	// APIURL is GitHub's API; empty is [APIURL].
	APIURL string
	// PrivateKeyFile is a file that contains the App's private key.
	PrivateKeyFile string
	// PrivateKey is the App's private key itself, the secret, which only the settings on
	// standard input contain.
	PrivateKey string
}

// maxSettingsInput is the most the settings on standard input may be, 64 KiB, as the
// integration contract defines it.
const maxSettingsInput = 64 << 10

// source is where a settings document comes from, as an error names it.
type source string

const (
	commandLine   source = "on the command line"
	standardInput source = "on standard input"
)

// ReadSettings reads the settings document passed on a command line, --settings <json>.
// It refuses a secret, a setting the schema marks writeOnly, before anything else,
// because a command line is visible to the machine's other processes; then a document
// the schema refuses. An error identifies a setting and what is wrong with it, never a
// value.
func ReadSettings(arg string) (Settings, error) {
	return readSettings([]byte(arg), commandLine)
}

// ReadSettingsInput reads the settings document on standard input, --settings -, the
// one place the settings may contain a secret. It reads r to its end, or until it has
// more than 64 KiB, before anything else, so a caller has read the settings before it
// acts. It refuses more than 64 KiB, input with no document, and anything after the
// first document but white space; then a secret <name> together with <name>_file,
// before the schema does, and a document the schema refuses. An error identifies a
// setting and what is wrong with it, never a value or any other part of the input.
func ReadSettingsInput(r io.Reader) (Settings, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxSettingsInput+1))
	if err != nil {
		return Settings{}, fmt.Errorf("reading the settings %s: %w", standardInput, err)
	}
	if len(b) > maxSettingsInput {
		return Settings{}, fmt.Errorf("the settings %s are larger than 64 KiB, %d bytes", standardInput, maxSettingsInput)
	}
	return readSettings(b, standardInput)
}

// readSettings reads one settings document from where. It is what reading the settings
// on the command line and on standard input share; the command line alone refuses a
// secret.
func readSettings(b []byte, where source) (Settings, error) {
	schema, err := settingsSchema()
	if err != nil {
		return Settings{}, err
	}
	raw, err := one(b)
	if err != nil {
		return Settings{}, fmt.Errorf("the settings %s %w", where, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return Settings{}, fmt.Errorf("the settings %s are not one JSON document", where)
	}
	if m, ok := doc.(map[string]any); ok {
		for _, name := range secrets(schema) {
			_, secret := m[name]
			if secret && where == commandLine {
				return Settings{}, fmt.Errorf("the settings on the command line contain %s, a secret, which the machine's other processes see; set %s_file to a file that contains it instead", name, name)
			}
			if _, file := m[name+"_file"]; secret && file {
				return Settings{}, fmt.Errorf("the settings %s contain both %s and %s_file; a secret has one source, so set one of them", where, name, name)
			}
		}
	}
	if err := schema.Validate(doc); err != nil {
		return Settings{}, fmt.Errorf("the settings are invalid: %s", explain(err))
	}
	var wire struct {
		AppID          json.RawMessage   `json:"app_id"`
		InstallationID int64             `json:"installation_id"`
		Permissions    map[string]string `json:"permissions"`
		APIURL         string            `json:"api_url"`
		PrivateKeyFile string            `json:"private_key_file"`
		PrivateKey     string            `json:"private_key"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return Settings{}, fmt.Errorf("the settings: %w", err)
	}
	s := Settings{InstallationID: wire.InstallationID, Permissions: wire.Permissions, APIURL: wire.APIURL, PrivateKeyFile: wire.PrivateKeyFile, PrivateKey: wire.PrivateKey}
	if err := json.Unmarshal(wire.AppID, &s.AppID); err != nil {
		s.AppID = string(wire.AppID)
	}
	if s.APIURL != "" {
		if err := CheckAPIURL(s.APIURL); err != nil {
			return Settings{}, fmt.Errorf("the settings are invalid: /api_url: %w", err)
		}
	}
	return s, nil
}

// one is the JSON document b contains, which nothing but JSON's white space may
// follow. Its error completes "the settings ... " and says where in b the document
// breaks, never what b contains there.
func one(b []byte) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	var raw json.RawMessage
	err := dec.Decode(&raw)
	var syntax *json.SyntaxError
	switch {
	case errors.Is(err, io.EOF):
		return nil, errors.New("are empty")
	case errors.Is(err, io.ErrUnexpectedEOF):
		return nil, errors.New("are not one JSON document: it ends before the document does")
	case errors.As(err, &syntax):
		return nil, fmt.Errorf("are not one JSON document: it breaks at byte %d", syntax.Offset)
	case err != nil:
		return nil, errors.New("are not one JSON document")
	}
	if strings.Trim(string(b[dec.InputOffset():]), " \t\r\n") != "" {
		return nil, errors.New("are not one JSON document: something other than white space follows it")
	}
	return raw, nil
}

// secrets are the settings the schema marks writeOnly.
func secrets(s *jsonschema.Schema) []string {
	var out []string
	for name, p := range s.Properties {
		if p.WriteOnly {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// explain is a schema's refusal on one line: where, and what is wrong, never the value
// that is. An alternative the document matches none of lists what each wanted.
func explain(err error) string {
	v, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return err.Error()
	}
	return strings.Join(reasons(v, message.NewPrinter(language.English)), "; ")
}

// location is where in the settings a refusal is, a JSON pointer such as
// /permissions/contents. A name the document chose is quoted, as Go quotes a string,
// when it contains what quoting escapes, a control character, a line or paragraph
// separator, a quote or a backslash among them, so the location stays on one line and
// reads as it is spelled. The schema's own names never need it.
func location(names []string) string {
	var b strings.Builder
	for _, name := range names {
		b.WriteString("/")
		if q := strconv.Quote(name); q[1:len(q)-1] != name {
			name = q
		}
		b.WriteString(name)
	}
	return b.String()
}

func reasons(v *jsonschema.ValidationError, p *message.Printer) []string {
	if _, ok := v.ErrorKind.(*kind.OneOf); ok && len(v.Causes) > 0 {
		var alts []string
		for _, c := range v.Causes {
			alts = append(alts, strings.Join(reasons(c, p), ", "))
		}
		return []string{strings.Join(alts, ", or ")}
	}
	at := ""
	if len(v.InstanceLocation) > 0 {
		at = location(v.InstanceLocation) + ": "
	}
	if len(v.Causes) > 0 {
		var out []string
		for _, c := range v.Causes {
			out = append(out, reasons(c, p)...)
		}
		// A refusal of a name reports which name. The validator hands it the location of
		// whatever it validates next, so the object that contains the name is read from
		// the schema's location instead.
		if k, ok := v.ErrorKind.(*kind.PropertyNames); ok {
			_, frag, _ := strings.Cut(v.SchemaURL, "#")
			at = strings.ReplaceAll(strings.TrimSuffix(frag, "/propertyNames"), "/properties/", "/") + ": "
			return []string{at + k.LocalizedString(p) + ": " + strings.Join(out, ", ")}
		}
		return out
	}
	switch k := v.ErrorKind.(type) {
	case *kind.Pattern:
		return []string{at + "does not match " + k.Want}
	case *kind.Format:
		return []string{at + "is not " + k.Want}
	case *kind.OneOf:
		return []string{at + "matches more than one of the alternatives it may match one of"}
	}
	return []string{at + v.ErrorKind.LocalizedString(p)}
}
