package github

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
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
	// PrivateKey is the App's private key itself, the secret.
	PrivateKey string
}

// ReadSettings reads the settings document passed on a command line. It refuses a
// secret, a setting the schema marks writeOnly, before anything else, because a command
// line is visible to the machine's other processes; then a document the schema refuses.
// An error identifies a setting and what is wrong with it, never a value.
func ReadSettings(arg string) (Settings, error) {
	schema, err := settingsSchema()
	if err != nil {
		return Settings{}, err
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(arg))
	if err != nil {
		return Settings{}, fmt.Errorf("the settings are not one JSON document: %w", err)
	}
	if m, ok := doc.(map[string]any); ok {
		for _, name := range secrets(schema) {
			if _, ok := m[name]; ok {
				return Settings{}, fmt.Errorf("the settings on the command line contain %s, a secret, which the machine's other processes see; set %s_file to a file that contains it instead", name, name)
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
	if err := json.Unmarshal([]byte(arg), &wire); err != nil {
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
		at = "/" + strings.Join(v.InstanceLocation, "/") + ": "
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
