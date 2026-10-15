package serve

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Settings are what serve runs with: one JSON document in a file, --settings FILE. They
// are not part of the integration's description, which describes credential's
// settings alone. A secret is never in them: each is in a file they name, which only
// its owner may read.
type Settings struct {
	// AppID is the App's numeric id or its client id.
	AppID string
	// PrivateKeyFile is a file that contains the App's private key, read with
	// [github.ReadKeyFile].
	PrivateKeyFile string
	// WebhookSecretFile is a file that contains the App's webhook secret, read with
	// [ReadWebhookSecret].
	WebhookSecretFile string
	// Listen is the address and port serve listens on for GitHub's webhook deliveries,
	// plain HTTP: the operator's proxy terminates TLS.
	Listen string
	// StateDir is the directory the store is in, see [store.Open].
	StateDir string
}

// fields are the settings' fields, in the order an error lists the missing ones. A
// field that is added later is added here and in [ReadSettings]'s switch.
var fields = []string{"app_id", "private_key_file", "webhook_secret_file", "listen", "state_dir"}

// maxSettingsFile is the most a settings file may hold, far more than its fields need.
const maxSettingsFile = 1 << 20

// appIDShape is an App's id as credential's settings take it: its numeric id or its
// client id.
var appIDShape = regexp.MustCompile(`^[A-Za-z0-9.]{1,64}$`)

// ReadSettings reads the settings file at path, one JSON object with nothing after it
// but white space. Every field is required, and a field it does not know is refused. An
// error says where the settings are wrong and what is wrong there, never a value: a
// field's name is quoted as Go quotes a string.
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

// parseSettings reads the settings document b.
func parseSettings(b []byte) (Settings, error) {
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
		if _, ok := doc[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return Settings{}, fmt.Errorf("the settings are invalid: missing fields %s", strings.Join(missing, ", "))
	}
	var s Settings
	for _, name := range fields {
		raw := doc[name]
		var err error
		switch name {
		case "app_id":
			s.AppID, err = appID(raw)
		case "private_key_file":
			s.PrivateKeyFile, err = text(raw)
		case "webhook_secret_file":
			s.WebhookSecretFile, err = text(raw)
		case "listen":
			if s.Listen, err = text(raw); err == nil {
				err = checkListen(s.Listen)
			}
		case "state_dir":
			s.StateDir, err = text(raw)
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
