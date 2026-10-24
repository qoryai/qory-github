package serve

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/ownerfile"
)

// maxSecretFile is the most a webhook secret file may hold; one byte more is read to
// tell a larger file apart. A secret is far shorter. setup keeps to it too.
const maxSecretFile = github.MaxWebhookSecretFile

// minSecret is the shortest webhook secret taken, in bytes: a shorter one is guessed
// sooner, and the signature it makes proves less. setup keeps to it too.
const minSecret = github.MinWebhookSecret

// maxClientSecretFile is the most a client secret file may hold; one byte more is read
// to tell a larger file apart. GitHub's client secret is 40 characters.
const maxClientSecretFile = 4 << 10

// maxAccessKeyFile is the most an access key secret file may hold; one byte more is
// read to tell a larger file apart. A secret is 47 characters.
const maxAccessKeyFile = 4 << 10

// secretSource is where a secret setting comes from: its value, as the environment
// gives it, or the file a setting names. Each secret is read in two steps: its bytes,
// from the value or from the file through [ownerfile.ReadNamed]'s checks, and then the
// checks of the bytes, which are the same for a value and a file.
type secretSource struct {
	// value is the secret's value, when the settings give it so, and file the file that
	// holds it otherwise.
	value SecretValue
	file  string
	// in names the secret's source in an error, never its value or the file's path:
	// the variable that holds the value, such as QORY_GITHUB_WEBHOOK_SECRET, or the
	// file's setting, such as "the file webhook_secret_file names". put names where a
	// person puts a new secret: the variable, or "the file".
	in, put string
	// state is whether the file is in serve's state directory, where serve keeps the
	// App it set up, rather than one the settings name.
	state bool
}

// secretOf is the secret of the field, one of [secretFields], in the settings.
func (s Settings) secretOf(field string) secretSource {
	var value SecretValue
	var file string
	switch field {
	case "private_key_file":
		value, file = s.PrivateKey, s.PrivateKeyFile
	case "webhook_secret_file":
		value, file = s.WebhookSecret, s.WebhookSecretFile
	case "access_key_secret_file":
		value, file = s.AccessKeySecret, s.AccessKeySecretFile
	case "client_secret_file":
		value, file = s.ClientSecret, s.ClientSecretFile
	}
	if len(value) > 0 {
		return secretSource{value: value, in: valueName(field), put: valueName(field)}
	}
	return fileSecret(source{s.env}.name(field), file)
}

// fileSecret is the secret in the file at path, which the setting name names.
func fileSecret(name, path string) secretSource {
	return secretSource{file: path, in: "the file " + name + " names", put: "the file"}
}

// read is the secret's bytes: its value, or the file read as [ownerfile.ReadNamed]
// reads it, never through a symbolic link and only when its owner alone has any
// permission on it, refused when larger than max with an error that says it holds
// more than holds, such as "a key". The value is held to the same bound.
func (c secretSource) read(max int, holds string) ([]byte, error) {
	if len(c.value) == 0 {
		return ownerfile.ReadNamed(c.file, max, c.in, holds)
	}
	if len(c.value) > max {
		return nil, fmt.Errorf("%s is larger than %s", c.in, holds)
	}
	return c.value, nil
}

// noKeyIn refuses the bytes b of the private key, the webhook secret or the client
// secret, read from c, when they hold what looks like an access key secret or a run
// key, qak_ or qrk_ in any case, as [secretIn] finds one: an access key secret belongs
// only where serve keeps its access key, a run key nowhere, and the App's secrets are
// sent to GitHub. The error names c's source and quotes nothing; a run key's says it
// belongs nowhere in serve's state directory for a file there, and nowhere in serve's
// settings otherwise.
func (c secretSource) noKeyIn(b []byte) error {
	switch err := secretIn(b); {
	case err == nil:
		return nil
	case errors.Is(err, errRunKeyInSettings) && c.state:
		return fmt.Errorf("%s holds what looks like a run key, qrk_, which belongs nowhere in serve's state directory", c.in)
	case errors.Is(err, errRunKeyInSettings):
		return fmt.Errorf("%s holds what looks like a run key, qrk_, which belongs nowhere in serve's settings", c.in)
	}
	return fmt.Errorf("%s holds what looks like an access key secret, qak_, %s", c.in, accessKeyBelongs)
}

// trimLineBreak is b without one line break at its end, \n or \r\n, which is not part
// of a secret.
func trimLineBreak(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r"))
}

// ReadWebhookSecret reads the App's webhook secret from the file webhook_secret_file
// names, which only its owner may have any permission on, as [github.ReadKeyFile] reads
// a key: the same checks, a bounded read. Then it checks the secret as
// [checkWebhookSecret] does. An error names the setting, never the path or the secret.
func ReadWebhookSecret(path string) ([]byte, error) {
	return fileSecret("webhook_secret_file", path).webhookSecret()
}

// webhookSecret reads the App's webhook secret from c and checks it as
// [checkWebhookSecret] does.
func (c secretSource) webhookSecret() ([]byte, error) {
	b, err := c.read(maxSecretFile, "a webhook secret")
	if err != nil {
		return nil, err
	}
	return checkWebhookSecret(b, c)
}

// checkWebhookSecret checks the webhook secret b, read from c: one that holds what looks
// like an access key secret or a run key is refused, see [secretSource.noKeyIn]; one
// line break at its end, \n or \r\n, is not part of the secret, and a secret shorter
// than 16 bytes is refused. An error names c's source, never the secret.
func checkWebhookSecret(b []byte, c secretSource) ([]byte, error) {
	if err := c.noKeyIn(b); err != nil {
		return nil, err
	}
	b = trimLineBreak(b)
	if len(b) < minSecret {
		return nil, fmt.Errorf("the webhook secret in %s is shorter than %d bytes; set a longer random secret on the App and in %s", c.in, minSecret, c.put)
	}
	return b, nil
}

// key reads the App's private key from c, the value or the file held to
// [github.MaxKeyFile], as [github.ReadKeyFile] reads a file, with an error that names
// c's source, never the path, refuses one that holds what looks like an access key
// secret or a run key, see [secretSource.noKeyIn], and parses it as [github.ParseKey]
// does.
func (c secretSource) key() (*rsa.PrivateKey, error) {
	b, err := c.read(github.MaxKeyFile, "a key")
	if err != nil {
		return nil, err
	}
	if err := c.noKeyIn(b); err != nil {
		return nil, err
	}
	return github.ParseKey(b)
}

// ReadClientSecret reads the App's client secret from the file client_secret_file
// names, which only its owner may have any permission on, as [ReadWebhookSecret] reads
// a secret, and checks it as [checkClientSecret] does. An error names the setting,
// never the path or the secret.
func ReadClientSecret(path string) ([]byte, error) {
	return fileSecret("client_secret_file", path).clientSecret()
}

// clientSecret reads the App's client secret from c and checks it as
// [checkClientSecret] does.
func (c secretSource) clientSecret() ([]byte, error) {
	b, err := c.read(maxClientSecretFile, "a client secret")
	if err != nil {
		return nil, err
	}
	return checkClientSecret(b, c)
}

// checkClientSecret checks the client secret b, read from c: one that holds what looks
// like an access key secret or a run key is refused, see [secretSource.noKeyIn]; one
// line break at its end, \n or \r\n, is not part of it, and a secret that is empty or
// holds white space or a control character is refused. An error names c's source,
// never the secret.
func checkClientSecret(b []byte, c secretSource) ([]byte, error) {
	if err := c.noKeyIn(b); err != nil {
		return nil, err
	}
	b = trimLineBreak(b)
	if len(b) == 0 || bytes.ContainsFunc(b, func(r rune) bool { return r <= ' ' || r >= 0x7f }) {
		return nil, fmt.Errorf("%s holds no client secret, or one with white space or a control character in it", c.in)
	}
	return b, nil
}

// ReadAccessKeySecret reads the adapter's access key from a file that only its owner
// has any permission on, as [ReadWebhookSecret] reads a secret, and checks it as
// [checkAccessKeySecret] does. An error names the setting, access_key_secret_file,
// never the path or the secret.
func ReadAccessKeySecret(path string) (*accesskey.Key, error) {
	return fileSecret("access_key_secret_file", path).accessKey()
}

// accessKey reads the adapter's access key from c and checks it as
// [checkAccessKeySecret] does.
func (c secretSource) accessKey() (*accesskey.Key, error) {
	b, err := c.read(maxAccessKeyFile, "an access key secret")
	if err != nil {
		return nil, err
	}
	return checkAccessKeySecret(b, c)
}

// checkAccessKeySecret checks the access key secret b, read from c: qak_ and 43
// characters, and one line break at its end, \n or \r\n, which is not part of it. A
// published fixture key, whose secret anyone can read, is refused. An error names c's
// source, never the secret.
func checkAccessKeySecret(b []byte, c secretSource) (*accesskey.Key, error) {
	k, err := accesskey.ParseSecret(string(trimLineBreak(b)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.in, err)
	}
	if k.PublicKey().Fixture() {
		return nil, errors.New(c.in + " holds a published fixture key, whose secret anyone can read")
	}
	return k, nil
}
