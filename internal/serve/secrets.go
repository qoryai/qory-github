package serve

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/ownerfile"
)

// minSecret is the shortest webhook secret taken, in bytes: a shorter one is guessed
// sooner, and the signature it makes proves less. setup keeps to it too.
const minSecret = github.MinWebhookSecret

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
	// the variable that contains the value, QORY_GITHUB_ACCESS_KEY_SECRET, or the
	// file's setting, "the file access_key_secret_file names".
	in string
}

// secretOf is the secret of the field, one of [secretFields], in the settings.
func (s Settings) secretOf(field string) secretSource {
	var value SecretValue
	var file string
	if field == "access_key_secret_file" {
		value, file = s.AccessKeySecret, s.AccessKeySecretFile
	}
	if len(value) > 0 {
		return secretSource{value: value, in: valueName(field)}
	}
	return fileSecret(source{s.env}.name(field), file)
}

// fileSecret is the secret in the file at path, which the setting name names.
func fileSecret(name, path string) secretSource {
	return secretSource{file: path, in: "the file " + name + " names"}
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

// trimLineBreak is b without one line break at its end, \n or \r\n, which is not part
// of a secret.
func trimLineBreak(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r"))
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
