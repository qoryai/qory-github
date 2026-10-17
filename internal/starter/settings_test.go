package starter

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/qory-github"
)

// valid is a whole settings document the starter takes, as a map a test changes.
func valid(t *testing.T) map[string]any {
	t.Helper()
	server, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"apiary_url":             "https://apiary.example.com",
		"access_key_id":          "ak_0123456789abcdef",
		"access_key_secret_file": "/etc/qory-github-starter/access-key-secret",
		"apiary_public_key":      []any{map[string]any{"alg": "ed25519", "public_key": server.PublicKey().String()}},
		"pool_id":                "np_0123456789abcdef",
		"listen":                 "127.0.0.1:8080",
		"public_url":             "https://starter.example.com",
		"state_dir":              "/var/lib/qory-github-starter",
		"app_id":                 12345,
		"private_key_file":       "/etc/qory-github-starter/app.pem",
		"api_url":                "http://127.0.0.1:9999",
		"repository":             "example-org/runners",
		"workflow":               "qory-runner.yml",
		"ref":                    "main",
		"workflow_sha":           "0123456789abcdef0123456789abcdef01234567",
	}
}

// write writes doc to a settings file and returns its path.
func write(t *testing.T, doc []byte) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "starter.json")
	if err := os.WriteFile(file, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// read reads the settings m.
func read(t *testing.T, m map[string]any) (Settings, error) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return ReadSettings(write(t, b))
}

func TestReadSettingsTakesEveryField(t *testing.T) {
	m := valid(t)
	s, err := read(t, m)
	if err != nil {
		t.Fatal(err)
	}
	if s.ApiaryURL != "https://apiary.example.com" || s.AccessKeyID != "ak_0123456789abcdef" || s.AccessKeySecretFile != "/etc/qory-github-starter/access-key-secret" ||
		len(s.ApiaryPublicKey) != 1 || s.PoolID != "np_0123456789abcdef" || s.Listen != "127.0.0.1:8080" || s.PublicURL != "https://starter.example.com" ||
		s.StateDir != "/var/lib/qory-github-starter" || s.AppID != "12345" || s.PrivateKeyFile != "/etc/qory-github-starter/app.pem" ||
		s.APIURL != "http://127.0.0.1:9999" || s.Repository != "example-org/runners" || s.Workflow != "qory-runner.yml" || s.Ref != "main" ||
		s.WorkflowSHA != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("%+v", s)
	}
}

// TestReadSettingsLeavesOutTheOptionalFields pins that pool_id, api_url and
// workflow_sha may be left out, api_url then GitHub's API, and that a trailing slash
// of apiary_url is dropped.
func TestReadSettingsLeavesOutTheOptionalFields(t *testing.T) {
	m := valid(t)
	delete(m, "pool_id")
	delete(m, "api_url")
	delete(m, "workflow_sha")
	m["apiary_url"] = "https://apiary.example.com/"
	m["app_id"] = "Iv1.example"
	m["ref"] = "refs/tags/runner-1.2"
	s, err := read(t, m)
	if err != nil || s.PoolID != "" || s.APIURL != github.APIURL || s.WorkflowSHA != "" || s.ApiaryURL != "https://apiary.example.com" || s.AppID != "Iv1.example" || s.Ref != "refs/tags/runner-1.2" {
		t.Errorf("%+v, %v", s, err)
	}
}

// TestReadSettingsRefusesAWrongField pins each field's refusal: the error names the
// field and the rule, never the value.
func TestReadSettingsRefusesAWrongField(t *testing.T) {
	for _, tc := range []struct {
		field string
		value any
		want  string
	}{
		{"apiary_url", "http://apiary.example.com", "/apiary_url: is neither an https origin nor, for a test, http on a loopback host"},
		{"apiary_url", "https://apiary.example.com/v1", "/apiary_url: is neither an https origin nor, for a test, http on a loopback host"},
		{"apiary_url", 1, "/apiary_url: is not a string that is not empty"},
		{"access_key_id", "ak_0123", "/access_key_id: is not ak_ and 16 lower-case Crockford base32 characters"},
		{"access_key_secret_file", "", "/access_key_secret_file: is not a string that is not empty"},
		{"access_key_secret_file", "/etc/a\nb", "/access_key_secret_file: holds a control character, so it is not a file's path"},
		{"apiary_public_key", []any{}, `/apiary_public_key: is not a list of {"alg": "ed25519", "public_key": "<32 bytes, base64url>"}, each a key that can be used, none twice`},
		{"apiary_public_key", "not-a-pin", `/apiary_public_key: is not a list of {"alg": "ed25519", "public_key": "<32 bytes, base64url>"}, each a key that can be used, none twice`},
		{"pool_id", "na_0123456789abcdef", "/pool_id: is not np_ and 16 lower-case Crockford base32 characters"},
		{"pool_id", "np_0123456789ABCDEF", "/pool_id: is not np_ and 16 lower-case Crockford base32 characters"},
		{"listen", "8080", "/listen: is not an address and a port, host:port"},
		{"listen", ":70000", "/listen: has a port that is not a number from 0 to 65535"},
		{"public_url", "http://starter.example.com", "/public_url: " + github.ErrPublicURL.Error()},
		{"state_dir", "", "/state_dir: is not a string that is not empty"},
		{"app_id", 0, "/app_id: is neither a positive 64-bit integer nor an App's client id"},
		{"app_id", "a b", "/app_id: is not an App's id, 1 to 64 letters, digits or dots"},
		{"private_key_file", "-----BEGIN RSA PRIVATE KEY-----", "/private_key_file: holds a PEM block, which belongs in the file it names"},
		{"api_url", "ftp://github.example.com", "/api_url: "},
		{"repository", "example-org", "/repository: is not one repository, owner/name"},
		{"repository", "example-org/runners,example-org/other", "/repository: is not one repository, owner/name"},
		{"repository", "example-org/..", "/repository: is not one repository, owner/name"},
		{"workflow", ".github/workflows/qory-runner.yml", "/workflow: is not a workflow's file name: letters, digits, dots, underscores or hyphens, ending in .yml or .yaml"},
		{"workflow", "qory-runner", "/workflow: is not a workflow's file name: letters, digits, dots, underscores or hyphens, ending in .yml or .yaml"},
		{"ref", "main..next", "/ref: is not a branch or tag name git takes"},
		{"ref", "feature branch", "/ref: is not a branch or tag name git takes"},
		{"ref", "/main", "/ref: is not a branch or tag name git takes"},
		{"ref", "main.lock", "/ref: is not a branch or tag name git takes"},
		{"ref", "@", "/ref: is not a branch or tag name git takes"},
		{"ref", "main@{1}", "/ref: is not a branch or tag name git takes"},
		{"ref", "-main", "/ref: is not a branch or tag name git takes"},
		{"ref", "HEAD", "/ref: is not a branch or tag name git takes"},
		{"ref", "refs/heads/HEAD", "/ref: is not a branch or tag name git takes"},
		{"ref", "refs/tags/-v1", "/ref: is not a branch or tag name git takes"},
		{"ref", "refs/pull/1/head", "/ref: is neither a branch, NAME or refs/heads/NAME, nor a tag, refs/tags/NAME"},
		{"ref", "refs/remotes/origin/main", "/ref: is neither a branch, NAME or refs/heads/NAME, nor a tag, refs/tags/NAME"},
		{"workflow_sha", "0123456789ABCDEF0123456789ABCDEF01234567", "/workflow_sha: is not a commit's SHA, 40 lower-case hexadecimal digits"},
		{"workflow_sha", "0123456", "/workflow_sha: is not a commit's SHA, 40 lower-case hexadecimal digits"},
	} {
		m := valid(t)
		m[tc.field] = tc.value
		_, err := read(t, m)
		if err == nil || !strings.HasPrefix(err.Error(), "the settings are invalid: "+tc.want) {
			t.Errorf("%s=%v: %v; want %q", tc.field, tc.value, err, tc.want)
			continue
		}
		if s, ok := tc.value.(string); ok && len(s) > 2 && strings.Contains(err.Error(), s) {
			t.Errorf("%s: the error quotes the value: %v", tc.field, err)
		}
	}
}

// TestReadSettingsRefusesAWrongDocument pins the refusal of a document that is not one
// JSON object of the fields the starter knows, each required one there.
func TestReadSettingsRefusesAWrongDocument(t *testing.T) {
	m := valid(t)
	m["github_url"] = "https://api.github.com"
	m["Repository"] = "example-org/runners"
	if _, err := read(t, m); err == nil || err.Error() != `the settings are invalid: unknown fields "Repository", "github_url"` {
		t.Errorf("unknown fields: %v", err)
	}
	m = valid(t)
	delete(m, "apiary_url")
	delete(m, "workflow")
	delete(m, "ref")
	if _, err := read(t, m); err == nil || err.Error() != "the settings are invalid: missing fields apiary_url, workflow, ref" {
		t.Errorf("missing fields: %v", err)
	}
	b, _ := json.Marshal(valid(t))
	for doc, want := range map[string]string{
		"":                  "the settings are empty",
		"[]":                "the settings are not one JSON object",
		"null":              "the settings are not one JSON object",
		`{"app_id": `:       "the settings are not one JSON object",
		`{"app_id" 1}`:      "the settings are not one JSON document: it breaks at byte 11",
		string(b) + " {}":   "the settings are not one JSON document: something other than white space follows it",
		string(b) + " \n\t": "",
	} {
		_, err := ReadSettings(write(t, []byte(doc)))
		if want == "" && err != nil || want != "" && (err == nil || err.Error() != want) {
			t.Errorf("%.40q: %v; want %q", doc, err, want)
		}
	}
	if _, err := ReadSettings(filepath.Join(t.TempDir(), "none.json")); err == nil || !strings.HasPrefix(err.Error(), "the settings file: ") {
		t.Errorf("no file: %v", err)
	}
	large := write(t, append(b, make([]byte, maxSettingsFile)...))
	if _, err := ReadSettings(large); err == nil || err.Error() != "the settings file "+large+" is larger than 1 MiB" {
		t.Errorf("a large file: %v", err)
	}
}

// TestReadSettingsRefusesASecret pins that settings that hold what looks like an access
// key secret or a run key, in a value or a member's name, in any case, are refused
// before anything else with an error that quotes nothing.
func TestReadSettingsRefusesASecret(t *testing.T) {
	key, _ := accesskey.Generate()
	secret := key.Secret()
	for name, change := range map[string]func(map[string]any){
		"a secret in a file setting": func(m map[string]any) { m["access_key_secret_file"] = secret },
		"a secret in upper case":     func(m map[string]any) { m["ref"] = "QAK_" + strings.TrimPrefix(secret, "qak_") },
		"a secret as a member name":  func(m map[string]any) { m[secret] = 1 },
		"a run key":                  func(m map[string]any) { m["workflow"] = "qrk_0123456789abcdef0123456789abcdef0123456789abcdef" },
	} {
		m := valid(t)
		change(m)
		_, err := read(t, m)
		want := errSecretInSettings
		if name == "a run key" {
			want = errRunKeyInSettings
		}
		if err != want {
			t.Errorf("%s: %v; want %v", name, err, want)
		}
		if err != nil && strings.Contains(err.Error(), strings.TrimPrefix(secret, "qak_")) {
			t.Errorf("%s: the error quotes the secret", name)
		}
	}
}

// TestReadAccessKeySecretChecksTheFile pins that the access key's secret is read only
// from a regular file of this user that grants group and others no permission, not
// through a link, and that an error names the setting, never the path or the secret.
func TestReadAccessKeySecretChecksTheFile(t *testing.T) {
	dir := t.TempDir()
	key, _ := accesskey.Generate()
	file := filepath.Join(dir, "access-key-secret")
	if err := os.WriteFile(file, []byte(key.Secret()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if k, err := ReadAccessKeySecret(file); err != nil || k.PublicKey().String() != key.PublicKey().String() {
		t.Fatalf("a good file: %v", err)
	}
	open := filepath.Join(dir, "open")
	os.WriteFile(open, []byte(key.Secret()+"\n"), 0o640)
	os.Chmod(open, 0o640)
	link := filepath.Join(dir, "link")
	os.Symlink(file, link)
	notASecret := filepath.Join(dir, "not-a-secret")
	os.WriteFile(notASecret, []byte("s3cr3t-value\n"), 0o600)
	for path, want := range map[string]string{
		open:                         "the file access_key_secret_file names is -rw-r-----: group or others have permissions on it; make it 0600",
		link:                         "the file access_key_secret_file names is a symbolic link; use the path of the file itself",
		notASecret:                   "the file access_key_secret_file names: an access key secret starts with qak_",
		filepath.Join(dir, "absent"): "the file access_key_secret_file names: no such file or directory",
	} {
		_, err := ReadAccessKeySecret(path)
		if err == nil || err.Error() != want {
			t.Errorf("%s: %v; want %q", filepath.Base(path), err, want)
		}
		if err != nil && (strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), key.Secret())) {
			t.Errorf("%s: the error says the path or the secret: %v", filepath.Base(path), err)
		}
	}
}

// TestReadPrivateKeyChecksTheFile pins that the App's private key is read only from a
// file of this user that grants group and others no permission.
func TestReadPrivateKeyChecksTheFile(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	dir := t.TempDir()
	file := filepath.Join(dir, "app.pem")
	os.WriteFile(file, b, 0o600)
	if got, err := ReadPrivateKey(file); err != nil || !got.Equal(k) {
		t.Fatalf("a good file: %v", err)
	}
	open := filepath.Join(dir, "open.pem")
	os.WriteFile(open, b, 0o644)
	os.Chmod(open, 0o644)
	if _, err := ReadPrivateKey(open); err == nil || err.Error() != "the file private_key_file names is -rw-r--r--: group or others have permissions on it; make it 0600" {
		t.Errorf("an open file: %v", err)
	}
}
