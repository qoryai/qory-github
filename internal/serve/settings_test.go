package serve

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/qory-github"
)

// lookupIn looks a variable up in env, as os.LookupEnv looks one up in the process's
// environment, so a test sets no variable of the process.
func lookupIn(env map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	}
}

// appKeyPEM is the App's private key in PEM, as GitHub's conversion answers it.
func appKeyPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(appKey())}))
}

// envSettings is an environment that gives every setting, the access key's secret as
// its value.
func envSettings(access *accesskey.Key) map[string]string {
	return map[string]string{
		"QORY_GITHUB_LISTEN":               ":8080",
		"QORY_GITHUB_STATE_DIR":            "/var/lib/qory-github",
		"QORY_GITHUB_API_URL":              "http://127.0.0.1:9",
		"QORY_GITHUB_APIARY_URL":           "http://127.0.0.1:4000/",
		"QORY_GITHUB_APIARY_PUBLIC_URL":    "https://apiary.example.com/",
		"QORY_GITHUB_PUBLIC_URL":           "https://github.example.com/",
		"QORY_GITHUB_ACCESS_KEY_ID":        "ak_0123456789abcdef",
		"QORY_GITHUB_ACCESS_KEY_SECRET":    access.Secret() + "\n",
		"QORY_GITHUB_APIARY_PUBLIC_KEY":    pinJSON,
		"QORY_GITHUB_ADAPTER_ID":           "na_0123456789abcdef",
		"QORY_GITHUB_ENROLMENT_CODE_FILE":  "/run/enrolment/code",
		"QORY_GITHUB_UPLOAD_RETRY_SECONDS": "900",
	}
}

// changed is env with set's variables set, an empty value among them, and unset's
// removed.
func changed(env map[string]string, set map[string]string, unset ...string) map[string]string {
	out := map[string]string{}
	for k, v := range env {
		out[k] = v
	}
	for k, v := range set {
		out[k] = v
	}
	for _, k := range unset {
		delete(out, k)
	}
	return out
}

// TestReadEnvironmentTakesEveryVariable pins that each setting is read from its
// variable, QORY_GITHUB_ and its name in upper case, the pin as its JSON, and the
// access key's secret as its value or as the file its _FILE variable names, checked as
// the file's settings are. The variables of the App that settings gave before are not
// read.
func TestReadEnvironmentTakesEveryVariable(t *testing.T) {
	access := newKey(t)
	env := envSettings(access)
	s, err := ReadEnvironment(lookupIn(env))
	want := Settings{Listen: ":8080", StateDir: "/var/lib/qory-github",
		APIURL: "http://127.0.0.1:9", ApiaryURL: "http://127.0.0.1:4000", ApiaryPublicURL: "https://apiary.example.com", PublicURL: "https://github.example.com",
		AccessKeyID: "ak_0123456789abcdef", AccessKeySecret: SecretValue(access.Secret() + "\n"), ApiaryPublicKey: accesskey.Pin{{Alg: "ed25519", PublicKey: "Pjsm5s3nnSkGz0Vag3fbXsTMycY1__2Z0w5jggPsA70"}},
		AdapterID: "na_0123456789abcdef", EnrolmentCodeFile: "/run/enrolment/code", UploadRetrySeconds: 900, env: true}
	if err != nil || !reflect.DeepEqual(s, want) || s.uploadFor() != 15*time.Minute {
		t.Fatalf("%+v %v", s, err)
	}
	if !s.GivesEnrolment() {
		t.Error("the enrolment is not given")
	}
	// The variables of the App are not read.
	withApp := changed(env, map[string]string{
		"QORY_GITHUB_APP_ID": "123456", "QORY_GITHUB_APP_SLUG": "qory-acme", "QORY_GITHUB_CLIENT_ID": "Iv1.abc",
		"QORY_GITHUB_PRIVATE_KEY": appKeyPEM(), "QORY_GITHUB_WEBHOOK_SECRET_FILE": "/s", "QORY_GITHUB_CLIENT_SECRET": clientSecret,
	})
	if s, err := ReadEnvironment(lookupIn(withApp)); err != nil || !reflect.DeepEqual(s, want) {
		t.Errorf("with the App's variables: %+v %v", s, err)
	}
	// The other way round: the access key's secret as a file. An empty variable counts
	// as one not set: api_url is GitHub's, upload_retry_seconds is 600, and
	// apiary_public_url and enrolment_code_file are left out.
	other := changed(env, map[string]string{
		"QORY_GITHUB_ACCESS_KEY_SECRET_FILE": "/a", "QORY_GITHUB_API_URL": "", "QORY_GITHUB_ENROLMENT_CODE_FILE": "", "QORY_GITHUB_UPLOAD_RETRY_SECONDS": "",
	}, "QORY_GITHUB_ACCESS_KEY_SECRET", "QORY_GITHUB_APIARY_PUBLIC_URL")
	s, err = ReadEnvironment(lookupIn(other))
	if err != nil || s.AccessKeySecretFile != "/a" || s.AccessKeySecret != nil || s.APIURL != github.APIURL || s.ApiaryPublicURL != "" || s.EnrolmentCodeFile != "" ||
		s.UploadRetrySeconds != 0 || s.uploadFor() != 10*time.Minute {
		t.Errorf("%+v %v", s, err)
	}
}

// TestReadEnvironmentRefusesAWrongVariable pins each refusal of the environment: an
// error names the variable and never says a value.
func TestReadEnvironmentRefusesAWrongVariable(t *testing.T) {
	access := newKey(t)
	env := envSettings(access)
	const invalid = "the settings in the environment are invalid: "
	const badPublicVariable = "Set QORY_GITHUB_PUBLIC_URL to the adapter's host name only, such as https://github.example.com: " + invalid + "QORY_GITHUB_PUBLIC_URL: is not an https URL of a host and an optional port, without a path, a user, a query or a fragment"
	const qak = "holds what looks like an access key secret, qak_, which belongs only where serve keeps its access key: the access key secret setting, or the state directory"
	for name, tc := range map[string]struct {
		set   map[string]string
		unset []string
		want  string
	}{
		"no port":                 {set: map[string]string{"QORY_GITHUB_LISTEN": "127.0.0.1"}, want: invalid + "QORY_GITHUB_LISTEN: is not an address and a port, host:port"},
		"a short retry":           {set: map[string]string{"QORY_GITHUB_UPLOAD_RETRY_SECONDS": "59"}, want: invalid + "QORY_GITHUB_UPLOAD_RETRY_SECONDS: is not an integer from 60 to 86400"},
		"a retry of no number":    {set: map[string]string{"QORY_GITHUB_UPLOAD_RETRY_SECONDS": "ten minutes"}, want: invalid + "QORY_GITHUB_UPLOAD_RETRY_SECONDS: is not an integer from 60 to 86400"},
		"a retry in quotes":       {set: map[string]string{"QORY_GITHUB_UPLOAD_RETRY_SECONDS": `"600"`}, want: invalid + "QORY_GITHUB_UPLOAD_RETRY_SECONDS: is not an integer from 60 to 86400"},
		"another API":             {set: map[string]string{"QORY_GITHUB_API_URL": "https://secret.example.com"}, want: invalid + "QORY_GITHUB_API_URL: the API is neither"},
		"Qory Apiary on http":     {set: map[string]string{"QORY_GITHUB_APIARY_URL": "http://secret.example.com"}, want: invalid + "QORY_GITHUB_APIARY_URL: is neither an https origin nor, for a test, http on a loopback host"},
		"a public Qory Apiary":    {set: map[string]string{"QORY_GITHUB_APIARY_PUBLIC_URL": "http://localhost:4000"}, want: invalid + "QORY_GITHUB_APIARY_PUBLIC_URL: is not an https origin, a scheme and a host with a port or none"},
		"a public path":           {set: map[string]string{"QORY_GITHUB_APIARY_PUBLIC_URL": "https://apiary.example.com/secret"}, want: invalid + "QORY_GITHUB_APIARY_PUBLIC_URL: is not an https origin"},
		"a public http URL":       {set: map[string]string{"QORY_GITHUB_PUBLIC_URL": "http://secret.example.com"}, want: badPublicVariable},
		"a public URL's path":     {set: map[string]string{"QORY_GITHUB_PUBLIC_URL": "https://github.example.com/secret"}, want: badPublicVariable},
		"a bad key id":            {set: map[string]string{"QORY_GITHUB_ACCESS_KEY_ID": "ak_secret"}, want: invalid + "QORY_GITHUB_ACCESS_KEY_ID: is not ak_"},
		"a pin of no JSON":        {set: map[string]string{"QORY_GITHUB_APIARY_PUBLIC_KEY": "secret value"}, want: invalid + `QORY_GITHUB_APIARY_PUBLIC_KEY: is not a list of {"alg": "ed25519"`},
		"a node's id":             {set: map[string]string{"QORY_GITHUB_ADAPTER_ID": "nd_0123456789abcdef"}, want: invalid + "QORY_GITHUB_ADAPTER_ID: is not na_"},
		"a control character":     {set: map[string]string{"QORY_GITHUB_ACCESS_KEY_SECRET_FILE": "/s\tsecret value"}, unset: []string{"QORY_GITHUB_ACCESS_KEY_SECRET"}, want: invalid + "QORY_GITHUB_ACCESS_KEY_SECRET_FILE: holds a control character, so it is not a file's path"},
		"a PEM as a path":         {set: map[string]string{"QORY_GITHUB_ACCESS_KEY_SECRET_FILE": "-----BEGIN secret value"}, unset: []string{"QORY_GITHUB_ACCESS_KEY_SECRET"}, want: invalid + "QORY_GITHUB_ACCESS_KEY_SECRET_FILE: holds a PEM block, which belongs in the file it names"},
		"a code file's line":      {set: map[string]string{"QORY_GITHUB_ENROLMENT_CODE_FILE": "/e\nsecret value"}, want: invalid + "QORY_GITHUB_ENROLMENT_CODE_FILE: holds a control character"},
		"no UTF-8":                {set: map[string]string{"QORY_GITHUB_STATE_DIR": "/d\xffsecret value"}, want: invalid + "QORY_GITHUB_STATE_DIR: is not UTF-8 text"},
		"an access secret twice":  {set: map[string]string{"QORY_GITHUB_ACCESS_KEY_SECRET_FILE": "/a"}, want: invalid + "both QORY_GITHUB_ACCESS_KEY_SECRET and QORY_GITHUB_ACCESS_KEY_SECRET_FILE are set; set one of them"},
		"a missing variable":      {set: map[string]string{"QORY_GITHUB_STATE_DIR": ""}, unset: []string{"QORY_GITHUB_LISTEN"}, want: invalid + "missing variables QORY_GITHUB_LISTEN, QORY_GITHUB_STATE_DIR"},
		"no public URL":           {unset: []string{"QORY_GITHUB_PUBLIC_URL", "QORY_GITHUB_APIARY_URL"}, want: invalid + "missing variables QORY_GITHUB_APIARY_URL, QORY_GITHUB_PUBLIC_URL"},
		"half the enrolment":      {unset: []string{"QORY_GITHUB_ACCESS_KEY_SECRET", "QORY_GITHUB_ADAPTER_ID"}, want: invalid + "missing variables QORY_GITHUB_ACCESS_KEY_SECRET or QORY_GITHUB_ACCESS_KEY_SECRET_FILE, QORY_GITHUB_ADAPTER_ID"},
		"a secret in a setting":   {set: map[string]string{"QORY_GITHUB_STATE_DIR": "qak_secret value"}, want: "the environment variable QORY_GITHUB_STATE_DIR " + qak},
		"a secret as its file":    {set: map[string]string{"QORY_GITHUB_ACCESS_KEY_SECRET_FILE": "QAK_secret value"}, unset: []string{"QORY_GITHUB_ACCESS_KEY_SECRET"}, want: "the environment variable QORY_GITHUB_ACCESS_KEY_SECRET_FILE " + qak},
		"a secret in a URL":       {set: map[string]string{"QORY_GITHUB_PUBLIC_URL": "https://qory-github.example.com/qak_secret value"}, want: "the environment variable QORY_GITHUB_PUBLIC_URL " + qak},
		"an escaped secret":       {set: map[string]string{"QORY_GITHUB_APIARY_PUBLIC_KEY": `["qak_secret value"]`}, want: "the environment variable QORY_GITHUB_APIARY_PUBLIC_KEY " + qak},
		"a run key":               {set: map[string]string{"QORY_GITHUB_LISTEN": "QRK_secret value"}, want: "the environment variable QORY_GITHUB_LISTEN holds what looks like a run key, qrk_, which belongs nowhere in serve's settings"},
		"a secret before a twice": {set: map[string]string{"QORY_GITHUB_ACCESS_KEY_SECRET_FILE": "qak_secret value"}, want: "the environment variable QORY_GITHUB_ACCESS_KEY_SECRET_FILE " + qak},
	} {
		_, err := ReadEnvironment(lookupIn(changed(env, tc.set, tc.unset...)))
		if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
		if err != nil && (strings.Contains(err.Error(), "secret value") || strings.Contains(err.Error(), "BEGIN") || strings.Contains(err.Error(), access.Secret())) {
			t.Errorf("%s: the error says a value: %v", name, err)
		}
	}
}

// TestOnlyTheAccessKeySecretMayHoldQak pins that the access key's secret, qak_ and 43
// characters, is taken in QORY_GITHUB_ACCESS_KEY_SECRET and its file, while every other
// variable is scanned for one: each is refused with an error that names the variable
// and quotes nothing.
func TestOnlyTheAccessKeySecretMayHoldQak(t *testing.T) {
	access := newKey(t)
	env := envSettings(access)
	if !strings.HasPrefix(env["QORY_GITHUB_ACCESS_KEY_SECRET"], "qak_") {
		t.Fatal("the access key's secret is not qak_")
	}
	if _, err := ReadEnvironment(lookupIn(env)); err != nil {
		t.Errorf("the secret's variable is refused: %v", err)
	}
	const inEnv = " holds what looks like an access key secret, qak_, which belongs only where serve keeps its access key: the access key secret setting, or the state directory"
	const runKey = " holds what looks like a run key, qrk_, which belongs nowhere in serve's settings"
	for _, name := range []string{"QORY_GITHUB_ADAPTER_ID", "QORY_GITHUB_API_URL", "QORY_GITHUB_APIARY_PUBLIC_URL", "QORY_GITHUB_ENROLMENT_CODE_FILE", "QORY_GITHUB_PUBLIC_URL"} {
		for value, want := range map[string]string{
			access.Secret():                       "the environment variable " + name + inEnv,
			"a-webhook-secret-" + access.Secret(): "the environment variable " + name + inEnv,
			"QRK_a-pasted-run-key":                "the environment variable " + name + runKey,
		} {
			_, err := ReadEnvironment(lookupIn(changed(env, map[string]string{name: value})))
			if err == nil || err.Error() != want || strings.Contains(err.Error(), value) {
				t.Errorf("%s: err %v, want %q", name, err, want)
			}
		}
	}
	dir := t.TempDir()
	// The access key's secret file is the one place a qak_ belongs.
	keyFile := filepath.Join(dir, "access-key")
	writeFile(t, keyFile, access.Secret()+"\n", 0o600)
	if k, err := (Settings{env: true, AccessKeySecretFile: keyFile}).secretOf("access_key_secret_file").accessKey(); err != nil || k.PublicKey().String() != access.PublicKey().String() {
		t.Errorf("the access key's file: %v %v", k, err)
	}
}

// TestASecretValueIsNeverPrinted pins that a secret the environment gives as its value
// prints as exactly [secret] with every fmt verb, and an empty one as nothing; that
// settings printed with any of those verbs show no secret, in plain text or as a list
// of its bytes in any base; and that the settings and a secret, encoded as JSON or
// text, or logged with slog's JSON and text handlers, show [secret] and no secret.
func TestASecretValueIsNeverPrinted(t *testing.T) {
	access := newKey(t)
	s, err := ReadEnvironment(lookupIn(envSettings(access)))
	if err != nil {
		t.Fatal(err)
	}
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "% x", "%#x", "%d", "%o", "%O", "%b", "%c", "%U", "%e", "%f", "%g", "%t", "%10s", "%-12v", "%08d"}
	for _, verb := range verbs {
		if got := fmt.Sprintf(verb, s.AccessKeySecret); got != "[secret]" {
			t.Errorf("%s prints a secret value as %q", verb, got)
		}
		if got := fmt.Sprintf(verb, SecretValue(nil)); got != "" {
			t.Errorf("%s prints an empty value as %q", verb, got)
		}
	}
	if got := fmt.Sprint(s.AccessKeySecret) + fmt.Sprintln(s.AccessKeySecret) + s.AccessKeySecret.String() + s.AccessKeySecret.GoString(); got != "[secret][secret]\n[secret][secret]" {
		t.Errorf("a secret value prints as %q", got)
	}
	// The forms a secret's bytes print in without [SecretValue.Format], which settings
	// printed whole must hold none of.
	b := []byte(s.AccessKeySecret)
	forbidden := []string{string(b), fmt.Sprint(b), fmt.Sprintf("%#v", b), fmt.Sprintf("%o", b), fmt.Sprintf("%b", b), fmt.Sprintf("%c", b),
		fmt.Sprintf("%x", b), fmt.Sprintf("%X", b), fmt.Sprintf("% x", b), fmt.Sprintf("%q", b), base64.StdEncoding.EncodeToString(b)}
	var out strings.Builder
	for _, verb := range append(verbs, "%T") {
		fmt.Fprintf(&out, verb+" ", s)
		fmt.Fprintf(&out, verb+" ", &s)
	}
	fmt.Fprint(&out, s, &s)
	fmt.Fprintln(&out, s, &s)
	fmt.Fprint(&out, s.AccessKeySecret.String(), s.AccessKeySecret.GoString())
	settingsJSON, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	valueJSON, _ := json.Marshal(s.AccessKeySecret)
	text, _ := s.AccessKeySecret.MarshalText()
	out.Write(settingsJSON)
	out.Write(valueJSON)
	out.Write(text)
	for _, h := range []slog.Handler{slog.NewJSONHandler(&out, nil), slog.NewTextHandler(&out, nil)} {
		slog.New(h).Info("settings", slog.Any("settings", s), slog.Any("secret", s.AccessKeySecret), "key", s.AccessKeySecret)
	}
	for _, value := range append(forbidden, access.Secret()) {
		if strings.Contains(out.String(), value) {
			t.Errorf("the settings show %q: %s", value, out.String())
		}
	}
	if string(valueJSON) != `"[secret]"` || string(text) != "[secret]" || !strings.Contains(string(settingsJSON), `"AccessKeySecret":"[secret]"`) ||
		!strings.Contains(out.String(), `"secret":"[secret]"`) || !strings.Contains(out.String(), "secret=[secret]") {
		t.Errorf("%s", out.String())
	}
	empty, _ := json.Marshal(SecretValue(nil))
	emptyText, _ := SecretValue(nil).MarshalText()
	if SecretValue(nil).String() != "" || string(empty) != `""` || len(emptyText) != 0 || SecretValue(nil).LogValue().String() != "" || s.AccessKeySecret.LogValue().String() != "[secret]" {
		t.Errorf("an empty value: %s %q", empty, emptyText)
	}
}

// TestASecretValueIsCheckedAsItsFileIs pins that the access key's secret the
// environment gives as its value is checked as its file is, with errors that name the
// variable, and that a file its _FILE variable names is read with errors that name
// that variable.
func TestASecretValueIsCheckedAsItsFileIs(t *testing.T) {
	value := func(v string) secretSource {
		return Settings{env: true, AccessKeySecret: SecretValue(v)}.secretOf("access_key_secret_file")
	}
	access := newKey(t)
	if k, err := value(access.Secret() + "\n").accessKey(); err != nil || k.PublicKey().String() != access.PublicKey().String() {
		t.Errorf("%v %v", k, err)
	}
	if _, err := value("not-a-secret-value").accessKey(); err == nil || err.Error() != "QORY_GITHUB_ACCESS_KEY_SECRET: an access key secret starts with qak_" {
		t.Errorf("err %v", err)
	}
	if _, err := value("qak_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA").accessKey(); err == nil || err.Error() != "QORY_GITHUB_ACCESS_KEY_SECRET holds a published fixture key, whose secret anyone can read" {
		t.Errorf("a fixture key: %v", err)
	}
	// A file the _FILE variable names is read with its checks, and an error names the
	// variable, never the path.
	dir := t.TempDir()
	missing := filepath.Join(dir, "none")
	if _, err := (Settings{env: true, AccessKeySecretFile: missing}).secretOf("access_key_secret_file").accessKey(); err == nil ||
		err.Error() != "the file QORY_GITHUB_ACCESS_KEY_SECRET_FILE names: no such file or directory" {
		t.Errorf("err %v", err)
	}
	loose := filepath.Join(dir, "loose")
	writeFile(t, loose, access.Secret(), 0o644)
	if _, err := (Settings{env: true, AccessKeySecretFile: loose}).secretOf("access_key_secret_file").accessKey(); err == nil || !strings.HasPrefix(err.Error(), "the file QORY_GITHUB_ACCESS_KEY_SECRET_FILE names is -rw-r--r--: group or others have permissions on it") {
		t.Errorf("a loose file: %v", err)
	}
}

// TestTheFileTakesTheNewFieldsAndAGroupLeftOut pins apiary_public_url and
// enrolment_code_file in the settings file, and that a group left out whole is read
// while part of one is refused, naming the fields it lacks.
func TestTheFileTakesTheNewFieldsAndAGroupLeftOut(t *testing.T) {
	base := map[string]any{"listen": ":8080", "state_dir": "/d",
		"apiary_url": "http://localhost:8443", "apiary_public_url": "https://Apiary.example.com:8443/", "public_url": "https://qory-github.example.com",
		"access_key_id": "ak_0123456789abcdef", "access_key_secret_file": "/a", "apiary_public_key": json.RawMessage(pinJSON),
		"adapter_id": "na_0123456789abcdef", "enrolment_code_file": "/run/enrolment/code"}
	read := func(change map[string]any, drop ...string) (Settings, error) {
		doc := map[string]any{}
		for k, v := range base {
			doc[k] = v
		}
		for k, v := range change {
			doc[k] = v
		}
		for _, k := range drop {
			delete(doc, k)
		}
		b, _ := json.Marshal(doc)
		return parseSettings(b)
	}
	if s, err := read(nil); err != nil || s.ApiaryPublicURL != "https://Apiary.example.com:8443" || s.EnrolmentCodeFile != "/run/enrolment/code" || s.env || !s.GivesEnrolment() {
		t.Errorf("%+v %v", s, err)
	}
	for value, want := range map[string]string{
		"http://localhost:8443":               "the settings are invalid: /apiary_public_url: is not an https origin, a scheme and a host with a port or none",
		"https://apiary.example.com/path":     "the settings are invalid: /apiary_public_url: is not an https origin",
		"https://user@apiary.example.com":     "the settings are invalid: /apiary_public_url: is not an https origin",
		"ftp://apiary.example.com":            "the settings are invalid: /apiary_public_url: is not an https origin",
		"https://apiary.example.com/?q":       "the settings are invalid: /apiary_public_url: is not an https origin",
		"https://apiary.example.com/#section": "the settings are invalid: /apiary_public_url: is not an https origin",
		"https://apiary.example.com#":         "the settings are invalid: /apiary_public_url: is not an https origin",
		"https://apiary.example.com/#":        "the settings are invalid: /apiary_public_url: is not an https origin",
		"https://apiary.example.com?":         "the settings are invalid: /apiary_public_url: is not an https origin",
	} {
		if _, err := read(map[string]any{"apiary_public_url": value}); err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("%s: err %v", value, err)
		}
	}
	// An empty fragment or query, which url.Parse leaves no trace of, is refused in
	// apiary_url too.
	for _, value := range []string{"https://apiary.example.com#", "https://apiary.example.com/#", "https://apiary.example.com?", "http://localhost:8443/?", "http://localhost:8443#"} {
		if _, err := read(map[string]any{"apiary_url": value}); err == nil || err.Error() != "the settings are invalid: /apiary_url: is neither an https origin nor, for a test, http on a loopback host" {
			t.Errorf("%s: err %v", value, err)
		}
	}
	if _, err := read(map[string]any{"enrolment_code_file": "-----BEGIN secret value"}); err == nil || err.Error() != "the settings are invalid: /enrolment_code_file: holds a PEM block, which belongs in the file it names" {
		t.Errorf("err %v", err)
	}
	// The optional fields may be left out.
	if s, err := read(nil, "apiary_public_url", "enrolment_code_file"); err != nil || s.ApiaryPublicURL != "" || s.EnrolmentCodeFile != "" {
		t.Errorf("%+v %v", s, err)
	}
	enrolment := []string{"access_key_id", "access_key_secret_file", "apiary_public_key", "adapter_id"}
	if s, err := read(nil, enrolment...); err != nil || s.GivesEnrolment() {
		t.Errorf("no enrolment: %+v %v", s, err)
	}
	if _, err := read(nil, "apiary_public_key", "state_dir"); err == nil || err.Error() != "the settings are invalid: missing fields state_dir, apiary_public_key" {
		t.Errorf("err %v", err)
	}
}

// TestRunRefusesSettingsWithoutAGroup pins that Run refuses settings that give no
// enrolment when the state directory holds none and no code file is set, or part of
// the enrolment, naming what they lack in the source's words, before it reads a secret
// or makes the state directory.
func TestRunRefusesSettingsWithoutAGroup(t *testing.T) {
	dir := t.TempDir()
	full := settingsFiles(t, dir, newKey(t), "https://apiary.example.com", pinOf(newKey(t)))
	noEnrolment := full
	noEnrolment.AccessKeyID, noEnrolment.AccessKeySecretFile, noEnrolment.ApiaryPublicKey, noEnrolment.AdapterID = "", "", nil, ""
	half := full
	half.AdapterID = ""
	envNoEnrolment := noEnrolment
	envNoEnrolment.env, envNoEnrolment.AccessKeySecret = true, SecretValue("x")
	envHalf := half
	envHalf.env = true
	for name, tc := range map[string]struct {
		s    Settings
		want string
	}{
		"no enrolment":                 {noEnrolment, "the settings give no enrolment in Qory Apiary, the state directory holds none, and enrolment_code_file is not set: give access_key_id, access_key_secret_file, apiary_public_key, adapter_id, or set enrolment_code_file for serve to enrol at its first start"},
		"half the enrolment":           {half, "the settings are invalid: missing fields adapter_id"},
		"half the enrolment, env":      {envNoEnrolment, "the settings in the environment are invalid: missing variables QORY_GITHUB_ACCESS_KEY_ID, QORY_GITHUB_APIARY_PUBLIC_KEY, QORY_GITHUB_ADAPTER_ID"},
		"half, in the environment":     {envHalf, "the settings in the environment are invalid: missing variables QORY_GITHUB_ADAPTER_ID"},
		"no enrolment, in environment": {Settings{env: true, StateDir: full.StateDir}, "the settings in the environment give no enrolment in Qory Apiary, the state directory holds none, and QORY_GITHUB_ENROLMENT_CODE_FILE is not set: give QORY_GITHUB_ACCESS_KEY_ID, QORY_GITHUB_ACCESS_KEY_SECRET or QORY_GITHUB_ACCESS_KEY_SECRET_FILE, QORY_GITHUB_APIARY_PUBLIC_KEY, QORY_GITHUB_ADAPTER_ID, or set QORY_GITHUB_ENROLMENT_CODE_FILE for serve to enrol at its first start"},
	} {
		listened := false
		err := Run(context.Background(), tc.s, Options{ProgramVersion: testVersion, Listening: func(net.Addr) { listened = true }})
		if err == nil || err.Error() != tc.want || listened {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
		if _, err := os.Stat(full.StateDir); !os.IsNotExist(err) {
			t.Errorf("%s: the state directory is made: %v", name, err)
		}
	}
}

// TestRunTakesSecretsAsValuesAndSendsTheBrowserToTheApiaryPublicURL runs serve with
// settings from the environment, the access key's secret a value, Qory Apiary's origin
// on loopback and its public origin apart: a delivery signed with the webhook secret
// of the App Qory Apiary stores is taken, and a connect return sends the browser to
// apiary_public_url, not to apiary_url; with apiary_public_url left out, it goes to
// apiary_url.
func TestRunTakesSecretsAsValuesAndSendsTheBrowserToTheApiaryPublicURL(t *testing.T) {
	for _, public := range []string{"https://apiary.example.com", ""} {
		dir := t.TempDir()
		access := newKey(t)
		apiary := newFakeApiary(t, access)
		env := map[string]string{
			"QORY_GITHUB_LISTEN": "127.0.0.1:0", "QORY_GITHUB_STATE_DIR": filepath.Join(dir, "state"),
			"QORY_GITHUB_APIARY_URL": apiary.srv.URL, "QORY_GITHUB_APIARY_PUBLIC_URL": public, "QORY_GITHUB_PUBLIC_URL": "https://qory-github.example.com",
			"QORY_GITHUB_ACCESS_KEY_ID": testKeyID, "QORY_GITHUB_ACCESS_KEY_SECRET": access.Secret(), "QORY_GITHUB_ADAPTER_ID": testAdapterID,
			"QORY_GITHUB_API_URL": appAPI(t),
		}
		pinBytes, _ := json.Marshal(pinOf(apiary.server))
		env["QORY_GITHUB_APIARY_PUBLIC_KEY"] = string(pinBytes)
		s, err := ReadEnvironment(lookupIn(env))
		if err != nil {
			t.Fatal(err)
		}
		handled := make(chan string, 1)
		hs := &Handlers{}
		hs.HandleFunc("issues", func(_ context.Context, d Delivery) error { handled <- d.GUID; return nil })
		var log syncBuffer
		addr := make(chan net.Addr, 1)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- Run(ctx, s, Options{ProgramVersion: testVersion, Handlers: hs, Log: slog.New(slog.NewJSONHandler(&log, nil)), Listening: func(a net.Addr) { addr <- a }})
		}()
		var base string
		select {
		case a := <-addr:
			pastAppCheck(t, a.String())
			base = "http://" + a.String()
		case err := <-done:
			t.Fatalf("Run: %v", err)
		}
		req, _ := http.NewRequest(http.MethodPost, base+WebhookPath, strings.NewReader(body1))
		req.Header.Set("X-GitHub-Event", "issues")
		req.Header.Set("X-GitHub-Delivery", guid1)
		req.Header.Set("X-Hub-Signature-256", sign(body1))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Errorf("the delivery: status %d", resp.StatusCode)
		}
		select {
		case <-handled:
		case <-time.After(5 * time.Second):
			t.Fatal("the delivery is not handled")
		}
		// A pass that verifies but has expired goes back to Qory Apiary at once.
		late := signPass(apiary.server, payload(testAdapterID, testConnection, newNonce(), time.Now().Add(-time.Hour)))
		noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err = noFollow.Get(base + "/v1/connect?state=" + url.QueryEscape(late))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		want := public
		if want == "" {
			want = apiary.srv.URL
		}
		if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, want+"/integrations/"+testConnection+"?return=") {
			t.Errorf("public %q: %d, sent to %s", public, resp.StatusCode, loc)
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Run does not return")
		}
		if strings.Contains(log.String(), "must not") || strings.Contains(log.String(), "PRIVATE KEY") || strings.Contains(log.String(), access.Secret()) {
			t.Errorf("the log carries a secret: %s", log.String())
		}
	}
}

// TestPublicAddressIsTrueOrFalse pins public_address: a JSON boolean in the file, true
// or false in the environment, left out for true, anything else refused with an error
// that names the field or its variable and quotes nothing.
func TestPublicAddressIsTrueOrFalse(t *testing.T) {
	base := map[string]any{"listen": ":8080", "state_dir": "/d", "apiary_url": "https://apiary.example.com", "public_url": "https://qory-github.example.com"}
	read := func(v any) (Settings, error) {
		doc := map[string]any{"public_address": v}
		for k, x := range base {
			doc[k] = x
		}
		b, _ := json.Marshal(doc)
		return parseSettings(b)
	}
	for _, v := range []bool{true, false} {
		if s, err := read(v); err != nil || s.PublicAddress == nil || *s.PublicAddress != v || s.publicAddress() != v {
			t.Errorf("%v: %+v %v", v, s, err)
		}
	}
	for _, v := range []any{"true", 1, nil, []any{}} {
		if _, err := read(v); err == nil || err.Error() != "the settings are invalid: /public_address: is neither true nor false" {
			t.Errorf("%v: err %v", v, err)
		}
	}
	b, _ := json.Marshal(base)
	if s, err := parseSettings(b); err != nil || s.PublicAddress != nil || !s.publicAddress() {
		t.Errorf("left out: %+v %v", s, err)
	}
	env := map[string]string{"QORY_GITHUB_LISTEN": ":8080", "QORY_GITHUB_STATE_DIR": "/d", "QORY_GITHUB_APIARY_URL": "https://apiary.example.com", "QORY_GITHUB_PUBLIC_URL": "https://qory-github.example.com"}
	for v, want := range map[string]bool{"true": true, "false": false} {
		env["QORY_GITHUB_PUBLIC_ADDRESS"] = v
		if s, err := ReadEnvironment(lookupIn(env)); err != nil || s.publicAddress() != want {
			t.Errorf("%s: %+v %v", v, s, err)
		}
	}
	for _, v := range []string{"yes", "True", `"true"`, " true", "1"} {
		env["QORY_GITHUB_PUBLIC_ADDRESS"] = v
		if _, err := ReadEnvironment(lookupIn(env)); err == nil || err.Error() != "the settings in the environment are invalid: QORY_GITHUB_PUBLIC_ADDRESS: is neither true nor false" {
			t.Errorf("%q: err %v", v, err)
		}
	}
}

// TestAPublicURLLongerThan2037CharactersIsRefused pins the bound on public_url, which
// keeps connect_url and setup_url within the contract's 2048 characters.
func TestAPublicURLLongerThan2037CharactersIsRefused(t *testing.T) {
	const scheme, domain = "https://", ".example.com"
	long := func(n int) string { return scheme + strings.Repeat("a", n-len(scheme)-len(domain)) + domain }
	for n, ok := range map[int]bool{2037: true, 2038: false} {
		b, _ := json.Marshal(map[string]any{"listen": ":8080", "state_dir": "/d", "apiary_url": "https://apiary.example.com", "public_url": long(n)})
		s, err := parseSettings(b)
		if ok && (err != nil || len(s.PublicURL+connectPath) != 2048) {
			t.Errorf("%d: %v", n, err)
		}
		if !ok && (err == nil || err.Error() != "Set public_url to the adapter's host name only, such as https://github.example.com: the settings are invalid: /public_url: is longer than 2037 characters") {
			t.Errorf("%d: err %v", n, err)
		}
	}
	// A trailing slash is not counted: the URL is bounded as serve uses it.
	b, _ := json.Marshal(map[string]any{"listen": ":8080", "state_dir": "/d", "apiary_url": "https://apiary.example.com", "public_url": long(2037) + "/"})
	if _, err := parseSettings(b); err != nil {
		t.Errorf("a trailing slash: %v", err)
	}
}
