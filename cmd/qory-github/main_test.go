package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode"

	"github.com/qoryai/integrations/conformance"
	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

const token = "ghs_faketokenthatmustnotleak"

// fakeAPI is GitHub's API as the command uses it, answering the mint with status.
func fakeAPI(t *testing.T, status int) string {
	t.Helper()
	return fakeAPIChecking(t, status, func() {})
}

// fakeAPIChecking is fakeAPI that runs check on every request, before it answers.
func fakeAPIChecking(t *testing.T, status int, check func()) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		check()
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			io.WriteString(w, `{"id":42}`)
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			w.WriteHeader(status)
			if status == 201 {
				io.WriteString(w, `{"token":"`+token+`","expires_at":"2026-09-25T21:00:00Z"}`)
			} else {
				io.WriteString(w, `{"message":"Resource not accessible by integration"}`)
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func keyFile(t *testing.T) (string, []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	file := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return file, b
}

// settings is a settings document for standard input, with these fields added.
func settings(t *testing.T, fields map[string]any) string {
	t.Helper()
	doc := map[string]any{"app_id": 123456}
	for k, v := range fields {
		doc[k] = v
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCredentialPrintsOneDocumentAndNothingElse(t *testing.T) {
	file, _ := keyFile(t)
	var out, errs bytes.Buffer
	in := strings.NewReader(settings(t, map[string]any{"private_key_file": file, "api_url": fakeAPI(t, 201)}))
	code := run(context.Background(), []string{"credential", "--", "acme/shop"}, in, &out, &errs)
	if code != 0 || errs.Len() != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("standard output is not one document: %v\n%s", err, out.String())
	}
	if doc["token"] != token || doc["version"] != float64(1) {
		t.Errorf("doc %v", doc)
	}
	if err := conformance.Credential(out.Bytes()); err != nil {
		t.Error(err)
	}
}

// TestCredentialReadsTheSettingsOnStandardInput hands the settings in on standard input,
// the key itself or its file, and checks that standard input is read to its end before
// GitHub's API is called.
func TestCredentialReadsTheSettingsOnStandardInput(t *testing.T) {
	file, pemBytes := keyFile(t)
	for _, tc := range []struct {
		name   string
		fields map[string]any
		after  string
	}{
		{"the key", map[string]any{"private_key": string(pemBytes)}, ""},
		{"the key, white space after", map[string]any{"private_key": string(pemBytes)}, "\n \t\r\n"},
		{"the key file", map[string]any{"private_key_file": file}, "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := &eofReader{}
			api := fakeAPIChecking(t, 201, func() {
				if !in.eof.Load() {
					t.Error("GitHub's API is called before standard input is read to its end")
				}
			})
			tc.fields["api_url"] = api
			in.r = strings.NewReader(settings(t, tc.fields) + tc.after)
			var out, errs bytes.Buffer
			code := run(context.Background(), []string{"credential", "--", "acme/shop"}, in, &out, &errs)
			if code != 0 || errs.Len() != 0 {
				t.Fatalf("exit %d: %s", code, errs.String())
			}
			if err := conformance.Credential(out.Bytes()); err != nil {
				t.Error(err)
			}
			if !strings.Contains(out.String(), token) {
				t.Errorf("stdout %s", out.String())
			}
		})
	}
}

// TestCredentialReadsStandardInputBeforeItChecksTheArgument checks that an argument is
// refused after standard input is read to its end, so the writer is never cut off: none,
// two, and the empty one a connection without an argument passes, which the
// repositories' rule refuses, not the count.
func TestCredentialReadsStandardInputBeforeItChecksTheArgument(t *testing.T) {
	_, pemBytes := keyFile(t)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"none", []string{"credential", "--"}, "qory-github credential: want one argument, owner/name[,owner/name...]\n"},
		{"two", []string{"credential", "--", "acme/shop", "acme/lib"}, "qory-github credential: want one argument, owner/name[,owner/name...]\n"},
		{"empty", []string{"credential", "--", ""}, "qory-github credential: the argument is empty; want owner/name[,owner/name...]\n"},
		{"empty, no --", []string{"credential", ""}, "qory-github credential: the argument is empty; want owner/name[,owner/name...]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := &eofReader{r: strings.NewReader(settings(t, map[string]any{"private_key": string(pemBytes)}))}
			var out, errs bytes.Buffer
			code := run(context.Background(), tc.args, in, &out, &errs)
			if !in.eof.Load() {
				t.Error("the argument is refused before standard input is read to its end")
			}
			if err := conformance.Failure(code, out.Bytes(), errs.Bytes()); err != nil {
				t.Error(err)
			}
			if errs.String() != tc.want {
				t.Errorf("stderr %q, want %q", errs.String(), tc.want)
			}
		})
	}
}

// TestCredentialRefusesTheSettingsFlag runs credential with the flag of 0.1.0, --settings,
// in each of its forms. credential takes no flags, so each is refused before standard
// input is read, with one line and nothing on standard output; -h still prints the help.
func TestCredentialRefusesTheSettingsFlag(t *testing.T) {
	file, _ := keyFile(t)
	for _, args := range [][]string{
		{"credential", "--settings", "{}", "--", "acme/shop"},
		{"credential", "--settings", "-", "--", "acme/shop"},
		{"credential", "--settings=-", "--", "acme/shop"},
		{"credential", "-settings", "-", "acme/shop"},
	} {
		in := &eofReader{r: strings.NewReader(settings(t, map[string]any{"private_key_file": file}))}
		var out, errs bytes.Buffer
		code := run(context.Background(), args, in, &out, &errs)
		if err := conformance.Failure(code, out.Bytes(), errs.Bytes()); err != nil {
			t.Errorf("%q: %v", args, err)
		}
		if want := "qory-github credential: flag provided but not defined: -settings\n"; errs.String() != want {
			t.Errorf("%q: stderr %q, want %q", args, errs.String(), want)
		}
		if in.eof.Load() {
			t.Errorf("%q: standard input is read for a flag that is refused", args)
		}
	}
	var out, errs bytes.Buffer
	if code := run(context.Background(), []string{"credential", "-h"}, strings.NewReader(""), &out, &errs); code != 2 || out.Len() != 0 || !strings.Contains(errs.String(), "usage:\n  qory-github credential [--] owner/name") {
		t.Errorf("-h: exit %d, stdout %q, stderr %q", code, out.String(), errs.String())
	}
}

// eofReader is standard input that records when it has been read, and when to its end.
type eofReader struct {
	r         io.Reader
	read, eof atomic.Bool
}

func (e *eofReader) Read(p []byte) (int, error) {
	e.read.Store(true)
	n, err := e.r.Read(p)
	if errors.Is(err, io.EOF) {
		e.eof.Store(true)
	}
	return n, err
}

func TestAFailureIsOneLineWithNoSecret(t *testing.T) {
	file, pemBytes := keyFile(t)
	// noAPI is an API that a failure on standard input never reaches.
	noAPI := fakeAPIChecking(t, 201, func() { t.Error("GitHub's API is called for settings that are refused") })
	key := settings(t, map[string]any{"private_key": string(pemBytes), "api_url": noAPI})
	cred := []string{"credential", "--", "acme/shop"}
	for _, tc := range []struct {
		name  string
		args  []string
		stdin string
		want  string
	}{
		{"github refuses", cred, settings(t, map[string]any{"private_key_file": file, "api_url": fakeAPI(t, 403)}), "403: Resource not accessible by integration"},
		{"two owners", []string{"credential", "--", "acme/shop,other/lib"}, settings(t, map[string]any{"private_key_file": file, "api_url": noAPI}), "share an owner"},
		{"no settings", cred, "{}", "missing property 'app_id'"},
		{"no key", cred, settings(t, nil), "missing property 'private_key_file'"},
		{"admin", cred, settings(t, map[string]any{"private_key_file": file, "permissions": map[string]string{"contents": "admin"}}), "/permissions/contents: value must be one of 'read', 'write'"},
		{"administration", cred, settings(t, map[string]any{"private_key_file": file, "permissions": map[string]string{"administration": "read"}}), "/permissions: invalid propertyName 'administration'"},
		{"an argument like a flag", []string{"credential", "--", "-acme/shop"}, settings(t, map[string]any{"private_key_file": file, "api_url": noAPI}), `"-acme/shop" is not owner/name`},
		{"a flag of old", []string{"credential", "--app-id", "123456", "--private-key-file", file, "acme/shop"}, key, "flag provided but not defined: -app-id"},
		{"the key and its file", cred, settings(t, map[string]any{"private_key": string(pemBytes), "private_key_file": file, "api_url": noAPI}), "contain both private_key and private_key_file; a secret has one source"},
		{"empty standard input", cred, "", "the settings on standard input are empty"},
		{"white space on standard input", cred, " \n\t\r\n", "the settings on standard input are empty"},
		{"two documents on standard input", cred, key + "\n" + key, "something other than white space follows it"},
		{"more than 64 KiB on standard input", cred, key + strings.Repeat(" ", 65537-len(key)), "larger than 64 KiB, 65536 bytes"},
		{"a key not escaped", cred, `{"app_id":123456,"private_key":"` + string(pemBytes) + `"}`, "not one JSON document: it breaks at byte"},
		{"a key that is not one", cred, settings(t, map[string]any{"private_key": "secretvalue", "api_url": noAPI}), "the private key is not PEM"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errs bytes.Buffer
			code := run(context.Background(), tc.args, strings.NewReader(tc.stdin), &out, &errs)
			if code != 1 || out.Len() != 0 {
				t.Fatalf("exit %d, stdout %q", code, out.String())
			}
			if err := conformance.Failure(code, out.Bytes(), errs.Bytes()); err != nil {
				t.Error(err)
			}
			line := errs.String()
			if strings.Count(line, "\n") != 1 || !strings.HasPrefix(line, "qory-github credential: ") || !strings.Contains(line, tc.want) {
				t.Errorf("stderr %q", line)
			}
			if strings.Contains(line, token) || strings.Contains(line, "PRIVATE KEY") || bytes.Contains([]byte(line), pemBytes[40:80]) || strings.Contains(line, "secretvalue") {
				t.Errorf("stderr contains a secret: %q", line)
			}
		})
	}
}

// TestAFailureFromGitHubIsOneLine has GitHub's API refuse the mint with a message that
// contains control characters and Unicode line separators, and checks that the failure
// is still one line on standard error, with each of them escaped.
func TestAFailureFromGitHubIsOneLine(t *testing.T) {
	file, _ := keyFile(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/installation") {
			io.WriteString(w, `{"id":42}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"message":"a\r\nb\rc\td\u007fe\u0085f\u2028g\u2029h\ni"}`)
	}))
	t.Cleanup(srv.Close)
	var out, errs bytes.Buffer
	in := strings.NewReader(settings(t, map[string]any{"private_key_file": file, "api_url": srv.URL}))
	code := run(context.Background(), []string{"credential", "--", "acme/shop"}, in, &out, &errs)
	if err := conformance.Failure(code, out.Bytes(), errs.Bytes()); err != nil {
		t.Error(err)
	}
	line := strings.TrimSuffix(errs.String(), "\n")
	if i := strings.IndexFunc(line, func(r rune) bool { return unicode.IsControl(r) || r == '\u2028' || r == '\u2029' }); i >= 0 {
		t.Errorf("stderr contains %q: %q", []rune(line[i:])[0], errs.String())
	}
	if want := `403: a b\rc\td\x7fe\u0085f\u2028g\u2029h i` + "\n"; !strings.HasSuffix(errs.String(), want) {
		t.Errorf("stderr %q, want it to end in %q", errs.String(), want)
	}
}

// TestOneLine pins how an error's text is written on its line: a line break as a space,
// every other control character, a line or paragraph separator and a byte that is not
// UTF-8 escaped, and the rest as it is.
func TestOneLine(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"the settings are invalid: /permissions/contents: value must be one of 'read', 'write'", "the settings are invalid: /permissions/contents: value must be one of 'read', 'write'"},
		{`/permissions/"a\u2028b": a quote " and a backslash \ stay`, `/permissions/"a\u2028b": a quote " and a backslash \ stay`},
		{"one\ntwo\r\nthree", "one two three"},
		{"a\rb\tc\x00d\x1be\x7ff", `a\rb\tc\x00d\x1be\x7ff`},
		{"a\u0085b\u009bc\u2028d\u2029e", `a\u0085b\u009bc\u2028d\u2029e`},
		{"a\x85b\xffc", `a\x85b\xffc`},
		{"GitHub – Ölsardine ✓", "GitHub – Ölsardine ✓"},
	} {
		if got := oneLine(tc.in); got != tc.want {
			t.Errorf("oneLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDescribeConformsAndIsPinned checks what describe prints against the integration
// contract and pins it to testdata/describe.json, so a change to the description is a
// change to that file too. The contract's fixture fixtures/github.json is the
// description of 0.1.0, an example of the contract's; this copy is the program's.
func TestDescribeConformsAndIsPinned(t *testing.T) {
	// The pinned copy is the description of a build with no version, whatever version
	// the test binary's build info contains.
	defer func(v string) { version = v }(version)
	version = "dev"
	var out, errs bytes.Buffer
	in := &eofReader{r: strings.NewReader("{}")}
	if code := run(context.Background(), []string{"describe"}, in, &out, &errs); code != 0 || errs.Len() != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	if in.read.Load() {
		t.Error("describe reads standard input")
	}
	if err := conformance.Description(out.Bytes()); err != nil {
		t.Fatal(err)
	}
	pinned, err := os.ReadFile("../../testdata/describe.json")
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != string(pinned) {
		t.Errorf("describe prints\n%s\nand testdata/describe.json contains\n%s", out.String(), pinned)
	}
	out.Reset()
	errs.Reset()
	code := run(context.Background(), []string{"describe", "acme/shop"}, nil, &out, &errs)
	if err := conformance.Failure(code, out.Bytes(), errs.Bytes()); err != nil {
		t.Errorf("describe with an argument: %v", err)
	}
}

// TestProgramVersionFallsBackToTheModuleVersion pins the program's version: the one
// set with ldflags first, then the module version go install records, a release or a
// pseudo-version, which the contract's schema accepts, and "dev" for a build whose
// module version is (devel) or empty, or with no build info.
func TestProgramVersionFallsBackToTheModuleVersion(t *testing.T) {
	pseudo := "v0.0.0-20260926201317-44236bb3bdba"
	for _, tc := range []struct {
		ldflags, module string
		info            bool
		want            string
	}{
		{"1.2.3", "v0.1.0", true, "1.2.3"},
		{"", "v0.1.0", true, "v0.1.0"},
		{"", pseudo, true, pseudo},
		{"", "(devel)", true, "dev"},
		{"", "", true, "dev"},
		{"", "", false, "dev"},
	} {
		read := func() (*debug.BuildInfo, bool) {
			if !tc.info {
				return nil, false
			}
			return &debug.BuildInfo{Main: debug.Module{Path: "github.com/qoryai/qory-github", Version: tc.module}}, true
		}
		if got := programVersion(tc.ldflags, read); got != tc.want {
			t.Errorf("ldflags %q, module %q, build info %v: %q, want %q", tc.ldflags, tc.module, tc.info, got, tc.want)
		}
	}
	schema, err := contracts.Compile("description.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(github.Describe(pseudo))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Errorf("the contract refuses the pseudo-version %s: %v", pseudo, err)
	}
}

// fakeGitHub answers the manifest flow's exchange with the App 123456 and a key.
func fakeGitHub(t *testing.T) string {
	t.Helper()
	_, pemBytes := keyFile(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/app-manifests/abc/conversions" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"id": 123456, "slug": "qory-github-test", "client_id": "Iv1.test", "html_url": "https://github.invalid/apps/qory-github-test", "pem": string(pemBytes)})
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// approve is the browser and the person: it reads the local page's state and follows
// GitHub's redirect with a code.
func approve(local string) error {
	resp, err := http.Get(local)
	if err != nil {
		return err
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	state := regexp.MustCompile(`state=([0-9a-f]+)`).FindSubmatch(b)
	if state == nil {
		return fmt.Errorf("the page contains no state:\n%s", b)
	}
	resp, err = http.Get(strings.TrimSuffix(local, "/") + "/callback?code=abc&state=" + string(state[1]))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// TestSetupPrintsTheDeclarationAndThePolicy runs setup whole and pins what it prints once
// the App is created: where it is installed, the integration's declaration, and the
// policy that allows GitHub's hosts and selects the credential qory expands it into.
func TestSetupPrintsTheDeclarationAndThePolicy(t *testing.T) {
	file := filepath.Join(t.TempDir(), "github-app.pem")
	s := github.Setup{Name: "qory-github-test", KeyFile: file, Web: "https://github.invalid", Client: github.Client{API: fakeGitHub(t)}, Open: approve, Wait: time.Minute}
	var out bytes.Buffer
	if err := runSetup(context.Background(), s, &out); err != nil {
		t.Fatal(err)
	}
	integrations, policy, err := declaration(123456, file)
	if err != nil {
		t.Fatal(err)
	}
	_, printed, _ := strings.Cut(out.String(), "\n\n")
	want := `The App 123456 (qory-github-test) is created, and its private key is in ` + file + `.

Install it on the repositories your agents work on:
  https://github.invalid/apps/qory-github-test/installations/new

Then declare the integration in the machine's configuration, ~/.config/qory/runner.yaml:

` + integrations + `
qory expands the declaration into the runner's credential github. A run's policy selects it
with the repositories the run works on, and allows GitHub's hosts beside the others the
run reaches:

` + policy
	if printed != want {
		t.Errorf("setup prints\n%s\nwant\n%s", printed, want)
	}
}

// TestADeclarationExpandsToWhatTheCredentialReads expands the declaration setup prints
// as the integration contract describes and hands the settings document, as it is, to
// what the command reads on standard input: a key file whose path has a quote and a
// dollar sign in it.
func TestADeclarationExpandsToWhatTheCredentialReads(t *testing.T) {
	file := filepath.Join(t.TempDir(), "it's ${argument}.pem")
	integrations, _, err := declaration(123456, file)
	if err != nil {
		t.Fatal(err)
	}
	credentials, stdin := expand(t, integrations)
	var c struct {
		Credentials map[string]struct {
			Adapter  []string `yaml:"adapter"`
			Argument string   `yaml:"argument"`
			Hosts    []string `yaml:"hosts"`
		} `yaml:"credentials"`
	}
	if err := yaml.Unmarshal([]byte(credentials), &c); err != nil {
		t.Fatalf("%v\n%s", err, credentials)
	}
	def := c.Credentials["github"]
	if strings.Join(def.Adapter, " ") != "qory-github credential -- ${argument}" {
		t.Fatalf("adapter %q", def.Adapter)
	}
	s, err := github.ReadSettings(strings.NewReader(stdin["github"]))
	if err != nil || s.AppID != "123456" || s.PrivateKeyFile != file {
		t.Errorf("settings %+v, %v", s, err)
	}
	d := github.Describe(version)
	if def.Argument != d.Roles.Credential.Argument || strings.Join(def.Hosts, " ") != strings.Join(d.Roles.Credential.Hosts, " ") {
		t.Errorf("definition %+v", def)
	}
}

// TestSetupRefusesAKeyPathItCannotDeclare pins that setup refuses, in one line and
// before the App is created, a key file's path the declaration cannot contain as it is
// written: a control character, C0, DEL or C1, or bytes that are not UTF-8.
func TestSetupRefusesAKeyPathItCannotDeclare(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"new\nline", "control character"},
		{"nul\x00", "control character"},
		{"del\x7f", "control character"},
		{"c1\u0085", "control character"},
		{"latin1\xe9", "not UTF-8"},
	} {
		opened := false
		s := github.Setup{Name: "qory-github-test", KeyFile: filepath.Join(t.TempDir(), tc.name+".pem"), Client: github.Client{API: "http://127.0.0.1:1"}, Open: func(string) error { opened = true; return nil }, Wait: time.Second}
		var out bytes.Buffer
		err := runSetup(context.Background(), s, &out)
		if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "\n") || opened || out.Len() != 0 {
			t.Errorf("%q: %v, opened %v, printed %q", tc.name, err, opened, out.String())
		}
	}
}

// TestSetupCreatesNothingForARefusedPath pins that a default key file under a home
// whose path setup refuses is refused before ~/.config/qory is created.
func TestSetupCreatesNothingForARefusedPath(t *testing.T) {
	home := filepath.Join(t.TempDir(), "h\x01me")
	t.Setenv("HOME", home)
	var out, errs bytes.Buffer
	if code := run(context.Background(), []string{"setup"}, nil, &out, &errs); code != 1 || !strings.Contains(errs.String(), "control character") || out.Len() != 0 {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errs.String())
	}
	if _, err := os.Stat(home); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("setup created %s: %v", home, err)
	}
}

// TestSetupPrintsWhereAMovedKeyIs creates the key file while the person approves, so the
// key goes beside it, and pins the line setup prints: where the key is, the file that
// could not be written once, and why.
func TestSetupPrintsWhereAMovedKeyIs(t *testing.T) {
	file := filepath.Join(t.TempDir(), "github-app.pem")
	open := func(local string) error {
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			return err
		}
		return approve(local)
	}
	s := github.Setup{Name: "qory-github-test", KeyFile: file, Web: "https://github.invalid", Client: github.Client{API: fakeGitHub(t)}, Open: open, Wait: time.Minute}
	var out bytes.Buffer
	if err := runSetup(context.Background(), s, &out); err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`\nThe key is in (\S+), since (\S+) could not be written: it exists\.\n`).FindStringSubmatch(out.String())
	if line == nil || !strings.HasPrefix(line[1], file+".") || line[2] != file || strings.Contains(out.String(), "choose another") {
		t.Errorf("setup prints\n%s", out.String())
	}
}

// TestTheReadmesShowWhatSetupPrints pins README.md to what setup prints for a
// key file of setup's own: the declaration and the policy, and no credential definition.
func TestTheReadmesShowWhatSetupPrints(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	integrations, policy, err := declaration(123456, "/home/dev/.config/qory/github-app.pem")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(readme, []byte("```yaml\n"+integrations+"```")) || !bytes.Contains(readme, []byte("```yaml\n"+policy+"```")) {
		t.Errorf("README.md does not show what setup prints:\n%s\n%s", integrations, policy)
	}
	if bytes.Contains(readme, []byte("    adapter: [")) {
		t.Error("README.md shows a credential definition, which qory expands from the declaration")
	}
}

// expand is a declaration as a reader expands it for a runner that hands the settings
// in on standard input, in the order declared: for each key, the credential of the same
// key, with the adapter [<program>, credential, --, "${argument}"], the program
// qory-<key> when none is declared, and the argument and the hosts of qory-github's
// description; and, by key, the settings document written to the program's standard
// input, the declaration's settings as compact JSON, {} when none are declared, with
// nothing in it replaced or escaped. How a definition gives the runner that document is
// the runner's contract, which this leaves out.
func expand(t *testing.T, integrations string) (string, map[string]string) {
	t.Helper()
	var doc struct {
		Integrations yaml.Node `yaml:"integrations"`
	}
	if err := yaml.Unmarshal([]byte(integrations), &doc); err != nil || doc.Integrations.Kind != yaml.MappingNode {
		t.Fatalf("%v\n%s", err, integrations)
	}
	var b strings.Builder
	b.WriteString("credentials:\n")
	stdin := map[string]string{}
	nodes := doc.Integrations.Content
	for i := 0; i+1 < len(nodes); i += 2 {
		key := nodes[i].Value
		var decl struct {
			Program  string         `yaml:"program"`
			Settings map[string]any `yaml:"settings"`
		}
		if err := nodes[i+1].Decode(&decl); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if decl.Program == "" {
			decl.Program = "qory-" + key
		}
		if decl.Settings == nil {
			decl.Settings = map[string]any{}
		}
		var settings bytes.Buffer
		enc := json.NewEncoder(&settings)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(decl.Settings); err != nil {
			t.Fatal(err)
		}
		if decl.Program != "qory-github" {
			t.Fatalf("%s: the program %s is not qory-github", key, decl.Program)
		}
		stdin[key] = settings.String()
		d := github.Describe(version)
		fmt.Fprintf(&b, `  %s:
    adapter: [%s, credential, --, "${argument}"]
    argument: %s
    hosts: [%s]
`, key, decl.Program, quote(d.Roles.Credential.Argument), strings.Join(d.Roles.Credential.Hosts, ", "))
	}
	return b.String(), stdin
}

// quote is YAML's single-quoted scalar, in which nothing is an escape but the quote,
// doubled.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func TestNoCommandIsUsage(t *testing.T) {
	var out, errs bytes.Buffer
	if code := run(context.Background(), nil, nil, &out, &errs); code != 2 || !strings.Contains(errs.String(), "usage:") {
		t.Errorf("exit %d: %s", code, errs.String())
	}
}
