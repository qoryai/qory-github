package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/qory-github/internal/ownerfile"
)

// keyFile is the App's private key, in a file only its owner reads.
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

// writeFile writes b to the file at path, 0600, and stops the test when it cannot.
func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// usageWithoutFactory is the usage without factory: the usage line alone, with no
// description and no command.
const usageWithoutFactory = `usage:
  qory-github-server <command> [flags]
`

// usageWithFactory is the usage with factory, which lists serve and access-key.
const usageWithFactory = `qory-github-server connects a GitHub App to Qory Apiary: it takes the App's webhook
deliveries and writes on GitHub what Qory Apiary's change feed says.

usage:
  qory-github-server <command> [flags]

commands:
  serve        Take the GitHub App's webhook deliveries
  access-key   Enrol the integration's access key with a code from Qory Apiary

qory-github-server <command> -h prints a command's help.
`

// TestTheProgramIsAbsentWithoutFactory pins that, unless QORY_FEATURES names factory,
// the program knows no command: whatever it is run with, it prints the usage that lists
// none and describes nothing, naming no hidden feature, command or what the program
// does, on standard error, and exits 2.
func TestTheProgramIsAbsentWithoutFactory(t *testing.T) {
	for _, features := range []string{"", " ", "all", "all-security", "all-security,factory", " all-factory", "factory2", "observability,security", "factory,all", "factory, all-security"} {
		t.Setenv("QORY_FEATURES", features)
		for _, args := range [][]string{nil, {"bogus"}, {"-h"}, {"--help"}, {"help"}, {"serve"}, {"serve", "-h"}, {"serve", "--settings", "/none.json"}} {
			var out, errs bytes.Buffer
			if code := run(context.Background(), args, &out, &errs); code != 2 || errs.String() != usageWithoutFactory || out.Len() != 0 {
				t.Errorf("QORY_FEATURES=%q %v: exit %d, %q", features, args, code, errs.String())
			}
			for _, hidden := range []string{"factory", "serve ", "access-key", "connects", "GitHub App", "Qory Apiary", "webhook", "deliveries", "change feed"} {
				if strings.Contains(errs.String(), hidden) {
					t.Errorf("QORY_FEATURES=%q %v: the usage names %s", features, args, hidden)
				}
			}
		}
	}
}

func TestServeIsPresentWithFactory(t *testing.T) {
	for _, features := range []string{"factory", "observability, factory ", " factory,", "observability,security,secrets,factory"} {
		t.Setenv("QORY_FEATURES", features)
		for _, args := range [][]string{nil, {"bogus"}, {"-h"}} {
			var out, errs bytes.Buffer
			if code := run(context.Background(), args, &out, &errs); code != 2 || errs.String() != usageWithFactory || out.Len() != 0 {
				t.Errorf("QORY_FEATURES=%q %v: exit %d, usage:\n%s", features, args, code, errs.String())
			}
		}
		var out, errs bytes.Buffer
		if code := run(context.Background(), []string{"serve", "-h"}, &out, &errs); code != 2 || !strings.Contains(errs.String(), "\nusage:\n  qory-github-server serve [--settings FILE]\n") || strings.Contains(errs.String(), "More:") ||
			!strings.Contains(errs.String(), "\nexamples:\n  qory-github-server serve --settings /etc/qory-github/serve.json   # the settings in a file\n  qory-github-server serve                                          # the settings in QORY_GITHUB_ variables\n") ||
			!strings.Contains(errs.String(), "\n  QORY_GITHUB_ACCESS_KEY_SECRET or QORY_GITHUB_ACCESS_KEY_SECRET_FILE\nAn empty variable counts as one not set.\n") {
			t.Errorf("QORY_FEATURES=%q: serve -h exits %d:\n%s", features, code, errs.String())
		}
		errs.Reset()
		// Without --settings, serve reads the environment, here one that sets none of its
		// variables.
		for _, name := range serveVariables {
			t.Setenv(name, "")
		}
		if code := run(context.Background(), []string{"serve"}, &out, &errs); code != 1 || errs.String() != "qory-github-server serve: the settings in the environment are invalid: missing variables QORY_GITHUB_LISTEN, QORY_GITHUB_STATE_DIR, QORY_GITHUB_APIARY_URL, QORY_GITHUB_PUBLIC_URL\n" {
			t.Errorf("QORY_FEATURES=%q: serve exits %d: %q", features, code, errs.String())
		}
		errs.Reset()
		if code := run(context.Background(), []string{"serve", "--bogus"}, &out, &errs); code != 1 || errs.String() != "flag provided but not defined: -bogus\nusage:\n  qory-github-server serve [--settings FILE]\n\nflags:\n  -settings string\n    \tthe settings file, one JSON document; without it the settings are read from QORY_GITHUB_ variables\nqory-github-server serve: flag provided but not defined: -bogus\n" {
			t.Errorf("QORY_FEATURES=%q: serve --bogus exits %d: %q", features, code, errs.String())
		}
	}
}

func TestServeRefusesSettingsItDoesNotKnow(t *testing.T) {
	t.Setenv("QORY_FEATURES", "factory")
	file := filepath.Join(t.TempDir(), "serve.json")
	writeFile(t, file, []byte(`{"app_id":1,"private_key_file":"/k","webhook_secret_file":"/s","listen":":0","state_dir":"/d","github_url":"https://api.github.com"}`))
	var out, errs bytes.Buffer
	if code := run(context.Background(), []string{"serve", "--settings", file}, &out, &errs); code != 1 || !strings.Contains(errs.String(), `unknown fields "app_id", "github_url", "private_key_file", "webhook_secret_file"`) || out.Len() != 0 {
		t.Errorf("exit %d: %q", code, errs.String())
	}
}

// readingFails is the line serve logs while it cannot reach Qory Apiary to read the App.
const readingFails = `"msg":"reading the GitHub App from Qory Apiary failed, and is tried again"`

// TestServeStopsOnItsContext runs serve whole, and stops it as a signal does.
func TestServeStopsOnItsContext(t *testing.T) {
	t.Setenv("QORY_FEATURES", "factory")
	dir := t.TempDir()
	access, _ := accesskey.Generate()
	server, _ := accesskey.Generate()
	accessFile := filepath.Join(dir, "access-key")
	writeFile(t, accessFile, []byte(access.Secret()+"\n"))
	// Qory Apiary is a loopback port nothing listens on: serve listens all the same,
	// and reads the App again after a wait.
	settings, _ := json.Marshal(map[string]any{"listen": "127.0.0.1:0", "state_dir": filepath.Join(dir, "state"),
		"apiary_url": "http://127.0.0.1:1", "public_url": "https://qory-github.example.com", "access_key_id": "ak_0123456789abcdef",
		"access_key_secret_file": accessFile, "apiary_public_key": []any{map[string]any{"alg": "ed25519", "public_key": server.PublicKey().String()}},
		"adapter_id": "na_0123456789abcdef", "upload_retry_seconds": 120})
	file := filepath.Join(dir, "serve.json")
	writeFile(t, file, settings)
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	errs := &lockedBuffer{}
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"serve", "--settings", file}, &out, errs) }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(errs.String(), readingFails) {
		if time.Now().After(deadline) {
			t.Fatalf("serve does not read the App: %s", errs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 || out.Len() != 0 || strings.Contains(errs.String(), access.Secret()) || !strings.Contains(errs.String(), `"msg":"stopped"`) {
			t.Errorf("exit %d, stdout %q, stderr %s", code, out.String(), errs.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve does not stop")
	}
}

// serveVariables are the environment variables serve reads its settings from.
var serveVariables = []string{
	"QORY_GITHUB_LISTEN", "QORY_GITHUB_STATE_DIR", "QORY_GITHUB_API_URL", "QORY_GITHUB_APIARY_URL", "QORY_GITHUB_APIARY_PUBLIC_URL",
	"QORY_GITHUB_PUBLIC_URL", "QORY_GITHUB_ACCESS_KEY_ID", "QORY_GITHUB_ACCESS_KEY_SECRET", "QORY_GITHUB_ACCESS_KEY_SECRET_FILE", "QORY_GITHUB_APIARY_PUBLIC_KEY",
	"QORY_GITHUB_ADAPTER_ID", "QORY_GITHUB_ENROLMENT_CODE_FILE", "QORY_GITHUB_PUBLIC_ADDRESS", "QORY_GITHUB_UPLOAD_RETRY_SECONDS",
	"QORY_GITHUB_CALL_URL",
}

// TestServeReadsTheEnvironmentWithoutSettings runs serve whole without --settings, the
// access key's secret a value in the environment, and stops it as a signal does; with
// --settings, the environment is not read. The variables of the App that settings
// gave before are not read.
func TestServeReadsTheEnvironmentWithoutSettings(t *testing.T) {
	dir := t.TempDir()
	_, key := keyFile(t)
	access, _ := accesskey.Generate()
	server, _ := accesskey.Generate()
	pin, _ := json.Marshal([]any{map[string]any{"alg": "ed25519", "public_key": server.PublicKey().String()}})
	env := map[string]string{
		"QORY_GITHUB_APP_ID": "1", "QORY_GITHUB_APP_SLUG": "qory-acme", "QORY_GITHUB_CLIENT_ID": "Iv1.acme",
		"QORY_GITHUB_PRIVATE_KEY": string(key), "QORY_GITHUB_WEBHOOK_SECRET": "s3cr3t-0123456789abcdef", "QORY_GITHUB_CLIENT_SECRET": "c1ient-s3cr3t",
		"QORY_GITHUB_LISTEN": "127.0.0.1:0", "QORY_GITHUB_STATE_DIR": filepath.Join(dir, "state"),
		"QORY_GITHUB_APIARY_URL": "http://127.0.0.1:1", "QORY_GITHUB_PUBLIC_URL": "https://qory-github.example.com", "QORY_GITHUB_UPLOAD_RETRY_SECONDS": "120",
		"QORY_GITHUB_ACCESS_KEY_ID": "ak_0123456789abcdef", "QORY_GITHUB_ACCESS_KEY_SECRET": access.Secret(),
		"QORY_GITHUB_APIARY_PUBLIC_KEY": string(pin), "QORY_GITHUB_ADAPTER_ID": "na_0123456789abcdef",
	}
	lookup := func(name string) (string, bool) { v, ok := env[name]; return v, ok }
	ctx, cancel := context.WithCancel(context.Background())
	errs := &lockedBuffer{}
	done := make(chan error, 1)
	go func() { done <- runServe(ctx, nil, errs, lookup) }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(errs.String(), readingFails) {
		if time.Now().After(deadline) {
			t.Fatalf("serve does not read the App: %s", errs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil || strings.Contains(errs.String(), "s3cr3t") || strings.Contains(errs.String(), access.Secret()) || strings.Contains(errs.String(), "c1ient") || strings.Contains(errs.String(), "PRIVATE KEY") {
			t.Errorf("err %v, stderr %s", err, errs.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve does not stop")
	}
	// With --settings the file alone is read: a file that lacks listen is refused for
	// it, though the environment gives listen.
	file := filepath.Join(dir, "serve.json")
	writeFile(t, file, []byte(`{"state_dir":"/d","apiary_url":"https://apiary.example.com","public_url":"https://qory-github.example.com"}`))
	if err := runServe(context.Background(), []string{"--settings", file}, errs, lookup); err == nil || err.Error() != "the settings are invalid: missing fields listen" {
		t.Errorf("err %v", err)
	}
	// --settings given empty names no file, and is refused: the environment is not read
	// in its place.
	for _, args := range [][]string{{"--settings", ""}, {"--settings="}, {"-settings", ""}} {
		if err := runServe(context.Background(), args, errs, lookup); err == nil || err.Error() != "--settings names no file" {
			t.Errorf("%q: err %v", args, err)
		}
	}
}

// lockedBuffer is a buffer serve writes while a test reads it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// othersFile is a file's info as Stat gives it, 0600 and another user's.
type othersFile struct{ fs.FileInfo }

func (othersFile) Mode() fs.FileMode { return 0o600 }
func (othersFile) Sys() any          { return &syscall.Stat_t{Uid: uint32(os.Geteuid() + 1)} }

// TestAnotherUsersFileNamesQoryGithubServer pins that a secret file or the store that
// belongs to another user is refused with an error that names the program running,
// qory-github-server.
func TestAnotherUsersFileNamesQoryGithubServer(t *testing.T) {
	err := ownerfile.Check(othersFile{}, "the store /var/lib/qory-github/qory-github.db")
	if want := "the store /var/lib/qory-github/qory-github.db belongs to another user than the one qory-github-server runs as"; err == nil || err.Error() != want {
		t.Errorf("err %v, want %q", err, want)
	}
}

// TestServeHelpSaysTheAppSetup pins the lines serve's help says of the App setup, of
// /health and of public_address, each a sentence whatever the help's line breaks.
func TestServeHelpSaysTheAppSetup(t *testing.T) {
	t.Setenv("QORY_FEATURES", "factory")
	var out, errs bytes.Buffer
	run(context.Background(), []string{"serve", "-h"}, &out, &errs)
	help := strings.Join(strings.Fields(errs.String()), " ")
	for _, want := range []string{
		"No setting contains the GitHub App. Qory Apiary stores it: its id, slug, client id, private key, webhook secret and client secret.",
		"At each start serve reads the App from Qory Apiary, sealed to its access key, and keeps it in memory; serve writes none of it to disk.",
		"Until Qory Apiary stores an App, serve serves GitHub's App setup at public_url's /setup, which an instance admin opens with Set up in Qory Apiary.",
		"GitHub issues the App's private key once: when storing the App in Qory Apiary fails, the setup tries again for upload_retry_seconds, and then shows which App to delete on GitHub.",
		"upload_retry_seconds is how long the App setup tries again to store the App in Qory Apiary, 60 to 86400; left out, it is 600.",
		"/health answers 200 from the first moment.",
		"public_address, false when GitHub cannot reach public_url: the App setup creates has its webhook inactive, and serve learns of changes on GitHub by pulling. Left out, it is true.",
		"QORY_GITHUB_PUBLIC_ADDRESS for public_address",
		"Without call_url, serve takes no call.",
		"public_url is the adapter's host name only, such as https://github.example.com, so GitHub sends the deliveries to https://github.example.com/v1/events.",
		"Set call_url to the address Qory Apiary sends the calls to: public_url followed by /v1/calls/, such as https://github.example.com/v1/calls/.",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("the help lacks %q:\n%s", want, errs.String())
		}
	}
}
