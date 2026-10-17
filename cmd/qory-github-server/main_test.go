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
		if code := run(context.Background(), []string{"serve", "-h"}, &out, &errs); code != 2 || !strings.Contains(errs.String(), "\nusage:\n  qory-github-server serve --settings FILE\n") || !strings.Contains(errs.String(), "\nexamples:\n  qory-github-server serve --settings /etc/qory-github/serve.json\n") || strings.Contains(errs.String(), "More:") {
			t.Errorf("QORY_FEATURES=%q: serve -h exits %d:\n%s", features, code, errs.String())
		}
		errs.Reset()
		if code := run(context.Background(), []string{"serve"}, &out, &errs); code != 1 || errs.String() != "qory-github-server serve: --settings is required\n" {
			t.Errorf("QORY_FEATURES=%q: serve exits %d: %q", features, code, errs.String())
		}
		errs.Reset()
		if code := run(context.Background(), []string{"serve", "--bogus"}, &out, &errs); code != 1 || errs.String() != "flag provided but not defined: -bogus\nusage:\n  qory-github-server serve --settings FILE\n\nflags:\n  -settings string\n    \tthe settings file, one JSON document (required)\nqory-github-server serve: flag provided but not defined: -bogus\n" {
			t.Errorf("QORY_FEATURES=%q: serve --bogus exits %d: %q", features, code, errs.String())
		}
	}
}

func TestServeRefusesSettingsItDoesNotKnow(t *testing.T) {
	t.Setenv("QORY_FEATURES", "factory")
	file := filepath.Join(t.TempDir(), "serve.json")
	os.WriteFile(file, []byte(`{"app_id":1,"private_key_file":"/k","webhook_secret_file":"/s","listen":":0","state_dir":"/d","github_url":"https://api.github.com"}`), 0o600)
	var out, errs bytes.Buffer
	if code := run(context.Background(), []string{"serve", "--settings", file}, &out, &errs); code != 1 || !strings.Contains(errs.String(), `unknown fields "github_url"`) || out.Len() != 0 {
		t.Errorf("exit %d: %q", code, errs.String())
	}
}

// TestServeStopsOnItsContext runs serve whole, and stops it as a signal does.
func TestServeStopsOnItsContext(t *testing.T) {
	t.Setenv("QORY_FEATURES", "factory")
	dir := t.TempDir()
	key, _ := keyFile(t)
	secret := filepath.Join(dir, "secret")
	os.WriteFile(secret, []byte("s3cr3t-0123456789abcdef\n"), 0o600)
	access, _ := accesskey.Generate()
	server, _ := accesskey.Generate()
	accessFile := filepath.Join(dir, "access-key")
	os.WriteFile(accessFile, []byte(access.Secret()+"\n"), 0o600)
	clientFile := filepath.Join(dir, "client-secret")
	os.WriteFile(clientFile, []byte("c1ient-s3cr3t\n"), 0o600)
	// Qory Apiary is a loopback port nothing listens on: serve serves all the same,
	// and declares the adapter again after a wait.
	settings, _ := json.Marshal(map[string]any{"app_id": 1, "private_key_file": key, "webhook_secret_file": secret, "listen": "127.0.0.1:0", "state_dir": filepath.Join(dir, "state"),
		"app_slug": "qory-acme", "apiary_url": "http://127.0.0.1:1", "public_url": "https://qory-github.example.com", "access_key_id": "ak_0123456789abcdef",
		"access_key_secret_file": accessFile, "apiary_public_key": []any{map[string]any{"alg": "ed25519", "public_key": server.PublicKey().String()}},
		"adapter_id": "na_0123456789abcdef", "client_id": "Iv1.acme", "client_secret_file": clientFile})
	file := filepath.Join(dir, "serve.json")
	os.WriteFile(file, settings, 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	errs := &lockedBuffer{}
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"serve", "--settings", file}, &out, errs) }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(errs.String(), `"msg":"serving"`) {
		if time.Now().After(deadline) {
			t.Fatalf("serve does not serve: %s", errs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 || out.Len() != 0 || strings.Contains(errs.String(), "s3cr3t") || strings.Contains(errs.String(), access.Secret()) || strings.Contains(errs.String(), "c1ient") {
			t.Errorf("exit %d, stdout %q, stderr %s", code, out.String(), errs.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve does not stop")
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
