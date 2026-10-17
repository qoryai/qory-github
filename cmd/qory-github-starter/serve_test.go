package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/qoryai/forager/accesskey"
)

// serveRun runs serve with factory on, and returns the exit status, stdout and stderr.
func serveRun(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("QORY_FEATURES", "factory")
	var out, errs bytes.Buffer
	c := run(context.Background(), append([]string{"serve"}, args...), &out, &errs)
	return c, out.String(), errs.String()
}

// serveHelpText is serve's whole -h output.
const serveHelpText = `Claim the node pool's runs from Qory Apiary, and start the runner workflow for each.

serve claims the node pool's runs from Qory Apiary and, for each run of the explore
step, starts the workflow the settings name, in repository at ref, with the GitHub
App. It watches each job's workflow run to its end and tells Qory Apiary how the run
ended. It runs until it is stopped with SIGINT or SIGTERM.

serve serves the job's handover under public_url, at
POST /v1/dispatches/DISPATCH_ID/handover, where the job asks with its GitHub Actions
OIDC token for its run key. serve listens on listen, on plain HTTP: public_url must be
reachable by GitHub's runners over HTTPS, through a proxy in front that terminates
TLS.

The settings are one JSON document in FILE: apiary_url, access_key_id,
access_key_secret_file, apiary_public_key, listen, public_url, state_dir, app_id,
private_key_file, repository, workflow and ref, and pool_id, api_url and
workflow_sha, which may be left out. The access key's secret, in
access_key_secret_file, and the App's private key, in private_key_file, are each in a
file that belongs to the user serve runs as and that only that user may read.
state_dir keeps the instance id; serve makes it, 0700, when it does not exist and
its parent does.

usage:
  qory-github-starter serve --settings FILE

flags:
  -settings string
    	the settings file, one JSON document (required)

examples:
  qory-github-starter serve --settings /etc/qory-github-starter/starter.json
`

// TestServeHelpIsPinned pins serve's help, word for word.
func TestServeHelpIsPinned(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}} {
		code, out, errs := serveRun(t, args...)
		if code != 2 || out != "" || errs != serveHelpText {
			t.Errorf("%q: exit %d, stderr\n%s\nwant\n%s", args, code, errs, serveHelpText)
		}
	}
}

// TestServeUnknownFlag pins that a flag serve does not know prints the usage and flags
// alone, after the flag parser's message, then the error line, with exit 1 and nothing
// on standard output, as setup and template do.
func TestServeUnknownFlag(t *testing.T) {
	code, out, errs := serveRun(t, "--bogus")
	want := "flag provided but not defined: -bogus\n" + serveHelpText[strings.Index(serveHelpText, "usage:\n"):strings.Index(serveHelpText, "\nexamples:")] +
		"qory-github-starter serve: flag provided but not defined: -bogus\n"
	if code != 1 || out != "" || errs != want {
		t.Errorf("exit %d, stdout %q, stderr\n%s\nwant\n%s", code, out, errs, want)
	}
}

// counter is a fake server that answers 404 to every request and counts them.
func counter(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &n
}

// TestServeRefusesBeforeAnything pins serve's errors before it starts: no --settings,
// an argument, a settings file that cannot be read or is invalid, and settings whose
// access key secret or private key file is missing. Each is one line on standard error
// with exit 1 and nothing on standard output, and none sends a request to Qory Apiary or
// GitHub or makes the state directory.
func TestServeRefusesBeforeAnything(t *testing.T) {
	apiary, apiaryRequests := counter(t)
	api, gitHubRequests := counter(t)
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	server, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	access, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	accessFile := filepath.Join(dir, "access-key-secret")
	if err := os.WriteFile(accessFile, []byte(access.Secret()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := func(name, accessKeySecretFile string) string {
		b, err := json.Marshal(map[string]any{
			"apiary_url": apiary, "access_key_id": "ak_0123456789abcdef", "access_key_secret_file": accessKeySecretFile,
			"apiary_public_key": accesskey.Pin{{Alg: "ed25519", PublicKey: server.PublicKey().String()}}, "pool_id": poolID,
			"listen": "127.0.0.1:0", "public_url": "https://starter.example.com", "state_dir": state,
			"app_id": 1, "private_key_file": filepath.Join(dir, "missing.pem"), "api_url": api,
			"repository": "acme/qory-runner", "workflow": "qory-explore.yml", "ref": "main",
		})
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	invalid := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(invalid, []byte(`{"listen": "127.0.0.1:0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.json")
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "qory-github-starter serve: --settings is required\n"},
		{[]string{"--settings", invalid, "extra"}, "qory-github-starter serve: serve takes no arguments\n"},
		{[]string{"--settings", missing}, "qory-github-starter serve: the settings file: open " + missing + ": no such file or directory\n"},
		{[]string{"--settings", invalid}, "qory-github-starter serve: the settings are invalid: missing fields apiary_url, access_key_id, access_key_secret_file, apiary_public_key, public_url, state_dir, app_id, private_key_file, repository, workflow, ref\n"},
		{[]string{"--settings", settings("no-secret.json", filepath.Join(dir, "missing-secret"))}, "qory-github-starter serve: the file access_key_secret_file names: no such file or directory\n"},
		{[]string{"--settings", settings("no-key.json", accessFile)}, "qory-github-starter serve: the file private_key_file names: no such file or directory\n"},
	} {
		code, out, errs := serveRun(t, c.args...)
		if code != 1 || out != "" || errs != c.want {
			t.Errorf("%q: exit %d, stdout %q, stderr %q, want %q", c.args, code, out, errs, c.want)
		}
	}
	if n, m := apiaryRequests.Load(), gitHubRequests.Load(); n != 0 || m != 0 {
		t.Errorf("%d requests were sent to Qory Apiary and %d to GitHub", n, m)
	}
	if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the state directory was made: %v", err)
	}
}
