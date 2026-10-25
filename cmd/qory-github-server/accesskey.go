package main

import (
	"context"
	"io"
	"net/http"
	"os"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/qory-github/internal/cli"
	"github.com/qoryai/qory-github/internal/enrol"
	"github.com/qoryai/qory-github/internal/serve"
)

// accessKeyHelp is the help of access-key enrol, which has no section on qory-github's
// page: the command is switched on by QORY_FEATURES alone, see [cli.Factory].
//
// The enrol command's texts, this help and the lines and errors enrol prints, are
// placeholders awaiting the user's wording: they stay as they were but for the program's
// name until that wording replaces them.
var accessKeyHelp = cli.Help{
	Short: "Enrol the integration's access key with a code from Qory Apiary",
	Use:   "qory-github-server access-key enrol --secret-file FILE [--] SERVER CODE",
	Long: `Enrol a new access key for this integration with an enrolment code an instance
admin of Qory Apiary created on the adapter's Access key tab in Instance
settings. The code is valid for 15 minutes and used once.

qory-github-server makes the key, prints its fingerprint and sends Qory Apiary, at SERVER, the
public key. Qory Apiary's signed answer gives the key its id and lists Qory Apiary's
public key. Only then is the secret written, to --secret-file, which only you may
read. enrol never writes over a file that exists, and never prints the secret.

Then enrol prints the settings to add to serve's settings: apiary_url, access_key_id,
access_key_secret_file, apiary_public_key and adapter_id.`,
	Example: `  qory-github-server access-key enrol --secret-file /etc/qory-github/access-key-secret https://apiary.example.com "$code"`,
}

// adapterKind is what qory-github-server's access-key enrol takes: an integration's
// code, an adapter's, and the words its lines and errors name it with, as serve enrols
// one, see [serve.AdapterKind], with access-key enrol's help. Only an adapter's key is
// an integration's: a code for a node, a node pool or a gateway is refused.
func adapterKind() enrol.Kind {
	k := serve.AdapterKind(version)
	k.Help = accessKeyHelp
	return k
}

// enrol's test seams, see [enrol.Seams]: the key it makes; the access key's name, from
// this machine's host name; the client it posts with, nil for accesskey's; how the
// probe of the secret file's directory is removed; and how the secret file is created.
var (
	generateKey      = accesskey.Generate
	hostname         = os.Hostname
	enrolClient      *http.Client
	removeProbe      = os.Remove
	createSecretFile = enrol.CreateSecretFile
)

// accessKey runs access-key's one verb, enrol, as [enrol.AccessKey] runs it for an
// adapter's key.
func accessKey(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	seams := enrol.Seams{GenerateKey: generateKey, Hostname: hostname, Client: enrolClient, RemoveProbe: removeProbe, CreateSecretFile: createSecretFile}
	return enrol.AccessKey(ctx, adapterKind(), seams, args, stdout, stderr)
}
