package main

import "github.com/qoryai/qory-github/internal/enrol"

// The names the server's tests use for what moved to internal/enrol, so those tests run
// as they did.
type secretFile = enrol.SecretFile

var (
	checkServer     = enrol.CheckServer
	hasCodeOrSecret = enrol.HasCodeOrSecret
	writeSecretFile = enrol.WriteSecretFile
)
