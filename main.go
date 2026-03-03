package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/plugin"

	oci "github.com/gordon/Hashicorp-OCI-credential-engine/oci-backend"
)

var Version = "v0.0.0-dev"

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "oci-secrets",
		Level:  hclog.LevelFromString(os.Getenv("VAULT_OCI_LOG_LEVEL")),
		Output: os.Stderr,
	})

	logger.Info("Starting OCI secrets engine plugin", "version", Version)

	err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: oci.Factory(Version),
		TLSProviderFunc:    oci.TLSProvider,
		Logger:             logger,
	})
	if err != nil {
		logger.Error("Error serving plugin", "error", err)
		os.Exit(1)
	}
}
