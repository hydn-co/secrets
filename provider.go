// Package secrets loads secret values from environment first; if not set, loads from
// a vault via a configurable Provider (local, Azure Key Vault, or AWS).
//
// Environment variables (used by the default loader):
//   - SECRETS_BACKEND: local | azure | aws (default: local)
//   - AZURE_KEY_VAULT_URL: vault URL when backend is azure (e.g. https://myvault.vault.azure.net/)
//   - AZURE_CLIENT_ID: optional; when set, pins Azure auth to this managed identity client ID
package secrets

import (
	"os"
	"strings"
	"sync"

	"github.com/hydn-co/secrets/aws"
	"github.com/hydn-co/secrets/azure"
	"github.com/hydn-co/secrets/local"
)

const (
	EnvSecretsBackend   = "SECRETS_BACKEND"
	EnvAzureKeyVaultURL = "AZURE_KEY_VAULT_URL"
)

// Backend identifies which vault implementation to use.
type Backend string

const (
	BackendLocal Backend = "local"
	BackendAzure Backend = "azure"
	BackendAWS   Backend = "aws"
)

// Provider returns a secret by name. envKey is the environment variable name (e.g. MESH_CLIENT_SECRET);
// vaultName is the name in the vault (e.g. mesh-client-secret). Implementations may use one or both.
type Provider interface {
	GetSecret(envKey, vaultName string) (value string, ok bool)
	// SetSecret stores a secret in the vault (or no-op for local). Used by GetOrCreate when creating a new value.
	SetSecret(envKey, vaultName, value string) error
}

var (
	defaultProvider   Provider
	defaultProviderMu sync.Once
)

// DefaultProvider returns the Provider for the current SECRETS_BACKEND (local, azure, or aws).
func DefaultProvider() Provider {
	defaultProviderMu.Do(func() {
		switch GetBackend() {
		case BackendAzure:
			defaultProvider = azure.NewProvider(os.Getenv(EnvAzureKeyVaultURL))
		case BackendAWS:
			defaultProvider = aws.NewProvider()
		default:
			defaultProvider = local.Provider{}
		}
	})
	return defaultProvider
}

// GetBackend returns the current secrets backend from SECRETS_BACKEND (local | azure | aws).
// Default is local when unset or invalid.
func GetBackend() Backend {
	v, _ := os.LookupEnv(EnvSecretsBackend)
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "azure":
		return BackendAzure
	case "aws":
		return BackendAWS
	default:
		return BackendLocal
	}
}
