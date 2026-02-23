// Package azure provides a secrets provider that reads from Azure Key Vault.
package azure

import (
	"context"
	"log/slog"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// Provider reads secrets from Azure Key Vault by vaultName. envKey is ignored.
// Uses DefaultAzureCredential (managed identity, CLI, env).
type Provider struct {
	vaultURL string
	client   *azsecrets.Client
	mu       sync.Mutex
}

// NewProvider returns an Azure Provider for the given vault URL (e.g. https://myvault.vault.azure.net/).
// If vaultURL is empty, GetSecret will always return ("", false).
func NewProvider(vaultURL string) *Provider {
	return &Provider{vaultURL: vaultURL}
}

// GetSecret returns the secret value from Key Vault for vaultName, or ("", false) on error or if vault URL is unset.
func (p *Provider) GetSecret(envKey, vaultName string) (string, bool) {
	if p.vaultURL == "" {
		slog.Debug("secrets: Azure vault URL not set")
		return "", false
	}
	client, err := p.clientForVault()
	if err != nil {
		slog.Debug("secrets: Azure client failed", "error", err)
		return "", false
	}
	ctx := context.Background()
	resp, err := client.GetSecret(ctx, vaultName, "", nil)
	if err != nil {
		slog.Debug("secrets: Azure GetSecret failed", "name", vaultName, "error", err)
		return "", false
	}
	if resp.Value == nil {
		return "", false
	}
	return *resp.Value, true
}

func (p *Provider) clientForVault() (*azsecrets.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client != nil {
		return p.client, nil
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	client, err := azsecrets.NewClient(p.vaultURL, cred, nil)
	if err != nil {
		return nil, err
	}
	p.client = client
	return p.client, nil
}
