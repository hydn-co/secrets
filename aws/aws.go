// Package aws provides a secrets provider for AWS Secrets Manager.
// Not yet implemented; GetSecret always returns ("", false).
package aws

import "log/slog"

// Provider reads secrets from AWS Secrets Manager by vaultName. envKey is ignored.
type Provider struct{}

// NewProvider returns an AWS Provider. GetSecret is a stub until AWS SDK is added.
func NewProvider() *Provider {
	return &Provider{}
}

// GetSecret returns the secret value from AWS Secrets Manager for vaultName.
// Currently unimplemented and always returns ("", false).
func (p *Provider) GetSecret(envKey, vaultName string) (string, bool) {
	slog.Debug("secrets: AWS backend not implemented", "name", vaultName)
	return "", false
}

// SetSecret is a no-op until AWS Secrets Manager support is implemented.
func (p *Provider) SetSecret(envKey, vaultName, value string) error {
	return nil
}
