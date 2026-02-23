// Package local provides a secrets provider that reads only from the process environment.
package local

import "os"

// Provider reads secrets from environment variables (envKey). vaultName is ignored.
type Provider struct{}

// GetSecret returns the value of the environment variable envKey, or ("", false) if unset or empty.
func (Provider) GetSecret(envKey, vaultName string) (string, bool) {
	v, ok := os.LookupEnv(envKey)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}
