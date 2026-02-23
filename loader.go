// Package secrets: loader provides the env-first facade and package-level API.
package secrets

import "os"

// GetSecret returns the secret value: environment variable envKey first, then the default Provider (vault).
// vaultName is the name used in the vault (e.g. mesh-client-secret).
func GetSecret(envKey, vaultName string) string {
	if v, ok := os.LookupEnv(envKey); ok && v != "" {
		return v
	}
	val, ok := DefaultProvider().GetSecret(envKey, vaultName)
	if !ok {
		return ""
	}
	return val
}

// MustGetSecret returns the secret value or panics if missing (for startup/critical config).
func MustGetSecret(envKey, vaultName string) string {
	s := GetSecret(envKey, vaultName)
	if s == "" {
		panic("required secret not set: " + envKey + " (env or vault " + vaultName + ")")
	}
	return s
}
