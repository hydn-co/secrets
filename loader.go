// Package secrets: loader provides the env-first facade and package-level API.
package secrets

import (
	"crypto/rand"
	"encoding/hex"
	"os"
)

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

// GetOrCreate returns the secret if present (env or vault); otherwise generates a new value,
// saves it to the target vault via the default provider, and returns it.
// If gen is nil, a 32-byte hex-encoded random value is used. Returns an error if the value
// was newly generated and saving to the vault failed.
func GetOrCreate(envKey, vaultName string, gen func() string) (string, error) {
	if s := GetSecret(envKey, vaultName); s != "" {
		return s, nil
	}
	var value string
	if gen != nil {
		value = gen()
	} else {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			panic("secrets: failed to generate random value: " + err.Error())
		}
		value = hex.EncodeToString(b)
	}
	if err := DefaultProvider().SetSecret(envKey, vaultName, value); err != nil {
		return "", err
	}
	return value, nil
}
