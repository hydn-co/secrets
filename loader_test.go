package secrets

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldReturnEnvValueWhenKeySet(t *testing.T) {
	// Arrange
	os.Setenv(EnvSecretsBackend, "local")
	t.Cleanup(func() {
		os.Unsetenv(EnvSecretsBackend)
		os.Unsetenv("TEST_GETSECRET_ENV_KEY")
	})
	key := "TEST_GETSECRET_ENV_KEY"
	want := "from-env"
	os.Setenv(key, want)

	// Act
	got := GetSecret(key, "vault-name")

	// Assert
	assert.Equal(t, want, got)
}

func TestShouldReturnEmptyWhenKeyUnset(t *testing.T) {
	// Arrange
	os.Setenv(EnvSecretsBackend, "local")
	t.Cleanup(func() {
		os.Unsetenv(EnvSecretsBackend)
		os.Unsetenv("TEST_GETSECRET_UNSET_KEY")
	})
	os.Unsetenv("TEST_GETSECRET_UNSET_KEY")

	// Act
	got := GetSecret("TEST_GETSECRET_UNSET_KEY", "vault-name")

	// Assert
	assert.Empty(t, got)
}

func TestShouldPanicWhenSecretMissing(t *testing.T) {
	// Arrange
	os.Setenv(EnvSecretsBackend, "local")
	t.Cleanup(func() {
		os.Unsetenv(EnvSecretsBackend)
		os.Unsetenv("TEST_MUSTSECRET_MISSING")
	})
	os.Unsetenv("TEST_MUSTSECRET_MISSING")

	// Act & Assert
	require.Panics(t, func() {
		MustGetSecret("TEST_MUSTSECRET_MISSING", "vault-name")
	})
}

func TestShouldReturnExistingValueWhenGetOrCreateAndKeySet(t *testing.T) {
	// Arrange
	os.Setenv(EnvSecretsBackend, "local")
	key := "TEST_GETORCREATE_EXISTS"
	os.Setenv(key, "existing-value")
	t.Cleanup(func() {
		os.Unsetenv(EnvSecretsBackend)
		os.Unsetenv(key)
	})

	// Act
	got, err := GetOrCreate(key, "vault-name", nil)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "existing-value", got)
}

func TestShouldReturnHexStringWhenGetOrCreateAndKeyUnsetAndNoGenerator(t *testing.T) {
	// Arrange
	os.Setenv(EnvSecretsBackend, "local")
	key := "TEST_GETORCREATE_MISSING"
	os.Unsetenv(key)
	t.Cleanup(func() {
		os.Unsetenv(EnvSecretsBackend)
		os.Unsetenv(key)
	})

	// Act
	got, err := GetOrCreate(key, "vault-name", nil)

	// Assert
	require.NoError(t, err)
	require.Len(t, got, 64, "expected 32-byte hex (64 chars)")
	assert.Regexp(t, regexp.MustCompile(`^[0-9a-f]{64}$`), got)
}

func TestShouldReturnGeneratedValueWhenGetOrCreateAndKeyUnsetAndGeneratorProvided(t *testing.T) {
	// Arrange
	os.Setenv(EnvSecretsBackend, "local")
	key := "TEST_GETORCREATE_GEN"
	os.Unsetenv(key)
	t.Cleanup(func() {
		os.Unsetenv(EnvSecretsBackend)
		os.Unsetenv(key)
	})
	gen := func() string { return "custom-generated" }

	// Act
	got, err := GetOrCreate(key, "vault-name", gen)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "custom-generated", got)
}
