package local

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldReturnValueWhenEnvSet(t *testing.T) {
	// Arrange
	p := Provider{}
	key := "TEST_SECRET_FOO"
	want := "my-secret-value"
	os.Setenv(key, want)
	t.Cleanup(func() { os.Unsetenv(key) })

	// Act
	got, ok := p.GetSecret(key, "vault-name")

	// Assert
	require.True(t, ok)
	assert.Equal(t, want, got)
}

func TestShouldReturnFalseWhenEnvUnset(t *testing.T) {
	// Arrange
	p := Provider{}
	key := "TEST_SECRET_NEVER_SET_123"
	os.Unsetenv(key)

	// Act
	got, ok := p.GetSecret(key, "vault-name")

	// Assert
	require.False(t, ok)
	assert.Empty(t, got)
}

func TestShouldReturnFalseWhenEnvEmpty(t *testing.T) {
	// Arrange
	p := Provider{}
	key := "TEST_SECRET_EMPTY"
	os.Setenv(key, "")
	t.Cleanup(func() { os.Unsetenv(key) })

	// Act
	got, ok := p.GetSecret(key, "vault-name")

	// Assert
	require.False(t, ok)
	assert.Empty(t, got)
}
