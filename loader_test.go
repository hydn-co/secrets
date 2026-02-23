package secrets

import (
	"os"
	"testing"
)

func TestGetSecret_envWins(t *testing.T) {
	// Ensure default provider is local so we don't hit Azure/AWS
	os.Setenv(EnvSecretsBackend, "local")
	t.Cleanup(func() {
		os.Unsetenv(EnvSecretsBackend)
		os.Unsetenv("TEST_GETSECRET_ENV_KEY")
	})

	key := "TEST_GETSECRET_ENV_KEY"
	want := "from-env"
	os.Setenv(key, want)

	got := GetSecret(key, "vault-name")
	if got != want {
		t.Errorf("GetSecret(%q, ...) = %q; want %q", key, got, want)
	}
}

func TestGetSecret_fallsBackWhenUnset(t *testing.T) {
	os.Setenv(EnvSecretsBackend, "local")
	t.Cleanup(func() {
		os.Unsetenv(EnvSecretsBackend)
		os.Unsetenv("TEST_GETSECRET_UNSET_KEY")
	})

	os.Unsetenv("TEST_GETSECRET_UNSET_KEY")
	got := GetSecret("TEST_GETSECRET_UNSET_KEY", "vault-name")
	if got != "" {
		t.Errorf("GetSecret(unset, ...) = %q; want \"\"", got)
	}
}

func TestMustGetSecret_panicsWhenMissing(t *testing.T) {
	os.Setenv(EnvSecretsBackend, "local")
	t.Cleanup(func() {
		os.Unsetenv(EnvSecretsBackend)
		os.Unsetenv("TEST_MUSTSECRET_MISSING")
	})
	os.Unsetenv("TEST_MUSTSECRET_MISSING")

	defer func() {
		if r := recover(); r == nil {
			t.Error("MustGetSecret expected to panic")
		}
	}()
	MustGetSecret("TEST_MUSTSECRET_MISSING", "vault-name")
}
