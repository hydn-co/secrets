package local

import (
	"os"
	"testing"
)

func TestProvider_GetSecret(t *testing.T) {
	p := Provider{}

	t.Run("returns value when env set", func(t *testing.T) {
		key := "TEST_SECRET_FOO"
		want := "my-secret-value"
		os.Setenv(key, want)
		t.Cleanup(func() { os.Unsetenv(key) })

		got, ok := p.GetSecret(key, "vault-name")
		if !ok || got != want {
			t.Errorf("GetSecret(%q, ...) = %q, %v; want %q, true", key, got, ok, want)
		}
	})

	t.Run("returns false when env unset", func(t *testing.T) {
		key := "TEST_SECRET_NEVER_SET_123"
		os.Unsetenv(key)

		got, ok := p.GetSecret(key, "vault-name")
		if ok || got != "" {
			t.Errorf("GetSecret(%q, ...) = %q, %v; want \"\", false", key, got, ok)
		}
	})

	t.Run("returns false when env empty", func(t *testing.T) {
		key := "TEST_SECRET_EMPTY"
		os.Setenv(key, "")
		t.Cleanup(func() { os.Unsetenv(key) })

		got, ok := p.GetSecret(key, "vault-name")
		if ok || got != "" {
			t.Errorf("GetSecret(%q, ...) = %q, %v; want \"\", false", key, got, ok)
		}
	})
}
