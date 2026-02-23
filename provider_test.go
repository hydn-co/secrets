package secrets

import (
	"os"
	"testing"
)

func TestGetBackend(t *testing.T) {
	key := EnvSecretsBackend
	t.Cleanup(func() { os.Unsetenv(key) })

	tests := []struct {
		name string
		env  string
		want Backend
	}{
		{"unset", "", BackendLocal},
		{"local", "local", BackendLocal},
		{"azure", "azure", BackendAzure},
		{"aws", "aws", BackendAWS},
		{"Azure case", "Azure", BackendAzure},
		{"trimmed", "  azure  ", BackendAzure},
		{"unknown", "unknown", BackendLocal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				os.Setenv(key, tt.env)
			} else {
				os.Unsetenv(key)
			}
			got := GetBackend()
			if got != tt.want {
				t.Errorf("GetBackend() with %q = %v; want %v", tt.env, got, tt.want)
			}
		})
	}
}
