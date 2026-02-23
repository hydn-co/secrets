package secrets

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldReturnBackendFromEnv(t *testing.T) {
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
			// Arrange
			if tt.env != "" {
				os.Setenv(key, tt.env)
			} else {
				os.Unsetenv(key)
			}

			// Act
			got := GetBackend()

			// Assert
			assert.Equal(t, tt.want, got)
		})
	}
}
