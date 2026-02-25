// Credentials for Azure Key Vault: copied/adapted from streamkit pkg/storage/azurekit.
// ManagedIdentityCredential uses IMDS or App Service/Container Apps (IDENTITY_ENDPOINT/IDENTITY_HEADER).

package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tokenRefreshBuffer   = 5 * time.Minute
	imdsRequestTimeout   = 10 * time.Second
	imdsAPIVersion       = "2018-02-01"
	appServiceAPIVersion = "2019-08-01"
)

// managedIdentityCredential acquires tokens from Azure IMDS or App Service/Container Apps.
// Resource is fixed to https://vault.azure.net for Key Vault.
type managedIdentityCredential struct {
	clientID         string
	resource         string
	token            string
	tokenExpiry      time.Time
	mu               sync.RWMutex
	httpClient       *http.Client
	imdsEndpoint     string
	identityEndpoint string
	identityHeader   string
	useAppService    bool
}

type imdsTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresOn   string `json:"expires_on"`
}

// newManagedIdentityCredential creates a credential for Key Vault (resource https://vault.azure.net).
// clientID is optional (use empty for system-assigned identity).
func newManagedIdentityCredential(clientID string) *managedIdentityCredential {
	cred := &managedIdentityCredential{
		clientID:   strings.TrimSpace(clientID),
		resource:   vaultResource,
		httpClient: &http.Client{Timeout: imdsRequestTimeout},
	}
	identityEndpoint := os.Getenv("IDENTITY_ENDPOINT")
	identityHeader := os.Getenv("IDENTITY_HEADER")
	if identityEndpoint != "" && identityHeader != "" {
		cred.identityEndpoint = identityEndpoint
		cred.identityHeader = identityHeader
		cred.useAppService = true
		slog.Debug("secrets: Azure managed identity using App Service/Container Apps endpoint")
	} else {
		cred.imdsEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"
		slog.Debug("secrets: Azure managed identity using IMDS endpoint")
	}
	return cred
}

func (c *managedIdentityCredential) getToken(ctx context.Context) (string, error) {
	c.mu.RLock()
	cachedToken := c.token
	cachedExpiry := c.tokenExpiry
	c.mu.RUnlock()

	if cachedToken != "" && time.Now().Before(cachedExpiry.Add(-tokenRefreshBuffer)) {
		return cachedToken, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.tokenExpiry.Add(-tokenRefreshBuffer)) {
		return c.token, nil
	}

	query := url.Values{}
	query.Set("resource", c.resource)
	if c.clientID != "" {
		query.Set("client_id", c.clientID)
	}

	var reqURL string
	endpointType := "IMDS"
	if c.useAppService {
		query.Set("api-version", appServiceAPIVersion)
		reqURL = fmt.Sprintf("%s?%s", c.identityEndpoint, query.Encode())
		endpointType = "AppService"
	} else {
		query.Set("api-version", imdsAPIVersion)
		reqURL = fmt.Sprintf("%s?%s", c.imdsEndpoint, query.Encode())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("create %s request: %w", endpointType, err)
	}
	// Per Azure docs: IMDS requires header "Metadata: true" (SSRF protection).
	// App Service / Container Apps use IDENTITY_HEADER value in "X-IDENTITY-HEADER".
	if c.useAppService {
		req.Header.Set("X-IDENTITY-HEADER", c.identityHeader)
	} else {
		req.Header.Set("Metadata", "true")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("call %s endpoint: %w", endpointType, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		slog.Debug("secrets: Azure managed identity token failed", "status", resp.StatusCode, "body", string(body))
		return "", fmt.Errorf("%s returned %d: %s", endpointType, resp.StatusCode, string(body))
	}

	var tokenResp imdsTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	expiresOn, err := strconv.ParseInt(tokenResp.ExpiresOn, 10, 64)
	if err != nil {
		return "", fmt.Errorf("parse token expiry: %w", err)
	}

	c.tokenExpiry = time.Unix(expiresOn, 0)
	c.token = tokenResp.AccessToken
	logKeyVaultJWTClaims(c.token, endpointType)
	return c.token, nil
}

func (c *managedIdentityCredential) invalidate() {
	c.mu.Lock()
	c.token = ""
	c.mu.Unlock()
}

func logKeyVaultJWTClaims(token, endpointType string) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return
	}
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return
	}
	var claims map[string]interface{}
	if json.Unmarshal(decoded, &claims) != nil {
		return
	}
	aud, _ := claims["aud"].(string)
	expectedAud := "https://vault.azure.net"
	if aud != "" && aud != expectedAud && aud != expectedAud+"/" {
		slog.Warn("secrets: Azure token audience mismatch (Key Vault)", "got", aud, "expected", expectedAud, "endpoint_type", endpointType)
	}
}
