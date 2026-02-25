// Package azure provides a secrets provider that reads from Azure Key Vault
// using the REST API only (no Azure SDK).
package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// keyVaultAPIVersion: 7.4 is supported; 2025-07-01 is also valid per Azure REST docs.
	keyVaultAPIVersion = "7.4"
	vaultResource      = "https://vault.azure.net" // scope for token requests; audience in JWT is same
	tokenCacheTTL      = 55 * time.Minute
)

// Provider reads secrets from Azure Key Vault by vaultName. envKey is ignored.
// Auth: client credentials (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
// or Managed Identity (IMDS / App Service / Container Apps), same pattern as streamkit azurekit.
type Provider struct {
	vaultURL   string
	httpClient *http.Client
	miCred     *managedIdentityCredential
	mu         sync.Mutex
	token      string
	tokenUntil time.Time
}

// NewProvider returns an Azure Provider for the given vault URL (e.g. https://myvault.vault.azure.net/).
// If vaultURL is empty, GetSecret will always return ("", false).
func NewProvider(vaultURL string) *Provider {
	vaultURL = strings.TrimRight(vaultURL, "/")
	if vaultURL != "" && !strings.HasSuffix(vaultURL, "/") {
		vaultURL += "/"
	}
	return &Provider{
		vaultURL:   vaultURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		miCred:     newManagedIdentityCredential(getEnv("AZURE_CLIENT_ID")),
	}
}

// GetSecret returns the secret value from Key Vault for vaultName, or ("", false) on error or if vault URL is unset.
func (p *Provider) GetSecret(envKey, vaultName string) (string, bool) {
	if p.vaultURL == "" {
		slog.Debug("secrets: Azure vault URL not set")
		return "", false
	}
	token, err := p.getToken()
	if err != nil {
		slog.Debug("secrets: Azure token failed", "error", err)
		return "", false
	}
	// GET {vaultBaseUrl}/secrets/{secret-name}?api-version=... (omit secret-version for latest). Secret name: path-escaped.
	reqURL := p.vaultURL + "secrets/" + url.PathEscape(vaultName) + "?api-version=" + keyVaultAPIVersion
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, reqURL, nil)
	if err != nil {
		slog.Debug("secrets: Azure GetSecret request build failed", "error", err)
		return "", false
	}
	// Key Vault REST: Authorization Bearer token; Accept application/json (response is SecretBundle JSON).
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		slog.Debug("secrets: Azure GetSecret failed", "name", vaultName, "error", err)
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			p.invalidateToken()
			if p.miCred != nil {
				p.miCred.invalidate()
			}
		}
		slog.Debug("secrets: Azure GetSecret failed", "name", vaultName, "status", resp.StatusCode)
		return "", false
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		slog.Debug("secrets: Azure GetSecret decode failed", "name", vaultName, "error", err)
		return "", false
	}
	return out.Value, true
}

// SetSecret stores the secret in Azure Key Vault under vaultName.
func (p *Provider) SetSecret(envKey, vaultName, value string) error {
	if p.vaultURL == "" {
		return nil
	}
	token, err := p.getToken()
	if err != nil {
		return err
	}
	// PUT {vaultBaseUrl}/secrets/{secret-name}?api-version=...; body JSON SecretSetParameters with required "value".
	reqURL := p.vaultURL + "secrets/" + url.PathEscape(vaultName) + "?api-version=" + keyVaultAPIVersion
	body, _ := json.Marshal(map[string]string{"value": value})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, reqURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	// Key Vault REST: Authorization Bearer; Content-Type and Accept application/json (request/response SecretSetParameters/SecretBundle).
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		p.invalidateToken()
		if p.miCred != nil {
			p.miCred.invalidate()
		}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("azure key vault: %s %s", resp.Status, string(b))
	}
	return nil
}

func (p *Provider) getToken() (string, error) {
	p.mu.Lock()
	if p.token != "" && time.Now().Before(p.tokenUntil) {
		t := p.token
		p.mu.Unlock()
		return t, nil
	}
	p.mu.Unlock()

	token, err := p.acquireToken()
	if err != nil {
		return "", err
	}

	p.mu.Lock()
	p.token = token
	p.tokenUntil = time.Now().Add(tokenCacheTTL)
	p.mu.Unlock()
	return token, nil
}

func (p *Provider) invalidateToken() {
	p.mu.Lock()
	p.token = ""
	p.mu.Unlock()
}

func (p *Provider) acquireToken() (string, error) {
	if t, err := p.tokenClientCredentials(); err == nil && t != "" {
		return t, nil
	}
	if t, err := p.tokenAzureCLI(); err == nil && t != "" {
		return t, nil
	}
	if p.miCred != nil {
		if t, err := p.miCred.getToken(context.Background()); err == nil && t != "" {
			return t, nil
		}
	}
	return "", fmt.Errorf("no Azure credential: use az login, or set AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET, or run in Azure with managed identity")
}

func (p *Provider) tokenClientCredentials() (string, error) {
	tenantID := getEnv("AZURE_TENANT_ID")
	clientID := getEnv("AZURE_CLIENT_ID")
	clientSecret := getEnv("AZURE_CLIENT_SECRET")
	if tenantID == "" || clientID == "" || clientSecret == "" {
		return "", fmt.Errorf("client credentials not set")
	}
	// Microsoft identity platform client credentials: POST form with application/x-www-form-urlencoded.
	// Scope must be resource + /.default (e.g. https://vault.azure.net/.default). Client secret must be URL-encoded.
	u := "https://login.microsoftonline.com/" + url.PathEscape(tenantID) + "/oauth2/v2.0/token"
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("scope", vaultResource+"/.default")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, u, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.AccessToken, nil
}

// tokenAzureCLI returns a token from the Azure CLI (az login). Safe to call when az is not installed or not logged in.
func (p *Provider) tokenAzureCLI() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "az", "account", "get-access-token", "--resource", vaultResource, "--query", "accessToken", "-o", "tsv")
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", ctx.Err()
		}
		return "", err
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", fmt.Errorf("az returned empty token")
	}
	return token, nil
}

func getEnv(key string) string {
	return strings.TrimSpace(strings.Trim(os.Getenv(key), "\""))
}
