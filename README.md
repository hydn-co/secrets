# github.com/hydn-co/secrets

Load secrets from **env first**, then from a vault (Azure or AWS). One or two env vars in deployment; no need to wire every secret in Bicep.

## Usage

```go
import "github.com/hydn-co/secrets"

// Env wins; if unset, default provider (SECRETS_BACKEND) is used
id := secrets.GetSecret("MESH_CLIENT_ID", "mesh-client-id")
secret := secrets.MustGetSecret("JWT_SECRET", "jwt-secret") // panics if missing
```

Use a provider directly:

```go
import "github.com/hydn-co/secrets/azure"

p := azure.NewProvider("https://myvault.vault.azure.net/")
val, ok := p.GetSecret("", "my-secret-name")
```

## Provider interface

`GetSecret(envKey, vaultName string) (value string, ok bool)`

| Package | Behavior |
|---------|----------|
| `secrets/local` | Env only (`envKey`). |
| `secrets/azure` | Key Vault by `vaultName`; DefaultAzureCredential. |
| `secrets/aws` | Stub (not implemented). |

Root `GetSecret`/`MustGetSecret`: env first, then `DefaultProvider()` from `SECRETS_BACKEND`.

## Env vars

| Variable | Description |
|----------|-------------|
| `SECRETS_BACKEND` | `local` (default), `azure`, or `aws`. |
| `AZURE_KEY_VAULT_URL` | Vault URL when backend is `azure`. App identity needs Key Vault Secrets User. |

## Requirements

Go 1.21+. Azure: `azidentity` + `azsecrets`. AWS: not implemented.

**Monorepo:** In consumer `go.mod`, `replace github.com/hydn-co/secrets => ../secrets`.
