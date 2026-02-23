# Secrets

A lightweight Go helper for loading secrets with the following priority:
1. **Environment variables**
2. **Secret store** (Azure Key Vault, AWS, etc.)

The intent is to minimize configuration surface in deployments (often just
`SECRETS_BACKEND` and a vault URL) and avoid wiring every secret through
infrastructure code such as Bicep.

---

## Quick start

```go
import "github.com/hydn-co/secrets"

// lookup a value; env wins, otherwise the configured backend is used
id := secrets.GetSecret("MESH_CLIENT_ID", "mesh-client-id")

// panic if the secret is missing (useful during initialization)
secret := secrets.MustGetSecret("JWT_SECRET", "jwt-secret")
```

You can also work directly with a specific provider:

```go
import "github.com/hydn-co/secrets/azure"

p := azure.NewProvider("https://myvault.vault.azure.net/")
val, ok := p.GetSecret("", "my-secret-name")
```

---

## Provider interface

All providers implement:

```go
GetSecret(envKey, vaultName string) (value string, ok bool)
```

| Package             | Behavior                                                |
|---------------------|---------------------------------------------------------|
| `secrets/local`     | Environment only (key = `envKey`).                      |
| `secrets/azure`     | Azure Key Vault; uses `vaultName` and DefaultCredential.|
| `secrets/aws`       | Placeholder; not implemented yet.                       |

The root-level helpers (`GetSecret`, `MustGetSecret`) try the environment
first and fall back to `DefaultProvider()` which is chosen via
`SECRETS_BACKEND`.

---

## Configuration

Environment variables recognized by the library:

| Variable             | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| `SECRETS_BACKEND`    | `local` (default), `azure`, or `aws`. Determines the default provider.       |
| `AZURE_KEY_VAULT_URL`| Required when backend is `azure`; set to the vault URI.                    |

Additional provider-specific settings (e.g. AWS region) may be added in
future releases.

---

## Requirements

- Go **1.21 or newer**
- For Azure support: modules `github.com/Azure/azure-sdk-for-go/sdk/azidentity`
  and `.../sdk/keyvault/azsecrets`
- AWS support is currently a stub and must be implemented if needed


> **Monorepo tip:**
> in a consuming project’s `go.mod`, add a replace directive:
>
> ```go
> replace github.com/hydn-co/secrets => ../secrets
> ```

---

## Contributing

Contributions are welcome! Please open an issue or pull request for
new providers, bug fixes, or improvements.

---

## License

[MIT](LICENSE) (or whichever license is intended).
