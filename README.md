# <img src="public/images/Vault-LogoMark_onDark.svg" width="30" align="left" style="margin-right: 12px;"/> Vault MCP Server

> ## ⚠️ Independent fork — not a HashiCorp or IBM release
>
> This repository is a **fork of [`hashicorp/vault-mcp-server`](https://github.com/hashicorp/vault-mcp-server)**, independently maintained by **[contain.security](https://github.com/contain-security)**. It has been **substantially modified** beyond the upstream project — adding opt-in admin/audit tool tiers, a default-deny [read-only mode](#security-model), guard-railed token & credential tooling, and least-privilege [workflow prompts](#prompts).
>
> It is **not affiliated with, endorsed by, or supported by HashiCorp or IBM.** "HashiCorp" and "Vault" are trademarks of HashiCorp; used here only to describe interoperability. This fork is distributed under the same [Mozilla Public License 2.0](LICENSE) as the upstream project.

This fork of the Vault MCP Server is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/introduction)
server implementation that provides integration with HashiCorp
Vault for managing secrets and mounts. This server uses both stdio and StreamableHTTP
transports for MCP communication, making it compatible with Claude for Desktop 
and other MCP clients.

> **Security Note:** At this stage, the MCP server is intended for local use only. If using the StreamableHTTP transport, always configure the MCP_ALLOWED_ORIGINS environment variable to restrict access to trusted origins only. This helps prevent DNS rebinding attacks and other cross-origin vulnerabilities.

> **Security Note:** Depending on the query, the MCP server may expose certain Vault data, including Vault secrets, to the MCP client and LLM. Do not use the MCP server with untrusted MCP clients or LLMs.

> **Legal Note:** Your use of a third party MCP Client/LLM is subject solely to the terms of use for such MCP/LLM, and IBM is not responsible for the performance of such third party tools. IBM expressly disclaims any and all warranties and liability for third party MCP Clients/LLMs, and may not be able to provide support to resolve issues which are caused by the third party tools. 

> **Caution:**  The outputs and recommendations provided by the MCP server are generated dynamically and may vary based on the query, model, and the connected MCP client. Users should thoroughly review all outputs/recommendations to ensure they align with their organization’s security best practices, cost-efficiency goals, and compliance requirements before implementation.

## Features

- **75 tools** covering Vault administration end to end:
  - Secret engines: create/list/delete/tune mounts (kv, kv2, transit, pki, ssh, database, totp)
  - KV secrets: read, write, list, delete (v1 and v2)
  - PKI: issuers, roles, certificate issuance, full CA lifecycle (root, intermediate CSR, sign, set-signed), certificate list/read/revoke
  - SSH: CA signing-key configuration, signing-role management, SSH certificate signing
  - ACL policies: list, read, write, delete
  - Auth methods: list, enable, disable, tune; userpass user management
  - AppRole: role CRUD, role-id, secret-id generation (with response wrapping), accessor management
  - Tokens: create (guard-railed), lookup, renew, revoke, accessor listing
  - Identity: entities, entity aliases, groups
  - Leases: lookup, list, revoke (single-lease only)
  - Audit devices: list, enable, disable
  - System: seal status, health
- **Read-only mode** (`VAULT_MCP_READ_ONLY=true` / `--read-only`): the AI agent cannot alter Vault — see [Security model](#security-model)
- **Tiered tool gating**: admin and audit tool groups are opt-in
- **Workflow prompts**: opinionated, least-privilege provisioning workflows (e.g. set up an AppRole for PKI/SSH signing) surfaced as MCP prompts — see [Prompts](#prompts)
- Comprehensive HTTP middleware stack (CORS, logging, rate limiting, Vault context)
- Session-based Vault client management
- Structured logging with configurable output
- A disposable [Vault OSS test-bed](../test-bed/README.md) for developing and testing against a live Vault

## Security model

Tools are registered in three tiers, all controlled server-side (environment
variables or CLI flags — never by the MCP client):

| Tier | Tools | Gate | Default |
|---|---|---|---|
| Core | mounts, KV, PKI, seal/health | always on | on |
| Admin | policies, auth methods, AppRole, tokens, identity, leases | `VAULT_MCP_ADMIN_TOOLS=true` / `--admin-tools` | **off** |
| Audit | audit device management | `VAULT_MCP_AUDIT_TOOLS=true` / `--audit-tools` | **off** |

**Read-only mode** (`VAULT_MCP_READ_ONLY=true` / `--read-only`) applies on top
of whatever tiers are enabled and is enforced in two independent layers:

1. Tools that alter Vault or mint/reveal credentials are **never registered**
   — the AI agent cannot even see them.
2. A call-time middleware rejects, default-deny, any tool not on a
   hand-maintained static allowlist (so a single misclassified tool cannot
   defeat the mode). A unit test keeps both layers in sync.

Operations that *sound* like reads but produce credentials — reading an
AppRole role-id, generating a secret-id, creating/renewing a token, issuing a
certificate — are deliberately **not** read-only. Note that read-only mode
still permits reading KV secret *values*; "read-only" means the agent cannot
alter Vault, not that it sees no secrets.

**Token-creation guardrails** (server-side, not bypassable by the client):
`create_token` refuses the `root` policy, refuses TTLs above
`VAULT_MCP_TOKEN_MAX_TTL` (default 768h), and refuses orphan/periodic tokens
unless `VAULT_MCP_ALLOW_ORPHAN_TOKENS=true`.

**Response wrapping**: `create_token` and `generate_approle_secret_id` accept
a `wrap_ttl` parameter so only a single-use wrapping token — not the
credential itself — enters the LLM conversation context. Strongly recommended.

**Residual risks to keep in mind** (in addition to the security notes above):

- The MCP server can only do what its Vault token's policies allow. Read-only
  mode and tier gating are brakes on top of Vault ACLs, not substitutes —
  pair read-only mode with a read-only Vault token for defense in depth.
- Content stored in Vault (secret values, policy documents, metadata) is read
  into the LLM context and could carry injected instructions. With admin
  tools enabled and a privileged token, a successful injection could chain
  policy-write → token-create. Keep admin tools off when you don't need them.
- `create_entity_alias` can bind an auth-method login to an existing
  privileged entity (a classic Vault privilege-escalation vector). Verify the
  target entity's policies before binding.
- Disabling an audit device destroys the audit trail; the audit tier exists
  precisely so this stays a deliberate human decision.

## Prerequisites
- Go 1.24 or later (if building from source)
- Docker
- HashiCorp Vault server running locally or remotely
- A valid Vault token with appropriate permissions

## Setup

1. Clone the repository:
    ```bash
    git clone https://github.com/hashicorp/vault-mcp-server.git
    cd vault-mcp-server
    ```

2. Build the binary:
    ```bash
    make build
    ```

3. Run the server:

    **Stdio mode (default):**
    ```bash
    ./vault-mcp-server
    # or explicitly
    ./vault-mcp-server stdio
    ```

    **HTTP mode:**
    ```bash
    ./vault-mcp-server http --transport-port 8080
    # or using make
    make run-http
    ```

## Environment Variables

The server can be configured using environment variables:

- `VAULT_ADDR`: Vault server address (default: `http://127.0.0.1:8200`)
- `VAULT_TOKEN`: Vault authentication token (required)
- `VAULT_NAMESPACE`: Vault namespace (optional)
- `VAULT_SKIP_VERIFY`: Skip TLS verification of the Vault connection (server-side only; never accepted from MCP clients)
- `VAULT_MCP_READ_ONLY`: Set to `true` for read-only mode (default: `false`)
- `VAULT_MCP_ADMIN_TOOLS`: Set to `true` to enable admin tools (default: `false`)
- `VAULT_MCP_AUDIT_TOOLS`: Set to `true` to enable audit device tools (default: `false`)
- `VAULT_MCP_TOKEN_MAX_TTL`: TTL cap for tokens minted via `create_token` (default: `768h`)
- `VAULT_MCP_ALLOW_ORPHAN_TOKENS`: Set to `true` to let `create_token` mint orphan/periodic tokens (default: `false`)
- `MCP_ALLOW_INSECURE_TRANSPORT`: Set to `true` to allow plaintext HTTP on a non-localhost binding (e.g. inside a container behind a TLS-terminating proxy). Without it, non-localhost bindings require TLS (default: `false`)
- `TRANSPORT_MODE`: Set to `http` to enable HTTP mode
- `TRANSPORT_HOST`: Host to bind to for HTTP mode (default: `127.0.0.1`)
- `TRANSPORT_PORT`: Port for HTTP mode (default: `8080`)
- `MCP_ENDPOINT`: HTTP server endpoint path (default: `/mcp`)
- `MCP_ALLOWED_ORIGINS`: Comma-separated list of allowed origins for CORS (default: `""`)
- `MCP_CORS_MODE`: CORS mode: `strict`, `development`, or `disabled` (default: `strict`)
- `MCP_TLS_CERT_FILE`: Location of the TLS certificate file (e.g. `/path/to/cert.pem`) (default: `""`)
- `MCP_TLS_KEY_FILE`: Location of the TLS key file (e.g. `/path/to/key.pem`)(default: `""`)
- `MCP_RATE_LIMIT_GLOBAL`: Global rate limit (format: `rps:burst`) (default: `10:20`)
- `MCP_RATE_LIMIT_SESSION`: Per-session rate limit (format: `rps:burst`) (default: `5:10`)

## HTTP Mode Configuration

In HTTP mode, Vault configuration can be provided through (in order of precedence):

- **HTTP Headers**: `VAULT_ADDR`, `X-Vault-Token`, and `X-Vault-Namespace`
- **Environment Variables**: Standard `VAULT_ADDR`, `VAULT_TOKEN`, and `VAULT_NAMESPACE` env vars

Security rules enforced by the server:

- The Vault token is accepted from headers only — never query parameters.
- `VAULT_ADDR` is accepted from headers only — never query parameters.
- A session that supplies its own `VAULT_ADDR` must also supply its own
  `X-Vault-Token`; the server will never send its environment token to a
  client-chosen address.
- `VAULT_SKIP_VERIFY` is server-side configuration only and is ignored if
  sent by a client.

### Middleware Stack

The HTTP server includes a comprehensive middleware stack:

- **CORS Middleware**: Enables cross-origin requests with appropriate headers
- **Vault Context Middleware**: Extracts Vault configuration and adds to request context
- **Logging Middleware**: Structured HTTP request logging

## Integration with Visual Studio Code

1. In your project workspace root, create or open the `.vscode/mcp.json` configuration file. Alternatively, to add an MCP to your user configuration, run the `MCP: Open User Configuration` command, which opens the mcp.json file in your user profile. If the file does not exist, VS Code creates it for you.

    <table>
    <tr><th>Streamable HTTP mode</th><th>Stdio mode</th></tr>
    <tr valign=top>
    <td>

    ```json
        {
            "inputs": [
            {
                "type": "promptString",
                "id": "vault_token",
                "description": "Vault Token",
                "password": true
            },
            {
                "type": "promptString",
                "id": "vault_namespace",
                "description": "Vault Namespace (optional)",
                "password": false
            }
            ],
            "servers": {
                "vault-mcp-server": {
                    "url": "http://localhost:8080/mcp?VAULT_ADDR=http://127.0.0.1:8200",
                    "headers": {
                        "X-Vault-Token": "${input:vault_token}",
                        "X-Vault-Namespace": "${input:vault_namespace}"
                    }
                }
            }
        }
    ```

    </td>
    <td>

    ```json
        {
            "inputs": [
            {
                "type": "promptString",
                "id": "vault_token",
                "description": "Vault Token",
                "password": true
            },
            {
                "type": "promptString",
                "id": "vault_namespace",
                "description": "Vault Namespace (optional)",
                "password": false
            },
            {
                "type": "promptString",
                "id": "vault_addr",
                "description": "Vault Address (optional)",
                "password": false
            }
            ],
            "servers": {
            "vault-mcp-server": {
                "command": "docker",
                "args": [
                    "run",
                    "-i",
                    "--rm",
                    "-e", "VAULT_ADDR=${input:vault_addr}",
                    "-e", "VAULT_TOKEN=${input:vault_token}",
                    "-e", "VAULT_NAMESPACE=${input:vault_namespace}",
                    "hashicorp/vault-mcp-server"
                    ]
                }
            }
        }
    ```

    </td>
    </tr>
    </table>

1. Save `mcp.json` file.

1. Restart Visual Studio Code (or reload the window).

**Note:** Visual Studio Code will prompt you for the VAULT_TOKEN once and store it securely in the client.

## Integration with Gemini extensions


For security, avoid hardcoding your credentials, create or update `~/.gemini/.env` (where ~ is your home or project directory) for storing Vault Address, Token and Namespace

```
# ~/.gemini/.env
VAULT_ADDR=your_vault_addr_here
VAULT_TOKEN=your_vault_token_here
VAULT_NAMESPACE=your_vault_namespace_here
```

Install the extension & run Gemini

```
gemini extensions install https://github.com/hashicorp/vault-mcp-server
gemini
```


## Working with Docker

Build the docker image:

```bash
make docker-build
```

Build the image with a custom registry:
```bash
make docker-build DOCKER_REGISTRY=your-registry.com
```

Push the image to a custom registry:
```bash
make docker-push DOCKER_REGISTRY=your-registry.com
```

Run the Vault container and get the root token:

```bash
docker network create mcp
docker run --cap-add=IPC_LOCK --name=vault-dev --network=mcp -p 8200:8200 hashicorp/vault server -dev
docker logs vault-dev
```

Run the Vault MCP server:

```bash
docker run --network=mcp -p 8080:8080 -e VAULT_ADDR='http://vault-dev:8200' -e VAULT_TOKEN='<your-token-from-last-step>' -e TRANSPORT_MODE='http' vault-mcp-server:dev
```

## Available Tools

75 tools in three tiers. **RO** marks tools available in read-only mode.
Read-only excludes anything that mints or reveals credentials, even when the
underlying HTTP call is a read.

### Core tier (always registered)

| Tool | RO | Description |
|---|---|---|
| `list_mounts` | ✓ | List all secret engine mounts |
| `create_mount` | | Mount a secrets engine (kv, kv2, transit, pki, ssh, database, totp) |
| `delete_mount` | | Unmount a secrets engine (destroys its data) |
| `tune_mount` | | Tune mount TTLs / description |
| `seal_status` | ✓ | Seal status, progress, threshold |
| `health_status` | ✓ | Health: initialized, sealed, standby, version |
| `list_secrets` | ✓ | List KV secrets under a path |
| `read_secret` | ✓ | Read a KV secret (v1 and v2) |
| `write_secret` | | Write/update a KV secret |
| `delete_secret` | | Delete a KV secret or a single key |
| `enable_pki` | | Enable and configure a PKI engine |
| `create_pki_issuer` | | Import a PEM cert/key as an issuer |
| `list_pki_issuers` / `read_pki_issuer` | ✓ | Inspect issuers |
| `list_pki_roles` / `read_pki_role` | ✓ | Inspect PKI roles |
| `create_pki_role` / `delete_pki_role` | | Manage PKI roles |
| `issue_pki_certificate` | | Issue a certificate from a role (mints key material) |
| `list_pki_certificates` / `read_pki_certificate` | ✓ | Inspect issued certificates |
| `revoke_pki_certificate` | | Revoke a certificate (permanent, joins CRL) |
| `generate_pki_root` | | Generate a root CA (internal — private key never leaves Vault) |
| `generate_pki_intermediate_csr` | | Generate an intermediate CSR (internal) |
| `sign_pki_intermediate` | | Sign an intermediate CSR with the root |
| `set_pki_signed_intermediate` | | Install the signed intermediate certificate |
| `configure_ssh_ca` | | Configure an SSH mount's CA signing key (generates internally by default) |
| `read_ssh_ca` | ✓ | Read the SSH CA public key |
| `delete_ssh_ca` | | Delete the SSH CA signing key |
| `create_ssh_role` | | Create/update an SSH CA signing role (user or host certs) |
| `list_ssh_roles` / `read_ssh_role` | ✓ | Inspect SSH roles |
| `delete_ssh_role` | | Delete an SSH role |
| `sign_ssh_key` | | Sign an SSH public key into a short-lived certificate (mints a credential) |

### Admin tier (`VAULT_MCP_ADMIN_TOOLS=true` / `--admin-tools`)

| Tool | RO | Description |
|---|---|---|
| `list_policies` / `read_policy` | ✓ | Inspect ACL policies |
| `write_policy` | | Create/update an ACL policy from HCL (refuses `root`/`default`) |
| `delete_policy` | | Delete an ACL policy (refuses `root`/`default`) |
| `list_auth_methods` | ✓ | List enabled auth methods with accessors |
| `enable_auth_method` | | Enable an auth method (userpass, approle, ldap, oidc, ...) |
| `disable_auth_method` | | Disable an auth method (refuses `token`; invalidates its tokens) |
| `tune_auth_method` | | Tune auth method TTLs / description |
| `list_userpass_users` / `read_userpass_user` | ✓ | Inspect userpass users |
| `write_userpass_user` | | Create/update a userpass user (refuses `root` policy) |
| `delete_userpass_user` | | Delete a userpass user |
| `list_approle_roles` / `read_approle_role` | ✓ | Inspect AppRole roles |
| `write_approle_role` | | Create/update an AppRole role (refuses `root` policy) |
| `delete_approle_role` | | Delete an AppRole role |
| `read_approle_role_id` | | Read a role-id (half of a login credential) |
| `generate_approle_secret_id` | | Generate a secret-id; supports `wrap_ttl` (recommended) |
| `list_approle_secret_id_accessors` | ✓ | List secret-id accessors |
| `destroy_approle_secret_id` | | Destroy a secret-id by accessor |
| `create_token` | | Mint a token (guard-railed: no root policy, TTL cap, orphan gated); supports `wrap_ttl` |
| `lookup_token` | ✓ | Look up self or by accessor (metadata only) |
| `renew_token` | | Renew self or by accessor |
| `revoke_token` | | Revoke by accessor (also revokes children) |
| `list_token_accessors` | ✓ | List all token accessors (sudo) |
| `list_entities` / `read_entity` | ✓ | Inspect identity entities |
| `write_entity` / `delete_entity` | | Manage entities (refuses `root` policy) |
| `create_entity_alias` | | Bind an auth login to an entity (privilege-escalation sensitive) |
| `delete_entity_alias` | | Delete an entity alias by ID |
| `list_groups` / `read_group` | ✓ | Inspect identity groups |
| `write_group` / `delete_group` | | Manage identity groups (refuses `root` policy) |
| `lookup_lease` / `list_leases` | ✓ | Inspect leases (list requires sudo) |
| `revoke_lease` | | Revoke a single lease (prefix/mass revocation refused) |

### Audit tier (`VAULT_MCP_AUDIT_TOOLS=true` / `--audit-tools`)

| Tool | RO | Description |
|---|---|---|
| `list_audit_devices` | ✓ | List audit devices |
| `enable_audit_device` | | Enable a file/syslog/socket audit device |
| `disable_audit_device` | | Disable an audit device (destroys the audit trail — deliberate human decision) |

## Prompts

The server ships **MCP prompts** — parameterized, opinionated workflow
templates that compose the primitive tools into the higher-level operations an
administrator is repeatedly asked for. In MCP clients they surface as
selectable prompts / slash commands (e.g. `/mcp__vault__setup_pki_approle`).

All current prompts provision or tear down credentials, so they only appear
when **admin tools are enabled and read-only mode is off** (`VAULT_MCP_ADMIN_TOOLS=true`,
without `VAULT_MCP_READ_ONLY`). They drive the existing tools — so the same
gating, validation, and audit logging apply to every step.

| Prompt | What it does |
|---|---|
| `setup_pki_approle` | Provision a least-privilege AppRole that can `issue` or `sign` certs against a single PKI role. Scoped policy (only `<mount>/<action>/<role>`), AppRole role, response-wrapped secret-id. Args: `app_name`, `pki_mount`, `pki_role`, `action`, TTLs, `wrap_ttl`. |
| `setup_ssh_approle` | Same pattern for SSH CA signing — policy scoped to `<mount>/sign/<role>`. Args: `app_name`, `ssh_mount`, `ssh_role`, TTLs, `wrap_ttl`. |
| `setup_kv_approle` | AppRole for `read` or `read-write` access to a single KV path (handles v1/v2 path shapes). Args: `app_name`, `kv_mount`, `kv_path`, `access`, TTLs, `wrap_ttl`. |
| `decommission_approle` | Cleanly tear down an AppRole: destroy its secret-ids, delete the role, and (optionally) delete only its dedicated policies — never shared/built-in ones. Args: `app_name`, `approle_mount`, `delete_policies`. |

Every setup prompt enforces strict least-privilege scoping, merges into an
existing AppRole rather than clobbering it, and delivers the secret-id as a
single-use response-wrapping token (never a raw secret-id in the transcript).

## Command Line Usage

```bash
# Show help
./vault-mcp-server --help

# Run in stdio mode (default)
./vault-mcp-server
./vault-mcp-server stdio

# Run in HTTP mode
./vault-mcp-server http --transport-port 8080 --transport-host 127.0.0.1

# Show version
./vault-mcp-server --version

# Run with custom log file
./vault-mcp-server --log-file /path/to/logfile.log
```

## Using the MCP Inspector

You can use
the [@modelcontextprotocol/inspector](https://www.npmjs.com/package/@modelcontextprotocol/inspector)
tool to inspect and interact with your running Vault MCP server via a web UI.

For HTTP mode:
```bash
npx @modelcontextprotocol/inspector http://localhost:8080/mcp
```

For stdio mode:
```bash
npx @modelcontextprotocol/inspector ./vault-mcp-server
```

## Development

### Building

```bash
# Build the binary
make build

# Build with Docker
make docker-build

# Clean build artifacts
make clean
```

### Testing

```bash
# Run tests
make test

# Run end-to-end tests
make test-e2e

# Test HTTP endpoint
make test-http
```

### Project Structure

```
vault-mcp-server/
├── bin/                                  # Binary output directory
│   └── vault-mcp-server                  # Compiled binary
├── cmd/vault-mcp-server/                 # Main application entry point
│   ├── init.go                           # Initialization code
│   └── main.go                           # Main application
├── pkg/                                  # Package directory
│   ├── client/                           # Client implementation
│   │   ├── client.go                     # Core client functionality
│   │   └── middleware.go                 # HTTP middleware
│   ├── tools/                            # MCP tools implementation
│   │   ├── kv/                           # Key-Value tools
│   │   ├── pki/                          # PKI certificate tools
│   │   ├── sys/                          # System management tools
│   │   └── tools.go                      # Tool registration
│   └── utils/                            # Utility functions
├── scripts/                              # Build and utility scripts
├── version/                              # Version information
├── e2e/                                  # End-to-end tests
├── Dockerfile                            # Container build definition
├── Makefile                              # Build automation
├── go.mod                                # Go module definition
└── LICENSE                               # License information
```

## Support

This fork is maintained by **[contain.security](https://github.com/contain-security)**. For bug reports and feature requests **specific to this fork**, please open an [issue on this repository](https://github.com/contain-security/vault-mcp-server/issues).

For questions about the original, unmodified Vault MCP Server, refer to the [upstream project](https://github.com/hashicorp/vault-mcp-server).

## Upstream & attribution

This project is a fork of [`hashicorp/vault-mcp-server`](https://github.com/hashicorp/vault-mcp-server),
© HashiCorp, Inc., licensed under the [Mozilla Public License 2.0](LICENSE). Files
modified by this fork retain that license; substantial functionality has been
added and changed by [contain.security](https://github.com/contain-security) (see
[Features](#features) and [Security model](#security-model)).

"HashiCorp", "Vault", and related marks and logos are trademarks of HashiCorp and
are used here solely to describe interoperability. This fork is not affiliated with,
endorsed by, or supported by HashiCorp or IBM.
