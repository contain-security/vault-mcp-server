## 0.3.0 (unreleased)

FEATURES

- Read-only mode (`VAULT_MCP_READ_ONLY` / `--read-only`): mutating and credential-minting tools are never registered and are additionally blocked at call time by an independent static allowlist
- Tiered tool gating: admin tools (`VAULT_MCP_ADMIN_TOOLS` / `--admin-tools`) and audit tools (`VAULT_MCP_AUDIT_TOOLS` / `--audit-tools`), both default off
- ACL policy tools: list, read, write, delete (built-in `root`/`default` protected)
- Auth method tools: list, enable, disable, tune; userpass user management
- AppRole tools: role CRUD, role-id, secret-id generate/list/destroy with `wrap_ttl` response-wrapping support
- Token tools: create (guard-railed: no root policy, TTL cap via `VAULT_MCP_TOKEN_MAX_TTL`, orphan/period gated by `VAULT_MCP_ALLOW_ORPHAN_TOKENS`, `wrap_ttl` support), lookup, renew, revoke (accessor-only), list accessors
- Identity tools: entities, entity aliases, groups
- Lease tools: lookup, list, revoke (single lease only — no prefix revocation)
- Audit device tools: list, enable, disable
- System tools: seal status, health, mount tuning; `create_mount` now supports transit, pki, ssh, database, and totp engines
- PKI: certificate list/read/revoke and full CA lifecycle (internal root generation, intermediate CSR, sign, set-signed)
- SSH secrets engine (certificate-signing mode): configure/read/delete CA signing key, signing-role CRUD, and SSH certificate signing (sign_ssh_key)
- MCP prompts: opinionated least-privilege workflow templates that compose the primitive tools — `setup_pki_approle`, `setup_ssh_approle`, `setup_kv_approle`, and `decommission_approle`. Gated to admin, non-read-only mode; deliver credentials response-wrapped
- Vault OSS test-bed (`../test-bed`) with seeded fixtures and a live MCP smoke-test script

SECURITY

- HTTP mode: the server's environment `VAULT_TOKEN` is never paired with a client-supplied `VAULT_ADDR`; sessions overriding the address must supply their own token
- HTTP mode: `VAULT_ADDR` is no longer accepted from query parameters (headers only)
- `VAULT_SKIP_VERIFY` is server-side configuration only; client-supplied values are ignored
- `0.0.0.0` is no longer treated as localhost for the TLS requirement; explicit `MCP_ALLOW_INSECURE_TRANSPORT=true` is required for plaintext non-localhost bindings

## 0.2.1

FEATURES

* Adding Gemini extension. See [56](https://github.com/hashicorp/vault-mcp-server/pull/56)

## 0.2.0

FEATURES

- Support for Vault PKI operations (create, list, read, delete)
- Comprehensive HTTP middleware stack (CORS, TLS, logging, Vault context, rate limiting)
- Session-based Vault client management
- Structured logging with configurable output

## 0.1.0

FEATURES

- Initial release of Vault MCP Server
- Support for Vault mount operations (create, list, delete)
- Support for Vault secret operations (read, write, list)
- Docker support
- Basic HTTP & STDIO transport support
