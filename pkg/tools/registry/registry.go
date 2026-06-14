// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package registry defines the tool registration model used by all tool
// packages. It exists as its own package (rather than living in pkg/tools)
// so that individual tool packages can reference it without an import cycle.
package registry

import (
	"github.com/mark3labs/mcp-go/server"
)

// Category groups tools into separately-gated capability tiers.
type Category string

const (
	// CategoryCore tools (mounts, KV, PKI, system health) are always available.
	CategoryCore Category = "core"
	// CategoryAdmin tools (policies, auth methods, AppRole, tokens, identity,
	// leases) administer Vault's security configuration and are only
	// registered when the server is explicitly started with admin tools
	// enabled.
	CategoryAdmin Category = "admin"
	// CategoryAudit tools manage audit devices. Disabling an audit device
	// destroys the audit trail, so these are gated behind their own flag.
	CategoryAudit Category = "audit"
)

// Tool wraps an MCP server tool with the security classification used to
// decide whether it is registered at startup.
//
// ReadOnly deliberately defaults (zero value) to false: an unclassified tool
// is treated as mutating and therefore hidden in read-only mode. The
// classification here controls registration only; an independent static
// allowlist in pkg/tools enforces read-only mode at call time as a second
// layer (see AR-005 in the architecture review).
//
// ReadOnly must be true only for tools that neither alter Vault state nor
// mint or reveal credentials. Credential-producing operations that sound
// like reads (reading an AppRole role-id, generating a secret-id, creating
// or renewing a token, issuing a certificate) are NOT read-only.
type Tool struct {
	server.ServerTool
	ReadOnly bool
	Category Category
}
