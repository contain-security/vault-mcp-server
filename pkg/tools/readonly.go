// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package tools

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// readOnlyToolNames is the static allowlist of tools permitted to execute in
// read-only mode. It is deliberately maintained BY HAND, independently of the
// per-tool ReadOnly classification used at registration time, so that a
// single misclassified tool cannot defeat both enforcement layers
// (architecture review finding AR-005). TestReadOnlyAllowlistConsistency
// keeps the two in sync.
//
// A tool belongs here only if it neither alters Vault state nor mints or
// reveals credentials. Operations that sound like reads but produce
// credentials — reading an AppRole role-id, generating a secret-id, creating
// or renewing a token, issuing a certificate — must NOT be added.
var readOnlyToolNames = map[string]struct{}{
	// sys
	"list_mounts":   {},
	"seal_status":   {},
	"health_status": {},
	// kv
	"list_secrets": {},
	"read_secret":  {},
	// pki
	"list_pki_issuers":      {},
	"read_pki_issuer":       {},
	"list_pki_roles":        {},
	"read_pki_role":         {},
	"list_pki_certificates": {},
	"read_pki_certificate":  {},
	// ssh
	"read_ssh_ca":    {},
	"read_ssh_role":  {},
	"list_ssh_roles": {},
	// policy
	"list_policies": {},
	"read_policy":   {},
	// auth
	"list_auth_methods":   {},
	"list_userpass_users": {},
	"read_userpass_user":  {},
	// approle
	"list_approle_roles":               {},
	"read_approle_role":                {},
	"list_approle_secret_id_accessors": {},
	// token
	"lookup_token":         {},
	"list_token_accessors": {},
	// identity
	"list_entities": {},
	"read_entity":   {},
	"list_groups":   {},
	"read_group":    {},
	// audit
	"list_audit_devices": {},
	// lease
	"lookup_lease": {},
	"list_leases":  {},
}

// IsReadOnlyTool reports whether the named tool is in the static read-only
// allowlist.
func IsReadOnlyTool(name string) bool {
	_, ok := readOnlyToolNames[name]
	return ok
}

// ReadOnlyGuardMiddleware blocks every tool call not on the static read-only
// allowlist when read-only mode is active. This is the second enforcement
// layer: mutating tools are already never registered in read-only mode, so a
// rejection here indicates a registration bug — it is logged accordingly.
// Default-deny: unknown tool names are rejected.
func ReadOnlyGuardMiddleware(readOnly bool, logger *log.Logger) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if readOnly && !IsReadOnlyTool(req.Params.Name) {
				logger.WithField("tool", req.Params.Name).Warn(
					"Blocked non-read-only tool call in read-only mode; the tool should not have been registered")
				return mcp.NewToolResultError(fmt.Sprintf(
					"The Vault MCP server is running in read-only mode; tool '%s' is not permitted", req.Params.Name)), nil
			}
			return next(ctx, req)
		}
	}
}
