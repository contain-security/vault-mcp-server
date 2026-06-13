// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package token provides MCP tools for managing Vault tokens.
//
// Security note: token creation is the highest-privilege-escalation-risk
// surface of this MCP server (see AR-002 in the architecture review).
// create_token enforces server-side guardrails that cannot be bypassed via
// tool arguments: the 'root' policy is always refused, TTLs are capped by
// cfg.TokenMaxTTL, and orphan/periodic tokens require cfg.AllowOrphanTokens.
// All tools in this package are in the admin category and are only
// registered when the operator explicitly enables admin tools.
package token

import (
	"github.com/hashicorp/vault-mcp-server/pkg/config"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/registry"
	log "github.com/sirupsen/logrus"
)

// Tools returns all token tools with their security classification.
//
// create_token and renew_token mint or extend credentials and are therefore
// NOT read-only even though renew_token might sound like a benign operation.
func Tools(logger *log.Logger, cfg config.Config) []registry.Tool {
	return []registry.Tool{
		{ServerTool: CreateToken(logger, cfg), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: LookupToken(logger), ReadOnly: true, Category: registry.CategoryAdmin},
		{ServerTool: RenewToken(logger), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: RevokeToken(logger), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: ListTokenAccessors(logger), ReadOnly: true, Category: registry.CategoryAdmin},
	}
}
