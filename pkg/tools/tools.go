// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package tools

import (
	"github.com/hashicorp/vault-mcp-server/pkg/config"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/approle"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/audit"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/auth"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/identity"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/kv"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/lease"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/pki"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/policy"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/registry"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/ssh"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/sys"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/token"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// allTools collects every tool from every tool package, with its security
// classification. Gating (category flags, read-only mode) happens in
// InitTools; this list is the complete capability surface.
func allTools(logger *log.Logger, cfg config.Config) []registry.Tool {
	var all []registry.Tool
	all = append(all, sys.Tools(logger)...)
	all = append(all, kv.Tools(logger)...)
	all = append(all, pki.Tools(logger)...)
	all = append(all, ssh.Tools(logger)...)
	all = append(all, policy.Tools(logger)...)
	all = append(all, auth.Tools(logger)...)
	all = append(all, approle.Tools(logger)...)
	all = append(all, token.Tools(logger, cfg)...)
	all = append(all, identity.Tools(logger)...)
	all = append(all, lease.Tools(logger)...)
	all = append(all, audit.Tools(logger)...)
	return all
}

// categoryEnabled returns whether a tool category is enabled by the
// operator-controlled configuration. Core is always on; admin and audit are
// explicit opt-ins. Unknown categories are disabled (fail closed).
func categoryEnabled(cat registry.Category, cfg config.Config) bool {
	switch cat {
	case registry.CategoryCore:
		return true
	case registry.CategoryAdmin:
		return cfg.AdminTools
	case registry.CategoryAudit:
		return cfg.AuditTools
	default:
		return false
	}
}

// SelectTools returns the tools that should be registered for the given
// configuration. In read-only mode a tool must BOTH be classified read-only
// at registration AND appear on the independent static allowlist — the two
// layers deliberately do not share a single point of failure.
func SelectTools(logger *log.Logger, cfg config.Config) []registry.Tool {
	var selected []registry.Tool
	for _, tool := range allTools(logger, cfg) {
		if !categoryEnabled(tool.Category, cfg) {
			continue
		}
		if cfg.ReadOnly && (!tool.ReadOnly || !IsReadOnlyTool(tool.Tool.Name)) {
			continue
		}
		selected = append(selected, tool)
	}
	return selected
}

// InitTools registers the configured tool set on the MCP server.
func InitTools(hcServer *server.MCPServer, logger *log.Logger, cfg config.Config) {
	selected := SelectTools(logger, cfg)
	for _, tool := range selected {
		hcServer.AddTool(tool.Tool, tool.Handler)
	}

	logger.WithFields(log.Fields{
		"tools":       len(selected),
		"read_only":   cfg.ReadOnly,
		"admin_tools": cfg.AdminTools,
		"audit_tools": cfg.AuditTools,
	}).Info("Registered MCP tools")
}
