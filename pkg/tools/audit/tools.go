// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package audit provides MCP tools for managing Vault audit devices.
//
// Security note: disabling an audit device permanently destroys the audit
// trail for that device (AR-004). These tools are therefore in the audit
// category, which is gated behind its own flag and only registered when the
// operator explicitly enables audit tools.
package audit

import (
	"github.com/hashicorp/vault-mcp-server/pkg/tools/registry"
	log "github.com/sirupsen/logrus"
)

// Tools returns all audit device tools with their security classification.
func Tools(logger *log.Logger) []registry.Tool {
	return []registry.Tool{
		{ServerTool: ListAuditDevices(logger), ReadOnly: true, Category: registry.CategoryAudit},
		{ServerTool: EnableAuditDevice(logger), ReadOnly: false, Category: registry.CategoryAudit},
		{ServerTool: DisableAuditDevice(logger), ReadOnly: false, Category: registry.CategoryAudit},
	}
}
