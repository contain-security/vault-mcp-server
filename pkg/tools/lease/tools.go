// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package lease provides MCP tools for inspecting and revoking Vault leases.
//
// Security note: revoking a lease immediately invalidates the credential or
// secret attached to it. Prefix and force revocation are deliberately not
// exposed (AR-011); only a single fully-qualified lease ID can be revoked
// per call. These tools are in the admin category, which is only registered
// when the operator explicitly enables admin tools.
package lease

import (
	"github.com/hashicorp/vault-mcp-server/pkg/tools/registry"
	log "github.com/sirupsen/logrus"
)

// Tools returns all lease tools with their security classification.
func Tools(logger *log.Logger) []registry.Tool {
	return []registry.Tool{
		{ServerTool: LookupLease(logger), ReadOnly: true, Category: registry.CategoryAdmin},
		{ServerTool: ListLeases(logger), ReadOnly: true, Category: registry.CategoryAdmin},
		{ServerTool: RevokeLease(logger), ReadOnly: false, Category: registry.CategoryAdmin},
	}
}
