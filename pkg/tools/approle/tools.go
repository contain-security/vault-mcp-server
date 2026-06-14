// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package approle provides MCP tools for managing Vault AppRole auth method
// roles and their credentials.
//
// Security note: read_approle_role_id and generate_approle_secret_id produce
// credential material (the two halves of an AppRole login), so they are
// classified as mutating even though role-id retrieval is an HTTP read. All
// tools in this package are in the admin category, which is only registered
// when the operator explicitly enables admin tools.
package approle

import (
	"github.com/hashicorp/vault-mcp-server/pkg/tools/registry"
	log "github.com/sirupsen/logrus"
)

// Tools returns all AppRole tools with their security classification.
func Tools(logger *log.Logger) []registry.Tool {
	return []registry.Tool{
		{ServerTool: ListRoles(logger), ReadOnly: true, Category: registry.CategoryAdmin},
		{ServerTool: ReadRole(logger), ReadOnly: true, Category: registry.CategoryAdmin},
		{ServerTool: WriteRole(logger), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: DeleteRole(logger), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: ReadRoleID(logger), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: GenerateSecretID(logger), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: ListSecretIDAccessors(logger), ReadOnly: true, Category: registry.CategoryAdmin},
		{ServerTool: DestroySecretID(logger), ReadOnly: false, Category: registry.CategoryAdmin},
	}
}
