// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package identity provides MCP tools for managing Vault identity entities,
// entity aliases, and identity groups.
//
// Security note: entity aliases bind auth-method logins to entities, and
// entities/groups carry policy attachments. write_entity, write_group and
// create_entity_alias can therefore escalate the privileges granted at
// login time. These tools are in the admin category, which is only
// registered when the operator explicitly enables admin tools, and the
// built-in 'root' policy is always refused.
package identity

import (
	"github.com/hashicorp/vault-mcp-server/pkg/tools/registry"
	log "github.com/sirupsen/logrus"
)

// Tools returns all identity tools with their security classification.
func Tools(logger *log.Logger) []registry.Tool {
	return []registry.Tool{
		{ServerTool: ListEntities(logger), ReadOnly: true, Category: registry.CategoryAdmin},
		{ServerTool: ReadEntity(logger), ReadOnly: true, Category: registry.CategoryAdmin},
		{ServerTool: WriteEntity(logger), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: DeleteEntity(logger), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: CreateEntityAlias(logger), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: DeleteEntityAlias(logger), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: ListGroups(logger), ReadOnly: true, Category: registry.CategoryAdmin},
		{ServerTool: ReadGroup(logger), ReadOnly: true, Category: registry.CategoryAdmin},
		{ServerTool: WriteGroup(logger), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: DeleteGroup(logger), ReadOnly: false, Category: registry.CategoryAdmin},
	}
}
