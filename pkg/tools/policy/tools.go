// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package policy provides MCP tools for managing Vault ACL policies.
//
// Security note: write_policy combined with token creation is equivalent to
// the supplied Vault token's maximum theoretical privilege. These tools are
// therefore in the admin category, which is only registered when the
// operator explicitly enables admin tools.
package policy

import (
	"github.com/hashicorp/vault-mcp-server/pkg/tools/registry"
	log "github.com/sirupsen/logrus"
)

// Tools returns all ACL policy tools with their security classification.
func Tools(logger *log.Logger) []registry.Tool {
	return []registry.Tool{
		{ServerTool: ListPolicies(logger), ReadOnly: true, Category: registry.CategoryAdmin},
		{ServerTool: ReadPolicy(logger), ReadOnly: true, Category: registry.CategoryAdmin},
		{ServerTool: WritePolicy(logger), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: DeletePolicy(logger), ReadOnly: false, Category: registry.CategoryAdmin},
	}
}
