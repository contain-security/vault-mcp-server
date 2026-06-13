// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package auth provides MCP tools for managing Vault authentication methods
// and userpass users.
//
// Security note: enabling auth methods and writing userpass users changes
// who can authenticate to Vault and with what privileges — write_userpass_user
// in particular can create login credentials. These tools are therefore in
// the admin category, which is only registered when the operator explicitly
// enables admin tools.
package auth

import (
	"github.com/hashicorp/vault-mcp-server/pkg/tools/registry"
	log "github.com/sirupsen/logrus"
)

// Tools returns all auth method and userpass tools with their security
// classification.
func Tools(logger *log.Logger) []registry.Tool {
	return []registry.Tool{
		{ServerTool: ListAuthMethods(logger), ReadOnly: true, Category: registry.CategoryAdmin},
		{ServerTool: EnableAuthMethod(logger), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: DisableAuthMethod(logger), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: TuneAuthMethod(logger), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: ListUserpassUsers(logger), ReadOnly: true, Category: registry.CategoryAdmin},
		{ServerTool: ReadUserpassUser(logger), ReadOnly: true, Category: registry.CategoryAdmin},
		{ServerTool: WriteUserpassUser(logger), ReadOnly: false, Category: registry.CategoryAdmin},
		{ServerTool: DeleteUserpassUser(logger), ReadOnly: false, Category: registry.CategoryAdmin},
	}
}
