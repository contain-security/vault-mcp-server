// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"github.com/hashicorp/vault-mcp-server/pkg/tools/registry"
	log "github.com/sirupsen/logrus"
)

// Tools returns all KV tools with their security classification.
func Tools(logger *log.Logger) []registry.Tool {
	return []registry.Tool{
		{ServerTool: ListSecrets(logger), ReadOnly: true, Category: registry.CategoryCore},
		{ServerTool: ReadSecret(logger), ReadOnly: true, Category: registry.CategoryCore},
		{ServerTool: WriteSecret(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: DeleteSecret(logger), ReadOnly: false, Category: registry.CategoryCore},
	}
}
