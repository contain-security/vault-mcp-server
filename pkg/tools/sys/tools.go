// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"github.com/hashicorp/vault-mcp-server/pkg/tools/registry"
	log "github.com/sirupsen/logrus"
)

// Tools returns all system tools with their security classification.
func Tools(logger *log.Logger) []registry.Tool {
	return []registry.Tool{
		{ServerTool: ListMounts(logger), ReadOnly: true, Category: registry.CategoryCore},
		{ServerTool: CreateMount(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: DeleteMount(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: TuneMount(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: SealStatus(logger), ReadOnly: true, Category: registry.CategoryCore},
		{ServerTool: HealthStatus(logger), ReadOnly: true, Category: registry.CategoryCore},
	}
}
