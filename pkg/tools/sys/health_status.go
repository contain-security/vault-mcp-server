// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// HealthStatus creates a tool for reading the Vault server health.
func HealthStatus(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("health_status",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:   utils.ToBoolPtr(true),
					IdempotentHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Reads the health status of the Vault server: whether it is initialized, sealed or in standby mode, plus the server version and the cluster id and name. Takes no parameters."),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return healthStatusHandler(ctx, req, logger)
		},
	}
}

func healthStatusHandler(ctx context.Context, _ mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling health_status request")

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	health, err := vault.Sys().Health()
	if err != nil {
		logger.WithError(err).Error("Failed to read health status")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read health status: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"initialized": health.Initialized,
		"sealed":      health.Sealed,
		"standby":     health.Standby,
	}).Debug("Successfully read health status")

	return mcp.NewToolResultText(fmt.Sprintf(
		"Vault health status:\n"+
			"  Initialized: %t\n"+
			"  Sealed: %t\n"+
			"  Standby: %t\n"+
			"  Version: %s\n"+
			"  Cluster id: %s\n"+
			"  Cluster name: %s",
		health.Initialized,
		health.Sealed,
		health.Standby,
		health.Version,
		health.ClusterID,
		health.ClusterName,
	)), nil
}
