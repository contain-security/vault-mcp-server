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

// SealStatus creates a tool for reading the Vault seal status.
func SealStatus(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("seal_status",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:   utils.ToBoolPtr(true),
					IdempotentHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Reads the seal status of the Vault server: whether it is sealed, the seal type, unseal progress, the unseal key threshold and total share count, the server version and the cluster name. Takes no parameters."),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return sealStatusHandler(ctx, req, logger)
		},
	}
}

func sealStatusHandler(ctx context.Context, _ mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling seal_status request")

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	status, err := vault.Sys().SealStatus()
	if err != nil {
		logger.WithError(err).Error("Failed to read seal status")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read seal status: %v", err)), nil
	}

	logger.WithField("sealed", status.Sealed).Debug("Successfully read seal status")

	return mcp.NewToolResultText(fmt.Sprintf(
		"Vault seal status:\n"+
			"  Sealed: %t\n"+
			"  Seal type: %s\n"+
			"  Unseal progress: %d\n"+
			"  Key threshold: %d\n"+
			"  Total key shares: %d\n"+
			"  Version: %s\n"+
			"  Cluster name: %s",
		status.Sealed,
		status.Type,
		status.Progress,
		status.T,
		status.N,
		status.Version,
		status.ClusterName,
	)), nil
}
