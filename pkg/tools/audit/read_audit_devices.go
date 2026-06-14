// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package audit

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// ListAuditDevices creates a tool for listing enabled audit devices.
func ListAuditDevices(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_audit_devices",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Lists all enabled audit devices in Vault, including each device's path, type, description, and configuration options."),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listAuditDevicesHandler(ctx, req, logger)
		},
	}
}

func listAuditDevicesHandler(ctx context.Context, _ mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_audit_devices request")

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	devices, err := vault.Sys().ListAudit()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list audit devices: %v", err)), nil
	}

	if len(devices) == 0 {
		return mcp.NewToolResultText("No audit devices are enabled."), nil
	}

	paths := make([]string, 0, len(devices))
	for path := range devices {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	var sb strings.Builder
	sb.WriteString("Enabled audit devices:\n")
	for _, path := range paths {
		device := devices[path]
		sb.WriteString(fmt.Sprintf("- path: %s, type: %s", path, device.Type))
		if device.Description != "" {
			sb.WriteString(fmt.Sprintf(", description: %s", device.Description))
		}
		if len(device.Options) > 0 {
			optKeys := make([]string, 0, len(device.Options))
			for k := range device.Options {
				optKeys = append(optKeys, k)
			}
			sort.Strings(optKeys)
			opts := make([]string, 0, len(optKeys))
			for _, k := range optKeys {
				opts = append(opts, fmt.Sprintf("%s=%s", k, device.Options[k]))
			}
			sb.WriteString(fmt.Sprintf(", options: %s", strings.Join(opts, " ")))
		}
		sb.WriteString("\n")
	}

	return mcp.NewToolResultText(sb.String()), nil
}
