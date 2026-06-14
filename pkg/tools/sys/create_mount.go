// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// allowedMountTypes is the allowlist of secrets engine types that
// create_mount is permitted to enable.
var allowedMountTypes = map[string]bool{
	"kv":       true,
	"kv2":      true,
	"transit":  true,
	"pki":      true,
	"ssh":      true,
	"database": true,
	"totp":     true,
}

// CreateMount creates a tool for creating Vault mounts
func CreateMount(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("create_mount",
			mcp.WithDescription("Mount a new secrets engine on a specific path in Vault."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:   utils.ToBoolPtr(false),
					IdempotentHint: utils.ToBoolPtr(false),
				},
			),
			mcp.WithString("type",
				mcp.Required(),
				mcp.Enum("kv", "kv2", "transit", "pki", "ssh", "database", "totp"),
				mcp.Description("The type of secrets engine to mount. Supported types: 'kv' (unversioned key/value), 'kv2' (versioned key/value), 'transit' (encryption as a service), 'pki' (X.509 certificates), 'ssh' (SSH credentials), 'database' (dynamic database credentials), 'totp' (time-based one-time passwords)."),
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The path where the mount will be created. Examples would be 'secrets' or 'kv'."),
			),
			mcp.WithString("description",
				mcp.DefaultString(""),
				mcp.Description("A description for the mount."),
			),
			mcp.WithObject("options",
				mcp.Description("Optional mount options, specific to the mount type."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return createMountHandler(ctx, req, logger)
		},
	}
}

func createMountHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling create_mount request")

	// Extract parameters
	var mountType, path, description string
	var options interface{}

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			if mountType, ok = args["type"].(string); !ok || mountType == "" || !allowedMountTypes[mountType] {
				return mcp.NewToolResultError("Missing or invalid 'type' parameter, supported types are: kv, kv2, transit, pki, ssh, database, totp"), nil
			}

			if path, ok = args["path"].(string); !ok || path == "" {
				return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
			}

			description, _ = args["description"].(string)

			options = args["options"]

		} else {
			return mcp.NewToolResultError("Invalid arguments format"), nil
		}
	} else {
		return mcp.NewToolResultError("Missing arguments"), nil
	}

	logger.WithFields(log.Fields{
		"type":        mountType,
		"path":        path,
		"description": description,
	}).Debug("Creating mount with parameters")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	mounts, err := vault.Sys().ListMounts()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to list mounts: %v", err)), nil
	}

	// Check if the mount exists
	if _, ok := mounts[path+"/"]; ok {
		// Let the model know that the mount already exists and, it could delete it, need be.
		// We should not delete it automatically, as it could lead to data loss. We should return more options in the future to allow
		// the model to decide what to do with the existing mount (such as tuning).
		return mcp.NewToolResultError(fmt.Sprintf("mount path '%s' already exists, you should use 'delete_mount' if you want to re-create it.", path)), nil
	}

	// Prepare mount input
	mountInput := &api.MountInput{
		Type:        mountType,
		Description: description,
	}

	if mountType == "kv2" {
		mountInput.Options = make(map[string]string)
		mountInput.Type = "kv"
		// options is untyped JSON from the client; only treat it as a map.
		if optMap, ok := options.(map[string]interface{}); ok {
			for key, value := range optMap {
				if s, ok := value.(string); ok {
					mountInput.Options[key] = s
				}
			}
		}
		mountInput.Options["version"] = "2"
	}

	// Create the mount
	err = vault.Sys().Mount(path, mountInput)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"type": mountType,
			"path": path,
		}).Error("Failed to create mount")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create mount: %v", err)), nil
	}

	successMsg := fmt.Sprintf("Successfully created %s mount at path '%s'", mountType, path)
	if description != "" {
		successMsg += fmt.Sprintf(" with description: %s", description)
	}

	logger.WithFields(log.Fields{
		"type": mountType,
		"path": path,
	}).Info("Successfully created mount")

	return mcp.NewToolResultText(successMsg), nil
}
