// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// TuneMount creates a tool for tuning the configuration of an existing mount.
func TuneMount(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("tune_mount",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:   utils.ToBoolPtr(false),
					IdempotentHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Tune the configuration of an existing secrets engine mount in Vault. At least one of 'default_lease_ttl', 'max_lease_ttl' or 'description' must be provided; only the provided fields are changed."),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The path of the mount to tune. For example 'secret' or 'pki'."),
			),
			mcp.WithString("default_lease_ttl",
				mcp.Description("Optional new default lease TTL for the mount, as a duration string. For example '768h'."),
			),
			mcp.WithString("max_lease_ttl",
				mcp.Description("Optional new maximum lease TTL for the mount, as a duration string. For example '768h'."),
			),
			mcp.WithString("description",
				mcp.Description("Optional new description for the mount. Replaces the existing description."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return tuneMountHandler(ctx, req, logger)
		},
	}
}

func tuneMountHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling tune_mount request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	path, ok := args["path"].(string)
	if !ok || path == "" {
		return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
	}

	defaultLeaseTTL, _ := args["default_lease_ttl"].(string)
	maxLeaseTTL, _ := args["max_lease_ttl"].(string)
	description, descriptionProvided := args["description"].(string)

	if defaultLeaseTTL == "" && maxLeaseTTL == "" && !descriptionProvided {
		return mcp.NewToolResultError("At least one of 'default_lease_ttl', 'max_lease_ttl' or 'description' must be provided"), nil
	}

	config := api.MountConfigInput{}
	var changed []string

	if defaultLeaseTTL != "" {
		config.DefaultLeaseTTL = defaultLeaseTTL
		changed = append(changed, fmt.Sprintf("default_lease_ttl=%s", defaultLeaseTTL))
	}
	if maxLeaseTTL != "" {
		config.MaxLeaseTTL = maxLeaseTTL
		changed = append(changed, fmt.Sprintf("max_lease_ttl=%s", maxLeaseTTL))
	}
	if descriptionProvided {
		config.Description = &description
		changed = append(changed, fmt.Sprintf("description=%s", description))
	}

	logger.WithFields(log.Fields{
		"path":              path,
		"default_lease_ttl": defaultLeaseTTL,
		"max_lease_ttl":     maxLeaseTTL,
	}).Debug("Tuning mount with parameters")

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	if err := vault.Sys().TuneMount(path, config); err != nil {
		logger.WithError(err).WithField("path", path).Error("Failed to tune mount")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to tune mount '%s': %v", path, err)), nil
	}

	logger.WithFields(log.Fields{
		"path":    path,
		"changed": strings.Join(changed, ", "),
	}).Info("Successfully tuned mount")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully tuned mount '%s' (%s)", path, strings.Join(changed, ", "))), nil
}
