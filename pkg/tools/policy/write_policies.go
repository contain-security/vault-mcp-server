// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package policy

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// protectedPolicies are built-in policies that must never be modified or
// deleted through the MCP server. Vault normalizes policy names to lowercase,
// so the guard must compare case-insensitively (and ignore surrounding
// whitespace) — otherwise "Default" or " root " would slip past it and Vault
// would still write the normalized built-in policy.
var protectedPolicies = map[string]struct{}{
	"root":    {},
	"default": {},
}

func isProtectedPolicy(name string) bool {
	_, ok := protectedPolicies[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// WritePolicy creates a tool for creating or updating an ACL policy.
func WritePolicy(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("write_policy",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true), // overwrites the existing policy document
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Creates or updates an ACL policy in Vault from an HCL policy document. Overwrites any existing policy with the same name. The built-in 'root' and 'default' policies cannot be written."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the ACL policy. For example 'app-read'."),
			),
			mcp.WithString("policy",
				mcp.Required(),
				mcp.Description("The full HCL policy document. For example: path \"secret/data/app/*\" { capabilities = [\"read\", \"list\"] }"),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return writePolicyHandler(ctx, req, logger)
		},
	}
}

func writePolicyHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling write_policy request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	name, ok := args["name"].(string)
	if !ok || name == "" {
		return mcp.NewToolResultError("Missing or invalid 'name' parameter"), nil
	}

	policy, ok := args["policy"].(string)
	if !ok || policy == "" {
		return mcp.NewToolResultError("Missing or invalid 'policy' parameter"), nil
	}

	if isProtectedPolicy(name) {
		return mcp.NewToolResultError(fmt.Sprintf("Refusing to write built-in policy '%s'", name)), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	if err := vault.Sys().PutPolicy(name, policy); err != nil {
		logger.WithError(err).WithField("policy", name).Error("Failed to write policy")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to write policy '%s': %v", name, err)), nil
	}

	logger.WithField("policy", name).Info("Successfully wrote ACL policy")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully wrote ACL policy '%s'", name)), nil
}

// DeletePolicy creates a tool for deleting an ACL policy.
func DeletePolicy(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("delete_policy",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Deletes an ACL policy from Vault. Tokens that reference the policy lose those capabilities. The built-in 'root' and 'default' policies cannot be deleted."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the ACL policy to delete."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return deletePolicyHandler(ctx, req, logger)
		},
	}
}

func deletePolicyHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling delete_policy request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	name, ok := args["name"].(string)
	if !ok || name == "" {
		return mcp.NewToolResultError("Missing or invalid 'name' parameter"), nil
	}

	if isProtectedPolicy(name) {
		return mcp.NewToolResultError(fmt.Sprintf("Refusing to delete built-in policy '%s'", name)), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	if err := vault.Sys().DeletePolicy(name); err != nil {
		logger.WithError(err).WithField("policy", name).Error("Failed to delete policy")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to delete policy '%s': %v", name, err)), nil
	}

	logger.WithField("policy", name).Info("Successfully deleted ACL policy")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully deleted ACL policy '%s'", name)), nil
}
