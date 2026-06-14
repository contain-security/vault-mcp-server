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

// ListPolicies creates a tool for listing ACL policies.
func ListPolicies(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_policies",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Lists the names of all ACL policies in Vault."),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listPoliciesHandler(ctx, req, logger)
		},
	}
}

func listPoliciesHandler(ctx context.Context, _ mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_policies request")

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	policies, err := vault.Sys().ListPolicies()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list policies: %v", err)), nil
	}

	if len(policies) == 0 {
		return mcp.NewToolResultText("No ACL policies found."), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("ACL policies: %s", strings.Join(policies, ", "))), nil
}

// ReadPolicy creates a tool for reading a single ACL policy document.
func ReadPolicy(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_policy",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Reads the HCL document of an ACL policy in Vault."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the ACL policy to read. For example 'app-read'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readPolicyHandler(ctx, req, logger)
		},
	}
}

func readPolicyHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_policy request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	name, ok := args["name"].(string)
	if !ok || name == "" {
		return mcp.NewToolResultError("Missing or invalid 'name' parameter"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	policy, err := vault.Sys().GetPolicy(name)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read policy '%s': %v", name, err)), nil
	}

	if policy == "" {
		return mcp.NewToolResultError(fmt.Sprintf("Policy '%s' does not exist", name)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Policy '%s':\n%s", name, policy)), nil
}
