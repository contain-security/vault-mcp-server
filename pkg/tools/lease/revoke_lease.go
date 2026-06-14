// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package lease

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

// RevokeLease creates a tool for revoking a single lease.
//
// AR-011: prefix and force revocation are deliberately not supported. A
// prefix revoke could invalidate every credential under a mount in one call,
// so this tool only accepts a single fully-qualified lease ID.
func RevokeLease(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("revoke_lease",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Revokes a single Vault lease by its fully-qualified lease ID. The secret or token attached to the lease is immediately invalidated and cannot be recovered. Only one specific lease can be revoked per call: prefix revocation (lease IDs ending in '/') and bare mount prefixes (no '/') are refused by policy."),
			mcp.WithString("lease_id",
				mcp.Required(),
				mcp.Description("The single fully-qualified lease ID to revoke. For example 'auth/approle/login/abc123def456'. Must not end in '/' and must contain at least one '/'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return revokeLeaseHandler(ctx, req, logger)
		},
	}
}

func revokeLeaseHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling revoke_lease request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	leaseID, ok := args["lease_id"].(string)
	if !ok || leaseID == "" {
		return mcp.NewToolResultError("Missing or invalid 'lease_id' parameter"), nil
	}

	// AR-011: refuse anything that looks like a prefix rather than a single
	// fully-qualified lease ID.
	if strings.HasSuffix(leaseID, "/") {
		return mcp.NewToolResultError(fmt.Sprintf("Refusing to revoke '%s': it ends in '/' and looks like a lease prefix. This tool only revokes a single fully-qualified lease ID; prefix and force revocation are not supported by policy.", leaseID)), nil
	}
	if !strings.Contains(leaseID, "/") {
		return mcp.NewToolResultError(fmt.Sprintf("Refusing to revoke '%s': it contains no '/' and looks like a bare mount prefix, not a lease ID. This tool only revokes a single fully-qualified lease ID; prefix and force revocation are not supported by policy.", leaseID)), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	if err := vault.Sys().Revoke(leaseID); err != nil {
		logger.WithError(err).WithField("lease_id", leaseID).Error("Failed to revoke lease")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to revoke lease '%s': %v", leaseID, err)), nil
	}

	logger.WithField("lease_id", leaseID).Info("Successfully revoked lease")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully revoked lease '%s'", leaseID)), nil
}
