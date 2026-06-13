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

// LookupLease creates a tool for looking up metadata of a single lease.
//
// The lookup endpoint is an HTTP write (PUT sys/leases/lookup), but it
// discloses no secret material and changes no state, so it is classified
// read-only.
func LookupLease(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("lookup_lease",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Looks up metadata of a single Vault lease: issue time, expire time, remaining TTL, and whether it is renewable. Does not reveal the secret the lease is attached to and does not change any state."),
			mcp.WithString("lease_id",
				mcp.Required(),
				mcp.Description("The fully-qualified lease ID to look up. For example 'auth/approle/login/abc123def456'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return lookupLeaseHandler(ctx, req, logger)
		},
	}
}

func lookupLeaseHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling lookup_lease request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	leaseID, ok := args["lease_id"].(string)
	if !ok || leaseID == "" {
		return mcp.NewToolResultError("Missing or invalid 'lease_id' parameter"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	secret, err := vault.Logical().Write("sys/leases/lookup", map[string]interface{}{
		"lease_id": leaseID,
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to look up lease '%s': %v", leaseID, err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError(fmt.Sprintf("Lease '%s' was not found", leaseID)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf(
		"Lease '%s':\n- issue_time: %v\n- expire_time: %v\n- ttl: %v\n- renewable: %v",
		leaseID,
		secret.Data["issue_time"],
		secret.Data["expire_time"],
		secret.Data["ttl"],
		secret.Data["renewable"],
	)), nil
}

// ListLeases creates a tool for listing lease IDs under a prefix.
func ListLeases(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_leases",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Lists lease IDs under a given lease prefix in Vault. Requires a token with sudo capability on 'sys/leases/lookup'. Returned entries are lease ID segments relative to the prefix; entries ending in '/' are sub-prefixes that can be listed further."),
			mcp.WithString("prefix",
				mcp.Required(),
				mcp.Description("The lease prefix to list. For example 'auth/approle/login' or 'pki/issue/example-dot-com'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listLeasesHandler(ctx, req, logger)
		},
	}
}

func listLeasesHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_leases request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	prefix, ok := args["prefix"].(string)
	if !ok || prefix == "" {
		return mcp.NewToolResultError("Missing or invalid 'prefix' parameter"), nil
	}
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return mcp.NewToolResultError("Missing or invalid 'prefix' parameter"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	secret, err := vault.Logical().List(fmt.Sprintf("sys/leases/lookup/%s", prefix))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list leases under prefix '%s': %v", prefix, err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultText(fmt.Sprintf("No leases found under prefix '%s'.", prefix)), nil
	}

	rawKeys, ok := secret.Data["keys"].([]interface{})
	if !ok || len(rawKeys) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No leases found under prefix '%s'.", prefix)), nil
	}

	keys := make([]string, 0, len(rawKeys))
	for _, key := range rawKeys {
		keys = append(keys, fmt.Sprintf("%v", key))
	}

	return mcp.NewToolResultText(fmt.Sprintf("Leases under prefix '%s': %s", prefix, strings.Join(keys, ", "))), nil
}
