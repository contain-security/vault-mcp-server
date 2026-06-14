// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package token

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// LookupToken creates a tool for inspecting token metadata.
func LookupToken(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("lookup_token",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Looks up metadata about a Vault token (display name, policies, TTL, creation info). "+
				"With the 'accessor' parameter the token is looked up by its accessor; without it, the server's own token is inspected. "+
				"The token value itself is never returned."),
			mcp.WithString("accessor",
				mcp.Description("Optional token accessor (e.g. 'hmac.AAAA...'). If omitted, looks up the token the MCP server itself is using."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return lookupTokenHandler(ctx, req, logger)
		},
	}
}

func lookupTokenHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling lookup_token request")

	accessor := ""
	if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
		accessor, _ = args["accessor"].(string)
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	var secret *api.Secret
	if accessor != "" {
		secret, err = vault.Auth().Token().LookupAccessor(accessor)
	} else {
		secret, err = vault.Auth().Token().LookupSelf()
	}
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to look up token: %v", err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError("Token lookup returned no data"), nil
	}

	// Never expose the token value itself. Accessor lookups do not return it,
	// but a self-lookup includes the token in the 'id' field.
	data := make(map[string]interface{}, len(secret.Data))
	for k, v := range secret.Data {
		if k == "id" {
			continue
		}
		data[k] = v
	}

	formatted, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to format token metadata: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Token metadata:\n%s", formatted)), nil
}

// RenewToken creates a tool for renewing a token's lease.
func RenewToken(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("renew_token",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(false),
				},
			),
			mcp.WithDescription("Renews a Vault token, extending its TTL. This extends the lifetime of a credential, so it is a mutating operation. "+
				"With the 'accessor' parameter the token identified by that accessor is renewed; without it, the server's own token is renewed. "+
				"The token must be renewable and within its explicit max TTL."),
			mcp.WithString("accessor",
				mcp.Description("Optional token accessor identifying the token to renew. If omitted, renews the token the MCP server itself is using."),
			),
			mcp.WithString("increment",
				mcp.Description("Optional requested lease increment as a duration string, e.g. '1h'. Vault may cap it at the token's max TTL."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return renewTokenHandler(ctx, req, logger)
		},
	}
}

func renewTokenHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling renew_token request")

	accessor := ""
	incrementRaw := ""
	if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
		accessor, _ = args["accessor"].(string)
		incrementRaw, _ = args["increment"].(string)
	}

	incrementSeconds := 0
	if incrementRaw != "" {
		d, err := time.ParseDuration(incrementRaw)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid 'increment' value %q: %v (use a duration string such as '1h')", incrementRaw, err)), nil
		}
		if d <= 0 {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid 'increment' value %q: must be positive", incrementRaw)), nil
		}
		incrementSeconds = int(d.Seconds())
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	var secret *api.Secret
	if accessor != "" {
		secret, err = vault.Auth().Token().RenewAccessor(accessor, incrementSeconds)
	} else {
		secret, err = vault.Auth().Token().RenewSelf(incrementSeconds)
	}
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to renew token: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"viaAccessor": accessor != "",
		"increment":   incrementRaw,
	}).Info("Successfully renewed token")

	// Report only lease metadata — the renew response includes the token
	// value, which must never be echoed back.
	if secret != nil && secret.Auth != nil {
		return mcp.NewToolResultText(fmt.Sprintf(
			"Token renewed. New lease duration: %d seconds. Renewable: %t.",
			secret.Auth.LeaseDuration, secret.Auth.Renewable)), nil
	}
	return mcp.NewToolResultText("Token renewed."), nil
}

// RevokeToken creates a tool for revoking a token by accessor.
func RevokeToken(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("revoke_token",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Revokes a Vault token by its accessor, immediately invalidating it. "+
				"Revocation also revokes all child tokens created by the revoked token. "+
				"Only accessors are accepted (never raw token values) so that token values never need to travel through the conversation."),
			mcp.WithString("accessor",
				mcp.Required(),
				mcp.Description("The accessor of the token to revoke (e.g. 'hmac.AAAA...'). Accessors are returned by create_token and list_token_accessors."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return revokeTokenHandler(ctx, req, logger)
		},
	}
}

func revokeTokenHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling revoke_token request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	accessor, ok := args["accessor"].(string)
	if !ok || accessor == "" {
		return mcp.NewToolResultError("Missing or invalid 'accessor' parameter"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	if err := vault.Auth().Token().RevokeAccessor(accessor); err != nil {
		logger.WithError(err).Error("Failed to revoke token")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to revoke token: %v", err)), nil
	}

	logger.WithField("accessor", accessor).Info("Successfully revoked token")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully revoked token with accessor '%s' (child tokens were also revoked).", accessor)), nil
}

// ListTokenAccessors creates a tool for listing all token accessors.
func ListTokenAccessors(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_token_accessors",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Lists the accessors of all tokens in Vault (requires sudo capability on auth/token/accessors). "+
				"Accessors can be used with lookup_token and revoke_token; they never reveal the token values themselves."),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listTokenAccessorsHandler(ctx, req, logger)
		},
	}
}

func listTokenAccessorsHandler(ctx context.Context, _ mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_token_accessors request")

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	secret, err := vault.Logical().List("auth/token/accessors")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list token accessors: %v", err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultText("No token accessors found."), nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		return mcp.NewToolResultText("No token accessors found."), nil
	}

	formatted, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to format token accessors: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Token accessors (%d):\n%s", len(keys), formatted)), nil
}
