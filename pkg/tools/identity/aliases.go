// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// CreateEntityAlias creates a tool for binding an auth-method login to an
// identity entity.
func CreateEntityAlias(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("create_entity_alias",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Creates an entity alias that binds a login name on a specific auth method to an identity entity. SECURITY WARNING: binding an alias grants every login through that auth-method account ALL policies attached to the target entity (and its groups) - this is a known privilege-escalation vector. Always verify the target entity's policies with 'read_entity' before binding, and confirm the auth-method account really belongs to that identity."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The login name of the account on the auth method. For example the username 'alice' on a userpass mount, or a full LDAP DN. Must exactly match the name the auth method reports at login."),
			),
			mcp.WithString("canonical_id",
				mcp.Required(),
				mcp.Description("The ID of the identity entity to bind the alias to (the UUID shown by 'read_entity', not the entity name)."),
			),
			mcp.WithString("mount_accessor",
				mcp.Required(),
				mcp.Description("The accessor of the auth mount the login name belongs to. For example 'auth_userpass_b2c3d4'. Obtain it from 'list_auth_methods'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return createEntityAliasHandler(ctx, req, logger)
		},
	}
}

func createEntityAliasHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling create_entity_alias request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	name, ok := args["name"].(string)
	if !ok || name == "" {
		return mcp.NewToolResultError("Missing or invalid 'name' parameter"), nil
	}

	canonicalID, ok := args["canonical_id"].(string)
	if !ok || canonicalID == "" {
		return mcp.NewToolResultError("Missing or invalid 'canonical_id' parameter"), nil
	}

	mountAccessor, ok := args["mount_accessor"].(string)
	if !ok || mountAccessor == "" {
		return mcp.NewToolResultError("Missing or invalid 'mount_accessor' parameter"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	secret, err := vault.Logical().Write("identity/entity-alias", map[string]interface{}{
		"name":           name,
		"canonical_id":   canonicalID,
		"mount_accessor": mountAccessor,
	})
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"alias":          name,
			"canonical_id":   canonicalID,
			"mount_accessor": mountAccessor,
		}).Error("Failed to create entity alias")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create entity alias '%s': %v", name, err)), nil
	}

	logger.WithFields(log.Fields{
		"alias":          name,
		"canonical_id":   canonicalID,
		"mount_accessor": mountAccessor,
	}).Info("Successfully created entity alias")

	msg := fmt.Sprintf("Successfully created entity alias '%s' on mount accessor '%s' bound to entity '%s'", name, mountAccessor, canonicalID)
	if secret != nil && secret.Data != nil {
		if id, ok := secret.Data["id"].(string); ok && id != "" {
			msg = fmt.Sprintf("%s (alias ID: %s)", msg, id)
		}
	}

	return mcp.NewToolResultText(msg), nil
}

// DeleteEntityAlias creates a tool for deleting an entity alias by its ID.
func DeleteEntityAlias(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("delete_entity_alias",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Deletes an entity alias by its alias ID. Logins through the unbound auth-method account will no longer map to the entity or receive its policies."),
			mcp.WithString("id",
				mcp.Required(),
				mcp.Description("The ID of the entity alias to delete (the alias UUID shown in 'read_entity' output, not the alias name)."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return deleteEntityAliasHandler(ctx, req, logger)
		},
	}
}

func deleteEntityAliasHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling delete_entity_alias request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	id, ok := args["id"].(string)
	if !ok || id == "" {
		return mcp.NewToolResultError("Missing or invalid 'id' parameter"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	if _, err := vault.Logical().Delete(fmt.Sprintf("identity/entity-alias/id/%s", id)); err != nil {
		logger.WithError(err).WithField("alias_id", id).Error("Failed to delete entity alias")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to delete entity alias '%s': %v", id, err)), nil
	}

	logger.WithField("alias_id", id).Info("Successfully deleted entity alias")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully deleted entity alias '%s'", id)), nil
}
