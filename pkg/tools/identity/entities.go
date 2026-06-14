// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package identity

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

// splitCommaList splits a comma-separated string into trimmed, non-empty
// elements.
func splitCommaList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// containsRootPolicy reports whether the given policy list contains the
// built-in 'root' policy (case-insensitive). Attaching 'root' to an entity
// or group would grant unrestricted Vault access, so it is always refused.
func containsRootPolicy(policies []string) bool {
	for _, p := range policies {
		if strings.EqualFold(p, "root") {
			return true
		}
	}
	return false
}

// toStringSlice converts a Vault API []interface{} value into []string,
// skipping non-string elements.
func toStringSlice(v interface{}) []string {
	items, ok := v.([]interface{})
	if !ok {
		return nil
	}
	var out []string
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ListEntities creates a tool for listing identity entities.
func ListEntities(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_entities",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Lists the names of all identity entities in Vault. Use 'read_entity' to inspect a specific entity's policies and aliases."),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listEntitiesHandler(ctx, req, logger)
		},
	}
}

func listEntitiesHandler(ctx context.Context, _ mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_entities request")

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	secret, err := vault.Logical().List("identity/entity/name")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list entities: %v", err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultText("No identity entities found."), nil
	}

	names := toStringSlice(secret.Data["keys"])
	if len(names) == 0 {
		return mcp.NewToolResultText("No identity entities found."), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Identity entities: %s", strings.Join(names, ", "))), nil
}

// ReadEntity creates a tool for reading a single identity entity.
func ReadEntity(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_entity",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Reads an identity entity by name. Returns the entity ID, attached policies, metadata, whether it is disabled, and its aliases (each alias shows the alias ID, the auth-method login name, and the auth mount accessor it is bound to)."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the identity entity to read. For example 'dev-user'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readEntityHandler(ctx, req, logger)
		},
	}
}

func readEntityHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_entity request")

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

	secret, err := vault.Logical().Read(fmt.Sprintf("identity/entity/name/%s", name))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read entity '%s': %v", name, err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError(fmt.Sprintf("Entity '%s' does not exist", name)), nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Entity '%s':\n", name)
	if id, ok := secret.Data["id"].(string); ok {
		fmt.Fprintf(&sb, "  ID: %s\n", id)
	}
	fmt.Fprintf(&sb, "  Disabled: %v\n", secret.Data["disabled"] == true)

	policies := toStringSlice(secret.Data["policies"])
	if len(policies) > 0 {
		fmt.Fprintf(&sb, "  Policies: %s\n", strings.Join(policies, ", "))
	} else {
		sb.WriteString("  Policies: (none)\n")
	}

	if metadata, ok := secret.Data["metadata"].(map[string]interface{}); ok && len(metadata) > 0 {
		sb.WriteString("  Metadata:\n")
		for k, v := range metadata {
			fmt.Fprintf(&sb, "    %s: %v\n", k, v)
		}
	} else {
		sb.WriteString("  Metadata: (none)\n")
	}

	aliases, _ := secret.Data["aliases"].([]interface{})
	if len(aliases) > 0 {
		sb.WriteString("  Aliases:\n")
		for _, a := range aliases {
			alias, ok := a.(map[string]interface{})
			if !ok {
				continue
			}
			fmt.Fprintf(&sb, "    - ID: %v, Name: %v, Mount accessor: %v\n",
				alias["id"], alias["name"], alias["mount_accessor"])
		}
	} else {
		sb.WriteString("  Aliases: (none)\n")
	}

	return mcp.NewToolResultText(sb.String()), nil
}

// WriteEntity creates a tool for creating or updating an identity entity.
func WriteEntity(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("write_entity",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true), // overwrites the existing entity configuration
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Creates or updates an identity entity by name. Overwrites the existing entity configuration (policies, metadata, disabled state) if the entity already exists. The built-in 'root' policy can never be attached to an entity."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the identity entity. For example 'dev-user'."),
			),
			mcp.WithString("policies",
				mcp.Description("Comma-separated list of ACL policy names to attach to the entity. For example 'app-read,app-write'. The 'root' policy is refused."),
			),
			mcp.WithObject("metadata",
				mcp.Description("Key/value metadata to attach to the entity. All values must be strings. For example {\"team\": \"payments\"}."),
			),
			mcp.WithBoolean("disabled",
				mcp.Description("Whether the entity is disabled. A disabled entity cannot log in via any of its aliases. Defaults to false."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return writeEntityHandler(ctx, req, logger)
		},
	}
}

func writeEntityHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling write_entity request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	name, ok := args["name"].(string)
	if !ok || name == "" {
		return mcp.NewToolResultError("Missing or invalid 'name' parameter"), nil
	}

	data := map[string]interface{}{}

	if policiesRaw, ok := args["policies"]; ok {
		policiesStr, ok := policiesRaw.(string)
		if !ok {
			return mcp.NewToolResultError("Invalid 'policies' parameter: must be a comma-separated string"), nil
		}
		policies := splitCommaList(policiesStr)
		if containsRootPolicy(policies) {
			return mcp.NewToolResultError("Refusing to attach the built-in 'root' policy to an entity"), nil
		}
		data["policies"] = policies
	}

	if metadataRaw, ok := args["metadata"]; ok {
		metadataMap, ok := metadataRaw.(map[string]interface{})
		if !ok {
			return mcp.NewToolResultError("Invalid 'metadata' parameter: must be an object"), nil
		}
		metadata := map[string]string{}
		for k, v := range metadataMap {
			s, ok := v.(string)
			if !ok {
				return mcp.NewToolResultError(fmt.Sprintf("Invalid 'metadata' value for key '%s': all metadata values must be strings", k)), nil
			}
			metadata[k] = s
		}
		data["metadata"] = metadata
	}

	if disabledRaw, ok := args["disabled"]; ok {
		disabled, ok := disabledRaw.(bool)
		if !ok {
			return mcp.NewToolResultError("Invalid 'disabled' parameter: must be a boolean"), nil
		}
		data["disabled"] = disabled
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Writing by name is idempotent: it creates the entity if absent and
	// updates it in place if present.
	if _, err := vault.Logical().Write(fmt.Sprintf("identity/entity/name/%s", name), data); err != nil {
		logger.WithError(err).WithField("entity", name).Error("Failed to write entity")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to write entity '%s': %v", name, err)), nil
	}

	logger.WithField("entity", name).Info("Successfully wrote identity entity")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully wrote identity entity '%s'", name)), nil
}

// DeleteEntity creates a tool for deleting an identity entity.
func DeleteEntity(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("delete_entity",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Deletes an identity entity by name. All aliases bound to the entity are deleted with it, and logins through those aliases lose the entity's policies."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the identity entity to delete."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return deleteEntityHandler(ctx, req, logger)
		},
	}
}

func deleteEntityHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling delete_entity request")

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

	if _, err := vault.Logical().Delete(fmt.Sprintf("identity/entity/name/%s", name)); err != nil {
		logger.WithError(err).WithField("entity", name).Error("Failed to delete entity")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to delete entity '%s': %v", name, err)), nil
	}

	logger.WithField("entity", name).Info("Successfully deleted identity entity")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully deleted identity entity '%s'", name)), nil
}
