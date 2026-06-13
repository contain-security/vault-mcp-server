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

// ListGroups creates a tool for listing identity groups.
func ListGroups(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_groups",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Lists the names of all identity groups in Vault. Use 'read_group' to inspect a specific group's policies and members."),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listGroupsHandler(ctx, req, logger)
		},
	}
}

func listGroupsHandler(ctx context.Context, _ mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_groups request")

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	secret, err := vault.Logical().List("identity/group/name")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list groups: %v", err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultText("No identity groups found."), nil
	}

	names := toStringSlice(secret.Data["keys"])
	if len(names) == 0 {
		return mcp.NewToolResultText("No identity groups found."), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Identity groups: %s", strings.Join(names, ", "))), nil
}

// ReadGroup creates a tool for reading a single identity group.
func ReadGroup(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_group",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Reads an identity group by name. Returns the group ID, type (internal or external), attached policies, member entity IDs, and member group IDs."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the identity group to read. For example 'developers'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readGroupHandler(ctx, req, logger)
		},
	}
}

func readGroupHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_group request")

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

	secret, err := vault.Logical().Read(fmt.Sprintf("identity/group/name/%s", name))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read group '%s': %v", name, err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError(fmt.Sprintf("Group '%s' does not exist", name)), nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Group '%s':\n", name)
	if id, ok := secret.Data["id"].(string); ok {
		fmt.Fprintf(&sb, "  ID: %s\n", id)
	}
	if groupType, ok := secret.Data["type"].(string); ok {
		fmt.Fprintf(&sb, "  Type: %s\n", groupType)
	}

	formatList := func(label string, v interface{}) {
		items := toStringSlice(v)
		if len(items) > 0 {
			fmt.Fprintf(&sb, "  %s: %s\n", label, strings.Join(items, ", "))
		} else {
			fmt.Fprintf(&sb, "  %s: (none)\n", label)
		}
	}
	formatList("Policies", secret.Data["policies"])
	formatList("Member entity IDs", secret.Data["member_entity_ids"])
	formatList("Member group IDs", secret.Data["member_group_ids"])

	return mcp.NewToolResultText(sb.String()), nil
}

// WriteGroup creates a tool for creating or updating an identity group.
func WriteGroup(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("write_group",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true), // overwrites the existing group configuration
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Creates or updates an identity group by name. Overwrites the existing group configuration (policies and member lists) if the group already exists - omitted members are removed. Every member entity inherits all of the group's policies at login. The built-in 'root' policy can never be attached to a group."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the identity group. For example 'developers'."),
			),
			mcp.WithString("type",
				mcp.Enum("internal", "external"),
				mcp.Description("The group type. 'internal' groups have members managed in Vault; 'external' groups have membership mapped from an external provider via a group alias. Defaults to 'internal'."),
			),
			mcp.WithString("policies",
				mcp.Description("Comma-separated list of ACL policy names to attach to the group. For example 'app-read,app-write'. The 'root' policy is refused."),
			),
			mcp.WithString("member_entity_ids",
				mcp.Description("Comma-separated list of entity IDs (UUIDs from 'read_entity') that are members of the group. Only valid for internal groups."),
			),
			mcp.WithString("member_group_ids",
				mcp.Description("Comma-separated list of group IDs (UUIDs from 'read_group') that are nested member groups of the group."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return writeGroupHandler(ctx, req, logger)
		},
	}
}

func writeGroupHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling write_group request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	name, ok := args["name"].(string)
	if !ok || name == "" {
		return mcp.NewToolResultError("Missing or invalid 'name' parameter"), nil
	}

	groupType := "internal"
	if typeRaw, ok := args["type"]; ok {
		typeStr, ok := typeRaw.(string)
		if !ok {
			return mcp.NewToolResultError("Invalid 'type' parameter: must be a string"), nil
		}
		if typeStr != "" {
			groupType = typeStr
		}
	}
	if groupType != "internal" && groupType != "external" {
		return mcp.NewToolResultError(fmt.Sprintf("Invalid 'type' parameter '%s': must be 'internal' or 'external'", groupType)), nil
	}

	data := map[string]interface{}{
		"type": groupType,
	}

	if policiesRaw, ok := args["policies"]; ok {
		policiesStr, ok := policiesRaw.(string)
		if !ok {
			return mcp.NewToolResultError("Invalid 'policies' parameter: must be a comma-separated string"), nil
		}
		policies := splitCommaList(policiesStr)
		if containsRootPolicy(policies) {
			return mcp.NewToolResultError("Refusing to attach the built-in 'root' policy to a group"), nil
		}
		data["policies"] = policies
	}

	if memberEntityIDsRaw, ok := args["member_entity_ids"]; ok {
		memberEntityIDs, ok := memberEntityIDsRaw.(string)
		if !ok {
			return mcp.NewToolResultError("Invalid 'member_entity_ids' parameter: must be a comma-separated string"), nil
		}
		data["member_entity_ids"] = splitCommaList(memberEntityIDs)
	}

	if memberGroupIDsRaw, ok := args["member_group_ids"]; ok {
		memberGroupIDs, ok := memberGroupIDsRaw.(string)
		if !ok {
			return mcp.NewToolResultError("Invalid 'member_group_ids' parameter: must be a comma-separated string"), nil
		}
		data["member_group_ids"] = splitCommaList(memberGroupIDs)
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	if _, err := vault.Logical().Write(fmt.Sprintf("identity/group/name/%s", name), data); err != nil {
		logger.WithError(err).WithField("group", name).Error("Failed to write group")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to write group '%s': %v", name, err)), nil
	}

	logger.WithFields(log.Fields{
		"group": name,
		"type":  groupType,
	}).Info("Successfully wrote identity group")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully wrote identity group '%s'", name)), nil
}

// DeleteGroup creates a tool for deleting an identity group.
func DeleteGroup(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("delete_group",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Deletes an identity group by name. Member entities lose the group's policies at their next login or token renewal."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the identity group to delete."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return deleteGroupHandler(ctx, req, logger)
		},
	}
}

func deleteGroupHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling delete_group request")

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

	if _, err := vault.Logical().Delete(fmt.Sprintf("identity/group/name/%s", name)); err != nil {
		logger.WithError(err).WithField("group", name).Error("Failed to delete group")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to delete group '%s': %v", name, err)), nil
	}

	logger.WithField("group", name).Info("Successfully deleted identity group")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully deleted identity group '%s'", name)), nil
}
