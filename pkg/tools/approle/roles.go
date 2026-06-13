// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package approle

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// defaultMount is the conventional mount path of the AppRole auth method.
const defaultMount = "approle"

// extractMount returns the AppRole auth mount path from the arguments,
// defaulting to "approle" and stripping any trailing slash.
func extractMount(args map[string]interface{}) string {
	mount, ok := args["mount"].(string)
	if !ok {
		return defaultMount
	}
	mount = strings.TrimSuffix(mount, "/")
	if mount == "" {
		return defaultMount
	}
	return mount
}

// extractOptionalInt extracts an optional non-negative integer argument.
// JSON numbers arrive as float64; plain ints are accepted for convenience.
func extractOptionalInt(args map[string]interface{}, key string) (int, bool, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return 0, false, nil
	}
	switch n := v.(type) {
	case float64:
		if n != math.Trunc(n) || n < 0 {
			return 0, false, fmt.Errorf("invalid '%s' parameter: must be a non-negative integer", key)
		}
		return int(n), true, nil
	case int:
		if n < 0 {
			return 0, false, fmt.Errorf("invalid '%s' parameter: must be a non-negative integer", key)
		}
		return n, true, nil
	default:
		return 0, false, fmt.Errorf("invalid '%s' parameter: expected a number", key)
	}
}

// formatData renders a Vault response data map as indented JSON.
func formatData(data map[string]interface{}) (string, error) {
	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ListRoles creates a tool for listing AppRole roles.
func ListRoles(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_approle_roles",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Lists the names of all roles configured on an AppRole auth method. Role names only; no credential material is returned."),
			mcp.WithString("mount",
				mcp.Description("The mount path of the AppRole auth method, without the 'auth/' prefix or a trailing slash. Defaults to 'approle'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listRolesHandler(ctx, req, logger)
		},
	}
}

func listRolesHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_approle_roles request")

	args, _ := req.Params.Arguments.(map[string]interface{})
	mount := extractMount(args)

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	secret, err := vault.Logical().List(fmt.Sprintf("auth/%s/role", mount))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list AppRole roles on mount '%s': %v", mount, err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultText(fmt.Sprintf("No AppRole roles found on mount '%s'.", mount)), nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No AppRole roles found on mount '%s'.", mount)), nil
	}

	names := make([]string, 0, len(keys))
	for _, k := range keys {
		names = append(names, fmt.Sprintf("%v", k))
	}

	return mcp.NewToolResultText(fmt.Sprintf("AppRole roles on mount '%s': %s", mount, strings.Join(names, ", "))), nil
}

// ReadRole creates a tool for reading the configuration of an AppRole role.
func ReadRole(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_approle_role",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Reads the configuration of an AppRole role (token TTLs, token policies, secret-id TTL, use counts, and binding settings). Configuration only; no role-id or secret-id is returned."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the AppRole role to read. For example 'web-app'."),
			),
			mcp.WithString("mount",
				mcp.Description("The mount path of the AppRole auth method, without the 'auth/' prefix or a trailing slash. Defaults to 'approle'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readRoleHandler(ctx, req, logger)
		},
	}
}

func readRoleHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_approle_role request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	name, ok := args["name"].(string)
	if !ok || name == "" {
		return mcp.NewToolResultError("Missing or invalid 'name' parameter"), nil
	}

	mount := extractMount(args)

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	secret, err := vault.Logical().Read(fmt.Sprintf("auth/%s/role/%s", mount, name))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read AppRole role '%s': %v", name, err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError(fmt.Sprintf("AppRole role '%s' does not exist on mount '%s'", name, mount)), nil
	}

	config, err := formatData(secret.Data)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to format role configuration: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("AppRole role '%s' on mount '%s':\n%s", name, mount, config)), nil
}

// WriteRole creates a tool for creating or updating an AppRole role.
func WriteRole(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("write_approle_role",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true), // overwrites the existing role configuration
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Creates or updates a role on an AppRole auth method. Overwrites the existing configuration of a role with the same name. Roles granting the 'root' policy are refused. Only the parameters you provide are sent to Vault; omitted parameters keep Vault's defaults (or are reset on an existing role per Vault's overwrite semantics)."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the AppRole role. For example 'web-app'."),
			),
			mcp.WithString("token_policies",
				mcp.Description("Comma-separated list of policy names attached to tokens issued for this role. For example 'app-read,app-write'. The 'root' policy is refused."),
			),
			mcp.WithString("token_ttl",
				mcp.Description("Initial TTL of tokens issued for this role, as a duration string. For example '1h' or '30m'."),
			),
			mcp.WithString("token_max_ttl",
				mcp.Description("Maximum lifetime of tokens issued for this role, as a duration string. For example '4h'."),
			),
			mcp.WithString("secret_id_ttl",
				mcp.Description("TTL of secret-ids generated for this role, as a duration string. For example '24h'. '0' means secret-ids never expire."),
			),
			mcp.WithNumber("secret_id_num_uses",
				mcp.Description("Number of times a single secret-id can be used to log in. 0 means unlimited uses; prefer a small positive number."),
			),
			mcp.WithNumber("token_num_uses",
				mcp.Description("Number of times a token issued for this role can be used. 0 means unlimited uses."),
			),
			mcp.WithString("mount",
				mcp.Description("The mount path of the AppRole auth method, without the 'auth/' prefix or a trailing slash. Defaults to 'approle'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return writeRoleHandler(ctx, req, logger)
		},
	}
}

func writeRoleHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling write_approle_role request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	name, ok := args["name"].(string)
	if !ok || name == "" {
		return mcp.NewToolResultError("Missing or invalid 'name' parameter"), nil
	}

	mount := extractMount(args)
	data := map[string]interface{}{}

	if raw, ok := args["token_policies"].(string); ok && raw != "" {
		policies := make([]string, 0)
		for _, p := range strings.Split(raw, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if strings.EqualFold(p, "root") {
				return mcp.NewToolResultError("Refusing to write AppRole role with the 'root' policy: a role granting root would let any holder of its credentials gain full control of Vault"), nil
			}
			policies = append(policies, p)
		}
		if len(policies) > 0 {
			data["token_policies"] = policies
		}
	}

	for _, key := range []string{"token_ttl", "token_max_ttl", "secret_id_ttl"} {
		if v, ok := args[key].(string); ok && v != "" {
			data[key] = v
		}
	}

	for _, key := range []string{"secret_id_num_uses", "token_num_uses"} {
		n, present, err := extractOptionalInt(args, key)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if present {
			data[key] = n
		}
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	if _, err := vault.Logical().Write(fmt.Sprintf("auth/%s/role/%s", mount, name), data); err != nil {
		logger.WithError(err).WithFields(log.Fields{"role": name, "mount": mount}).Error("Failed to write AppRole role")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to write AppRole role '%s': %v", name, err)), nil
	}

	logger.WithFields(log.Fields{"role": name, "mount": mount}).Info("Successfully wrote AppRole role")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully wrote AppRole role '%s' on mount '%s'", name, mount)), nil
}

// DeleteRole creates a tool for deleting an AppRole role.
func DeleteRole(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("delete_approle_role",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Deletes a role from an AppRole auth method. Existing secret-ids for the role are invalidated and applications using this role can no longer log in."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the AppRole role to delete."),
			),
			mcp.WithString("mount",
				mcp.Description("The mount path of the AppRole auth method, without the 'auth/' prefix or a trailing slash. Defaults to 'approle'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return deleteRoleHandler(ctx, req, logger)
		},
	}
}

func deleteRoleHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling delete_approle_role request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	name, ok := args["name"].(string)
	if !ok || name == "" {
		return mcp.NewToolResultError("Missing or invalid 'name' parameter"), nil
	}

	mount := extractMount(args)

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	if _, err := vault.Logical().Delete(fmt.Sprintf("auth/%s/role/%s", mount, name)); err != nil {
		logger.WithError(err).WithFields(log.Fields{"role": name, "mount": mount}).Error("Failed to delete AppRole role")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to delete AppRole role '%s': %v", name, err)), nil
	}

	logger.WithFields(log.Fields{"role": name, "mount": mount}).Info("Successfully deleted AppRole role")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully deleted AppRole role '%s' from mount '%s'", name, mount)), nil
}
