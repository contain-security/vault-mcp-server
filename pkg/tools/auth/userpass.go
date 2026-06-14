// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

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

const defaultUserpassMount = "userpass"

// userpassMount extracts the optional 'mount' argument, defaulting to
// "userpass" and stripping any trailing slash.
func userpassMount(args map[string]interface{}) string {
	mount, ok := args["mount"].(string)
	if !ok || mount == "" {
		return defaultUserpassMount
	}
	mount = strings.TrimSuffix(mount, "/")
	if mount == "" {
		return defaultUserpassMount
	}
	return mount
}

// containsRootPolicy reports whether a comma-separated policy list contains
// the built-in 'root' policy (case-insensitive, whitespace-trimmed).
func containsRootPolicy(policies string) bool {
	for _, p := range strings.Split(policies, ",") {
		if strings.EqualFold(strings.TrimSpace(p), "root") {
			return true
		}
	}
	return false
}

// ListUserpassUsers creates a tool for listing users in a userpass auth method.
func ListUserpassUsers(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_userpass_users",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Lists the usernames registered in a userpass authentication method."),
			mcp.WithString("mount",
				mcp.Description("The mount path of the userpass auth method, without the 'auth/' prefix. Defaults to 'userpass'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listUserpassUsersHandler(ctx, req, logger)
		},
	}
}

func listUserpassUsersHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_userpass_users request")

	args, _ := req.Params.Arguments.(map[string]interface{})
	mount := userpassMount(args)

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	secret, err := vault.Logical().List(fmt.Sprintf("auth/%s/users", mount))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list users at 'auth/%s/users': %v", mount, err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultText(fmt.Sprintf("No users found in userpass auth method at 'auth/%s'.", mount)), nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No users found in userpass auth method at 'auth/%s'.", mount)), nil
	}

	users := make([]string, 0, len(keys))
	for _, k := range keys {
		if s, ok := k.(string); ok {
			users = append(users, s)
		}
	}

	return mcp.NewToolResultText(fmt.Sprintf("Users in userpass auth method at 'auth/%s': %s", mount, strings.Join(users, ", "))), nil
}

// ReadUserpassUser creates a tool for reading a userpass user's configuration.
func ReadUserpassUser(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_userpass_user",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Reads the configuration of a user in a userpass authentication method, including token policies and TTL settings. Vault never returns the user's password."),
			mcp.WithString("username",
				mcp.Required(),
				mcp.Description("The username to read."),
			),
			mcp.WithString("mount",
				mcp.Description("The mount path of the userpass auth method, without the 'auth/' prefix. Defaults to 'userpass'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readUserpassUserHandler(ctx, req, logger)
		},
	}
}

func readUserpassUserHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_userpass_user request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	username, ok := args["username"].(string)
	if !ok || username == "" {
		return mcp.NewToolResultError("Missing or invalid 'username' parameter"), nil
	}

	mount := userpassMount(args)

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	secret, err := vault.Logical().Read(fmt.Sprintf("auth/%s/users/%s", mount, username))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read user '%s' at 'auth/%s': %v", username, mount, err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError(fmt.Sprintf("User '%s' does not exist in userpass auth method at 'auth/%s'", username, mount)), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("User '%s' (auth/%s):\n", username, mount))
	for _, key := range []string{"token_policies", "policies", "token_ttl", "token_max_ttl", "ttl", "max_ttl", "token_type", "token_bound_cidrs"} {
		if value, ok := secret.Data[key]; ok {
			sb.WriteString(fmt.Sprintf("- %s: %v\n", key, value))
		}
	}

	return mcp.NewToolResultText(sb.String()), nil
}

// WriteUserpassUser creates a tool for creating or updating a userpass user.
func WriteUserpassUser(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("write_userpass_user",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true), // overwrites an existing user's configuration
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Creates or updates a user in a userpass authentication method. WARNING: this creates a credential that can log in to Vault — a careless user entry is a backdoor account. Grant only the minimal token policies required; the built-in 'root' policy is always refused. Overwrites the configuration of an existing user with the same username."),
			mcp.WithString("username",
				mcp.Required(),
				mcp.Description("The username to create or update."),
			),
			mcp.WithString("password",
				mcp.Description("The user's password. Required when creating a new user; optional when updating an existing user (omit to leave the password unchanged)."),
			),
			mcp.WithString("token_policies",
				mcp.Description("Optional comma-separated list of token policies to grant on login. For example 'app-read,app-write'. The 'root' policy is refused. Keep this list minimal."),
			),
			mcp.WithString("token_ttl",
				mcp.Description("Optional TTL for tokens issued on login, as a duration string. For example '1h'."),
			),
			mcp.WithString("mount",
				mcp.Description("The mount path of the userpass auth method, without the 'auth/' prefix. Defaults to 'userpass'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return writeUserpassUserHandler(ctx, req, logger)
		},
	}
}

func writeUserpassUserHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling write_userpass_user request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	username, ok := args["username"].(string)
	if !ok || username == "" {
		return mcp.NewToolResultError("Missing or invalid 'username' parameter"), nil
	}

	mount := userpassMount(args)

	data := map[string]interface{}{}

	if password, ok := args["password"].(string); ok && password != "" {
		data["password"] = password
	}

	if policies, ok := args["token_policies"].(string); ok && policies != "" {
		if containsRootPolicy(policies) {
			return mcp.NewToolResultError("Refusing to grant the 'root' policy to a userpass user: this would create a root-equivalent backdoor account"), nil
		}
		data["token_policies"] = policies
	}

	if ttl, ok := args["token_ttl"].(string); ok && ttl != "" {
		data["token_ttl"] = ttl
	}

	if len(data) == 0 {
		return mcp.NewToolResultError("At least one of 'password', 'token_policies' or 'token_ttl' must be provided"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	if _, err := vault.Logical().Write(fmt.Sprintf("auth/%s/users/%s", mount, username), data); err != nil {
		logger.WithError(err).WithFields(log.Fields{"username": username, "mount": mount}).Error("Failed to write userpass user")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to write user '%s' at 'auth/%s': %v", username, mount, err)), nil
	}

	logger.WithFields(log.Fields{"username": username, "mount": mount}).Info("Successfully wrote userpass user")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully wrote user '%s' in userpass auth method at 'auth/%s'", username, mount)), nil
}

// DeleteUserpassUser creates a tool for deleting a userpass user.
func DeleteUserpassUser(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("delete_userpass_user",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Deletes a user from a userpass authentication method. The user can no longer log in, but tokens they already hold remain valid until they expire or are revoked."),
			mcp.WithString("username",
				mcp.Required(),
				mcp.Description("The username to delete."),
			),
			mcp.WithString("mount",
				mcp.Description("The mount path of the userpass auth method, without the 'auth/' prefix. Defaults to 'userpass'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return deleteUserpassUserHandler(ctx, req, logger)
		},
	}
}

func deleteUserpassUserHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling delete_userpass_user request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	username, ok := args["username"].(string)
	if !ok || username == "" {
		return mcp.NewToolResultError("Missing or invalid 'username' parameter"), nil
	}

	mount := userpassMount(args)

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	if _, err := vault.Logical().Delete(fmt.Sprintf("auth/%s/users/%s", mount, username)); err != nil {
		logger.WithError(err).WithFields(log.Fields{"username": username, "mount": mount}).Error("Failed to delete userpass user")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to delete user '%s' at 'auth/%s': %v", username, mount, err)), nil
	}

	logger.WithFields(log.Fields{"username": username, "mount": mount}).Info("Successfully deleted userpass user")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully deleted user '%s' from userpass auth method at 'auth/%s'", username, mount)), nil
}
