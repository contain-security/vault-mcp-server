// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// allowedAuthTypes is the closed set of auth method types that may be enabled
// through the MCP server. The handler validates against this set in addition
// to the schema enum, because schema constraints are advisory to the client.
var allowedAuthTypes = map[string]bool{
	"userpass":   true,
	"approle":    true,
	"ldap":       true,
	"github":     true,
	"jwt":        true,
	"oidc":       true,
	"kubernetes": true,
	"cert":       true,
	"aws":        true,
	"azure":      true,
	"gcp":        true,
}

// ListAuthMethods creates a tool for listing enabled auth methods.
func ListAuthMethods(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_auth_methods",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Lists all enabled authentication methods in Vault, showing each method's mount path, type, description, and accessor."),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listAuthMethodsHandler(ctx, req, logger)
		},
	}
}

func listAuthMethodsHandler(ctx context.Context, _ mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_auth_methods request")

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	methods, err := vault.Sys().ListAuth()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list auth methods: %v", err)), nil
	}

	if len(methods) == 0 {
		return mcp.NewToolResultText("No auth methods are enabled."), nil
	}

	paths := make([]string, 0, len(methods))
	for path := range methods {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	var sb strings.Builder
	sb.WriteString("Enabled auth methods:\n")
	for _, path := range paths {
		m := methods[path]
		sb.WriteString(fmt.Sprintf("- path: %s, type: %s, description: %q, accessor: %s\n",
			path, m.Type, m.Description, m.Accessor))
	}

	return mcp.NewToolResultText(sb.String()), nil
}

// EnableAuthMethod creates a tool for enabling an auth method at a path.
func EnableAuthMethod(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("enable_auth_method",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(false),
					IdempotentHint:  utils.ToBoolPtr(false), // enabling at an existing path fails
				},
			),
			mcp.WithDescription("Enables a new authentication method in Vault at the given mount path. Fails if a method is already mounted at that path. Enabling an auth method expands how clients can authenticate to Vault, so only enable methods that are actually required."),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The mount path for the auth method, without the 'auth/' prefix and without a trailing slash. For example 'userpass' or 'approle-ci'."),
			),
			mcp.WithString("type",
				mcp.Required(),
				mcp.Enum("userpass", "approle", "ldap", "github", "jwt", "oidc", "kubernetes", "cert", "aws", "azure", "gcp"),
				mcp.Description("The auth method type. Must be one of: userpass, approle, ldap, github, jwt, oidc, kubernetes, cert, aws, azure, gcp."),
			),
			mcp.WithString("description",
				mcp.Description("Optional human-readable description for the auth method."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return enableAuthMethodHandler(ctx, req, logger)
		},
	}
}

func enableAuthMethodHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling enable_auth_method request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	path, ok := args["path"].(string)
	if !ok || path == "" {
		return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
	}
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
	}

	authType, ok := args["type"].(string)
	if !ok || authType == "" {
		return mcp.NewToolResultError("Missing or invalid 'type' parameter"), nil
	}
	if !allowedAuthTypes[authType] {
		return mcp.NewToolResultError(fmt.Sprintf("Invalid auth method type '%s'. Must be one of: userpass, approle, ldap, github, jwt, oidc, kubernetes, cert, aws, azure, gcp", authType)), nil
	}

	description, _ := args["description"].(string)

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	options := &api.EnableAuthOptions{
		Type:        authType,
		Description: description,
	}

	if err := vault.Sys().EnableAuthWithOptions(path, options); err != nil {
		logger.WithError(err).WithFields(log.Fields{"path": path, "type": authType}).Error("Failed to enable auth method")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to enable auth method '%s' at path '%s': %v", authType, path, err)), nil
	}

	logger.WithFields(log.Fields{"path": path, "type": authType}).Info("Successfully enabled auth method")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully enabled auth method '%s' at path 'auth/%s'", authType, path)), nil
}

// DisableAuthMethod creates a tool for disabling an auth method.
func DisableAuthMethod(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("disable_auth_method",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Disables an authentication method in Vault. WARNING: this is destructive — disabling an auth method immediately invalidates ALL tokens that were issued by it and deletes its configuration. The built-in 'token' auth method can never be disabled."),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The mount path of the auth method to disable, without the 'auth/' prefix. For example 'userpass'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return disableAuthMethodHandler(ctx, req, logger)
		},
	}
}

func disableAuthMethodHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling disable_auth_method request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	path, ok := args["path"].(string)
	if !ok || path == "" {
		return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
	}
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
	}

	if path == "token" {
		return mcp.NewToolResultError("Refusing to disable the 'token' auth method: it is built into Vault and disabling it would break all token-based authentication"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	if err := vault.Sys().DisableAuth(path); err != nil {
		logger.WithError(err).WithField("path", path).Error("Failed to disable auth method")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to disable auth method at path '%s': %v", path, err)), nil
	}

	logger.WithField("path", path).Info("Successfully disabled auth method")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully disabled auth method at path 'auth/%s'. All tokens issued by it are now invalid.", path)), nil
}

// TuneAuthMethod creates a tool for tuning an auth method's configuration.
func TuneAuthMethod(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("tune_auth_method",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(false),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Tunes the configuration of an enabled authentication method (lease TTLs and description). Only the parameters you provide are changed; omitted parameters keep their current values."),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The mount path of the auth method to tune, without the 'auth/' prefix. For example 'userpass'."),
			),
			mcp.WithString("default_lease_ttl",
				mcp.Description("Optional default lease TTL for tokens issued by this method, as a duration string. For example '1h' or '30m'."),
			),
			mcp.WithString("max_lease_ttl",
				mcp.Description("Optional maximum lease TTL for tokens issued by this method, as a duration string. For example '24h'."),
			),
			mcp.WithString("description",
				mcp.Description("Optional new human-readable description for the auth method."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return tuneAuthMethodHandler(ctx, req, logger)
		},
	}
}

func tuneAuthMethodHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling tune_auth_method request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	path, ok := args["path"].(string)
	if !ok || path == "" {
		return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
	}
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
	}

	config := api.MountConfigInput{}
	provided := false

	if ttl, ok := args["default_lease_ttl"].(string); ok && ttl != "" {
		config.DefaultLeaseTTL = ttl
		provided = true
	}
	if ttl, ok := args["max_lease_ttl"].(string); ok && ttl != "" {
		config.MaxLeaseTTL = ttl
		provided = true
	}
	if description, ok := args["description"].(string); ok && description != "" {
		config.Description = &description
		provided = true
	}

	if !provided {
		return mcp.NewToolResultError("At least one of 'default_lease_ttl', 'max_lease_ttl' or 'description' must be provided"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	if err := vault.Sys().TuneMount("auth/"+path, config); err != nil {
		logger.WithError(err).WithField("path", path).Error("Failed to tune auth method")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to tune auth method at path '%s': %v", path, err)), nil
	}

	logger.WithField("path", path).Info("Successfully tuned auth method")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully tuned auth method at path 'auth/%s'", path)), nil
}
