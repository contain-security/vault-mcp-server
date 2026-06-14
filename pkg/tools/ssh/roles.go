// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package ssh

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

// CreateSshRole creates a tool for creating an SSH CA signing role.
func CreateSshRole(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("create_ssh_role",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:   utils.ToBoolPtr(false),
					IdempotentHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Creates or updates a CA signing role (key_type 'ca') on an SSH secrets engine mount. The role constrains what certificates the CA will sign: which principals (users/hostnames), certificate type, TTL and extensions. Requires a CA signing key to be configured first (see configure_ssh_ca). This tool only creates CA signing roles, not dynamic/OTP roles."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The SSH mount to create the role on. For example 'ssh-client-ca'."),
			),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the role. For example 'clients' or 'hosts'."),
			),
			mcp.WithString("cert_type",
				mcp.DefaultString("user"),
				mcp.Enum("user", "host"),
				mcp.Description("The type of certificate this role signs: 'user' for client/user certificates or 'host' for host certificates. Defaults to 'user'."),
			),
			mcp.WithString("allowed_users",
				mcp.Description("Comma-separated list of usernames (for user certs) the role may sign for. Use '*' to allow any. For host certs, leave empty and use 'allowed_domains'."),
			),
			mcp.WithString("default_user",
				mcp.Description("The default username for which a certificate is signed when the request does not specify one. For example 'ubuntu'."),
			),
			mcp.WithString("allowed_domains",
				mcp.Description("For host certificates: comma-separated list of domains the role may sign host certificates for. Use with allow_subdomains on the SSH server side."),
			),
			mcp.WithString("allowed_extensions",
				mcp.Description("Comma-separated list of extensions the requester may request (for example 'permit-pty,permit-port-forwarding'). Use '*' to allow any."),
			),
			mcp.WithString("default_extensions",
				mcp.Description("Comma-separated list of extensions added to every certificate signed by this role (for example 'permit-pty,permit-port-forwarding')."),
			),
			mcp.WithString("ttl",
				mcp.Description("Default TTL for signed certificates (for example '30m'). If omitted, Vault's mount default applies."),
			),
			mcp.WithString("max_ttl",
				mcp.Description("Maximum TTL a requester may ask for (for example '24h')."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return createSshRoleHandler(ctx, req, logger)
		},
	}
}

func createSshRoleHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling create_ssh_role request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	name, ok := args["name"].(string)
	if !ok || name == "" {
		return mcp.NewToolResultError("Missing or invalid 'name' parameter"), nil
	}

	certType, _ := args["cert_type"].(string)
	if certType == "" {
		certType = "user"
	}
	if certType != "user" && certType != "host" {
		return mcp.NewToolResultError("'cert_type' must be 'user' or 'host'"), nil
	}

	// key_type 'ca' is what makes this a certificate-signing role.
	requestData := map[string]interface{}{
		"key_type":  "ca",
		"cert_type": certType,
	}
	if certType == "user" {
		requestData["allow_user_certificates"] = true
	} else {
		requestData["allow_host_certificates"] = true
	}

	// Optional string fields, passed through only when supplied.
	// Note: allowed_extensions is a comma-separated string in Vault, but
	// default_extensions is a MAP (extension -> value), handled separately.
	for _, key := range []string{
		"allowed_users", "default_user", "allowed_domains",
		"allowed_extensions", "ttl", "max_ttl",
	} {
		if v, ok := args[key].(string); ok && strings.TrimSpace(v) != "" {
			requestData[key] = v
		}
	}

	// default_extensions: accept a comma-separated convenience string (e.g.
	// "permit-pty,permit-port-forwarding") and convert to the map shape Vault
	// requires ({"permit-pty": "", ...}).
	if v, ok := args["default_extensions"].(string); ok && strings.TrimSpace(v) != "" {
		exts := map[string]interface{}{}
		for _, ext := range strings.Split(v, ",") {
			if ext = strings.TrimSpace(ext); ext != "" {
				exts[ext] = ""
			}
		}
		requestData["default_extensions"] = exts
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	fullPath := fmt.Sprintf("%s/roles/%s", mount, name)

	if _, err := vault.Logical().Write(fullPath, requestData); err != nil {
		logger.WithError(err).WithFields(log.Fields{"mount": mount, "role": name}).Error("Failed to create SSH role")
		return mcp.NewToolResultError(fmt.Sprintf("failed to write to path '%s': %v", fullPath, err)), nil
	}

	logger.WithFields(log.Fields{
		"mount":     mount,
		"role":      name,
		"cert_type": certType,
	}).Info("Successfully created SSH CA signing role")

	return mcp.NewToolResultText(fmt.Sprintf(
		"Successfully created SSH CA signing role '%s' (%s certificates) on mount '%s'. Sign keys against it with sign_ssh_key.",
		name, certType, mount,
	)), nil
}

// ReadSshRole creates a tool for reading an SSH role.
func ReadSshRole(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_ssh_role",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Reads the configuration of a role on an SSH secrets engine mount (key type, allowed principals, extensions, TTLs)."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The SSH mount. For example 'ssh-client-ca'."),
			),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the role to read."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readSshRoleHandler(ctx, req, logger)
		},
	}
}

func readSshRoleHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_ssh_role request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
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

	fullPath := fmt.Sprintf("%s/roles/%s", mount, name)

	secret, err := vault.Logical().Read(fullPath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to read SSH role '%s': %v", name, err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError(fmt.Sprintf("SSH role '%s' does not exist on mount '%s'", name, mount)), nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "SSH role '%s' on mount '%s':\n", name, mount)
	for _, key := range []string{
		"key_type", "cert_type", "allow_user_certificates", "allow_host_certificates",
		"allowed_users", "default_user", "allowed_domains",
		"allowed_extensions", "default_extensions", "ttl", "max_ttl",
	} {
		if v, ok := secret.Data[key]; ok && fmt.Sprintf("%v", v) != "" {
			fmt.Fprintf(&b, "  %s: %v\n", key, v)
		}
	}

	return mcp.NewToolResultText(b.String()), nil
}

// ListSshRoles creates a tool for listing SSH roles.
func ListSshRoles(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_ssh_roles",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Lists the names of all roles configured on an SSH secrets engine mount."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The SSH mount. For example 'ssh-client-ca'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listSshRolesHandler(ctx, req, logger)
		},
	}
}

func listSshRolesHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_ssh_roles request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	fullPath := fmt.Sprintf("%s/roles", mount)

	secret, err := vault.Logical().List(fullPath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to list SSH roles on mount '%s': %v", mount, err)), nil
	}

	if secret == nil || secret.Data == nil || secret.Data["keys"] == nil {
		return mcp.NewToolResultText(fmt.Sprintf("No roles found on SSH mount '%s'.", mount)), nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No roles found on SSH mount '%s'.", mount)), nil
	}

	names := make([]string, 0, len(keys))
	for _, k := range keys {
		names = append(names, fmt.Sprintf("%v", k))
	}

	return mcp.NewToolResultText(fmt.Sprintf("SSH roles on mount '%s': %s", mount, strings.Join(names, ", "))), nil
}

// DeleteSshRole creates a tool for deleting an SSH role.
func DeleteSshRole(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("delete_ssh_role",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Deletes a role from an SSH secrets engine mount. Certificates already signed under the role remain valid until they expire."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The SSH mount. For example 'ssh-client-ca'."),
			),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the role to delete."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return deleteSshRoleHandler(ctx, req, logger)
		},
	}
}

func deleteSshRoleHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling delete_ssh_role request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
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

	fullPath := fmt.Sprintf("%s/roles/%s", mount, name)

	if _, err := vault.Logical().Delete(fullPath); err != nil {
		logger.WithError(err).WithFields(log.Fields{"mount": mount, "role": name}).Error("Failed to delete SSH role")
		return mcp.NewToolResultError(fmt.Sprintf("failed to delete SSH role '%s': %v", name, err)), nil
	}

	logger.WithFields(log.Fields{"mount": mount, "role": name}).Info("Successfully deleted SSH role")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully deleted SSH role '%s' on mount '%s'.", name, mount)), nil
}
