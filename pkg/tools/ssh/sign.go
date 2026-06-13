// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// SignSshKey creates a tool for signing an SSH public key into a certificate.
func SignSshKey(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("sign_ssh_key",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:   utils.ToBoolPtr(false),
					IdempotentHint: utils.ToBoolPtr(false),
				},
			),
			mcp.WithDescription("Signs an SSH public key using a CA signing role, producing a short-lived SSH certificate. The caller supplies their existing PUBLIC key only (never the private key). Returns the signed certificate, which the user saves alongside their key (e.g. as id_ed25519-cert.pub) to authenticate to SSH servers that trust the CA. This mints a credential and is never available in read-only mode."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The SSH mount. For example 'ssh-client-ca'."),
			),
			mcp.WithString("role",
				mcp.Required(),
				mcp.Description("The CA signing role to sign against (see create_ssh_role). For example 'clients'."),
			),
			mcp.WithString("public_key",
				mcp.Required(),
				mcp.Description("The OpenSSH-encoded PUBLIC key to sign (the contents of a .pub file, e.g. 'ssh-ed25519 AAAA...'). Never supply a private key."),
			),
			mcp.WithString("valid_principals",
				mcp.Description("Comma-separated principals (usernames for user certs, hostnames for host certs) to embed in the certificate. Must be permitted by the role. If omitted, the role's default_user is used."),
			),
			mcp.WithString("ttl",
				mcp.Description("Requested certificate TTL (for example '30m'). Must not exceed the role's max_ttl. If omitted, the role default applies."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return signSshKeyHandler(ctx, req, logger)
		},
	}
}

func signSshKeyHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling sign_ssh_key request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	role, ok := args["role"].(string)
	if !ok || role == "" {
		return mcp.NewToolResultError("Missing or invalid 'role' parameter"), nil
	}

	publicKey, ok := args["public_key"].(string)
	if !ok || publicKey == "" {
		return mcp.NewToolResultError("Missing or invalid 'public_key' parameter"), nil
	}

	requestData := map[string]interface{}{
		"public_key": publicKey,
	}
	if v, ok := args["valid_principals"].(string); ok && v != "" {
		requestData["valid_principals"] = v
	}
	if v, ok := args["ttl"].(string); ok && v != "" {
		requestData["ttl"] = v
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	fullPath := fmt.Sprintf("%s/sign/%s", mount, role)

	secret, err := vault.Logical().Write(fullPath, requestData)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{"mount": mount, "role": role}).Error("Failed to sign SSH key")
		return mcp.NewToolResultError(fmt.Sprintf("failed to write to path '%s': %v", fullPath, err)), nil
	}

	if secret == nil || secret.Data == nil || secret.Data["signed_key"] == nil {
		return mcp.NewToolResultError(fmt.Sprintf("Vault returned no signed certificate when signing against role '%s' on mount '%s'", role, mount)), nil
	}

	// serial_number identifies the cert for auditing; safe to log (not secret).
	logger.WithFields(log.Fields{
		"mount":  mount,
		"role":   role,
		"serial": secret.Data["serial_number"],
	}).Info("Successfully signed SSH certificate")

	return mcp.NewToolResultText(fmt.Sprintf(
		"Successfully signed an SSH certificate using role '%s' on mount '%s'. Save the following as your certificate file (for example id_ed25519-cert.pub):\n%v",
		role, mount, secret.Data["signed_key"],
	)), nil
}
