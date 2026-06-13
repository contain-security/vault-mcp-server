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

// ConfigureSshCa creates a tool for configuring the CA signing key on an SSH mount.
func ConfigureSshCa(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("configure_ssh_ca",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:   utils.ToBoolPtr(false),
					IdempotentHint: utils.ToBoolPtr(false),
				},
			),
			mcp.WithDescription("Configures the Certificate Authority (CA) signing key for an SSH secrets engine mount, enabling SSH certificate signing. By default Vault generates the signing key pair internally ('generate_signing_key=true'): the private key never leaves Vault and is never returned. Returns the public key, which must be installed in the TrustedUserCAKeys (for user certificates) or known_hosts (for host certificates) of the target SSH servers."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The SSH mount to configure. For example 'ssh-client-ca'. The mount must already exist (see create_mount with type 'ssh')."),
			),
			mcp.WithBoolean("generate_signing_key",
				mcp.DefaultBool(true),
				mcp.Description("Whether Vault should generate the CA signing key pair internally. Defaults to true. Set to false only if you are supplying your own 'public_key' and 'private_key'."),
			),
			mcp.WithString("key_type",
				mcp.Description("Optional key type when generating the signing key (for example 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519'). Defaults to Vault's default (ssh-rsa)."),
			),
			mcp.WithString("public_key",
				mcp.Description("PEM/OpenSSH-encoded public key. Required (together with 'private_key') only when 'generate_signing_key' is false."),
			),
			mcp.WithString("private_key",
				mcp.Description("PEM-encoded private key. Required (together with 'public_key') only when 'generate_signing_key' is false. Handle with care: this value is sent to Vault."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return configureSshCaHandler(ctx, req, logger)
		},
	}
}

func configureSshCaHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling configure_ssh_ca request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// generate_signing_key defaults to true when not supplied.
	generate := true
	if v, ok := args["generate_signing_key"].(bool); ok {
		generate = v
	}

	publicKey, _ := args["public_key"].(string)
	privateKey, _ := args["private_key"].(string)
	keyType, _ := args["key_type"].(string)

	requestData := map[string]interface{}{
		"generate_signing_key": generate,
	}

	if generate {
		if keyType != "" {
			requestData["key_type"] = keyType
		}
	} else {
		// When not generating, both halves of the key pair are required.
		if publicKey == "" || privateKey == "" {
			return mcp.NewToolResultError("'public_key' and 'private_key' are both required when 'generate_signing_key' is false"), nil
		}
		requestData["public_key"] = publicKey
		requestData["private_key"] = privateKey
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	fullPath := fmt.Sprintf("%s/config/ca", mount)

	secret, err := vault.Logical().Write(fullPath, requestData)
	if err != nil {
		logger.WithError(err).WithField("mount", mount).Error("Failed to configure SSH CA")
		return mcp.NewToolResultError(fmt.Sprintf("failed to write to path '%s': %v", fullPath, err)), nil
	}

	logger.WithFields(log.Fields{
		"mount":    mount,
		"generate": generate,
	}).Info("Successfully configured SSH CA signing key")

	// Vault returns the public key when it generates the key pair.
	if secret != nil && secret.Data != nil {
		if pub, ok := secret.Data["public_key"]; ok {
			return mcp.NewToolResultText(fmt.Sprintf(
				"Successfully configured the SSH CA signing key on mount '%s'. Install this public key as a TrustedUserCAKeys (user certs) or in known_hosts (host certs) on your SSH servers:\n%v",
				mount, pub,
			)), nil
		}
	}

	return mcp.NewToolResultText(fmt.Sprintf(
		"Successfully configured the SSH CA signing key on mount '%s'. Retrieve the public key with read_ssh_ca.",
		mount,
	)), nil
}

// ReadSshCa creates a tool for reading the public CA signing key of an SSH mount.
func ReadSshCa(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_ssh_ca",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Reads the public CA signing key configured on an SSH secrets engine mount. Returns the public key to distribute to SSH servers (TrustedUserCAKeys or known_hosts). The private key is never returned."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The SSH mount to read the CA public key from. For example 'ssh-client-ca'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readSshCaHandler(ctx, req, logger)
		},
	}
}

func readSshCaHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_ssh_ca request")

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

	fullPath := fmt.Sprintf("%s/config/ca", mount)

	secret, err := vault.Logical().Read(fullPath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to read SSH CA on mount '%s': %v", mount, err)), nil
	}

	if secret == nil || secret.Data == nil || secret.Data["public_key"] == nil {
		return mcp.NewToolResultError(fmt.Sprintf("No CA signing key is configured on mount '%s'. Configure one with configure_ssh_ca.", mount)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf(
		"SSH CA public key for mount '%s':\n%v",
		mount, secret.Data["public_key"],
	)), nil
}

// DeleteSshCa creates a tool for deleting the CA signing key of an SSH mount.
func DeleteSshCa(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("delete_ssh_ca",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Deletes the CA signing key configured on an SSH secrets engine mount. After deletion the mount can no longer sign SSH certificates until a new key is configured. Any certificates already signed remain valid until they expire."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The SSH mount to delete the CA signing key from. For example 'ssh-client-ca'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return deleteSshCaHandler(ctx, req, logger)
		},
	}
}

func deleteSshCaHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling delete_ssh_ca request")

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

	fullPath := fmt.Sprintf("%s/config/ca", mount)

	if _, err := vault.Logical().Delete(fullPath); err != nil {
		logger.WithError(err).WithField("mount", mount).Error("Failed to delete SSH CA")
		return mcp.NewToolResultError(fmt.Sprintf("failed to delete SSH CA on mount '%s': %v", mount, err)), nil
	}

	logger.WithField("mount", mount).Info("Successfully deleted SSH CA signing key")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully deleted the SSH CA signing key on mount '%s'.", mount)), nil
}
