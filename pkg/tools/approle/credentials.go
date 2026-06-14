// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package approle

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// maxWrapTTL caps how long a response-wrapping token for a generated
// secret-id may live. Long-lived wrapping tokens widen the interception
// window, defeating the purpose of wrapping.
const maxWrapTTL = time.Hour

// ReadRoleID creates a tool for reading the role-id of an AppRole role.
//
// This is deliberately classified as mutating (not read-only) even though it
// is an HTTP read: the role-id is one half of an AppRole login credential.
func ReadRoleID(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_approle_role_id",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(false), // reveals credential material
				},
			),
			mcp.WithDescription("Reads the role-id of an AppRole role. SECURITY: the role-id is one half of an AppRole login credential (combined with a secret-id it logs in to Vault), so the returned value enters the conversation context. Only call this when the role-id is actually needed."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the AppRole role whose role-id to read."),
			),
			mcp.WithString("mount",
				mcp.Description("The mount path of the AppRole auth method, without the 'auth/' prefix or a trailing slash. Defaults to 'approle'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readRoleIDHandler(ctx, req, logger)
		},
	}
}

func readRoleIDHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_approle_role_id request")

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

	secret, err := vault.Logical().Read(fmt.Sprintf("auth/%s/role/%s/role-id", mount, name))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read role-id for AppRole role '%s': %v", name, err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError(fmt.Sprintf("AppRole role '%s' does not exist on mount '%s'", name, mount)), nil
	}

	roleID, _ := secret.Data["role_id"].(string)
	if roleID == "" {
		return mcp.NewToolResultError(fmt.Sprintf("Vault returned no role_id for AppRole role '%s'", name)), nil
	}

	logger.WithFields(log.Fields{"role": name, "mount": mount}).Info("Read AppRole role-id")

	return mcp.NewToolResultText(fmt.Sprintf("role_id for AppRole role '%s' on mount '%s': %s", name, mount, roleID)), nil
}

// GenerateSecretID creates a tool for generating a secret-id for an AppRole role.
func GenerateSecretID(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("generate_approle_secret_id",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(false), // mints a credential
				},
			),
			mcp.WithDescription("Generates a new secret-id for an AppRole role. SECURITY: a secret-id combined with the role-id is a complete Vault login credential. STRONGLY RECOMMENDED: pass 'wrap_ttl' (for example '120s') so Vault response-wraps the secret-id and only a single-use wrapping token enters the conversation context; the consumer then retrieves the real secret-id with 'vault unwrap <token>'. Without 'wrap_ttl' the plaintext secret-id is returned directly into the conversation."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the AppRole role to generate a secret-id for."),
			),
			mcp.WithString("wrap_ttl",
				mcp.Description("Optional but strongly recommended: response-wrapping TTL as a duration string, for example '120s' or '5m'. Must be positive and at most '1h'. When set, the tool returns a single-use wrapping token instead of the plaintext secret-id."),
			),
			mcp.WithString("mount",
				mcp.Description("The mount path of the AppRole auth method, without the 'auth/' prefix or a trailing slash. Defaults to 'approle'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return generateSecretIDHandler(ctx, req, logger)
		},
	}
}

func generateSecretIDHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling generate_approle_secret_id request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	name, ok := args["name"].(string)
	if !ok || name == "" {
		return mcp.NewToolResultError("Missing or invalid 'name' parameter"), nil
	}

	mount := extractMount(args)

	wrapTTL := ""
	if raw, ok := args["wrap_ttl"].(string); ok && raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid 'wrap_ttl' parameter: %v (use a duration string such as '120s')", err)), nil
		}
		if d <= 0 {
			return mcp.NewToolResultError("Invalid 'wrap_ttl' parameter: must be a positive duration such as '120s'"), nil
		}
		if d > maxWrapTTL {
			return mcp.NewToolResultError("Invalid 'wrap_ttl' parameter: must be at most '1h'"), nil
		}
		wrapTTL = raw
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	path := fmt.Sprintf("auth/%s/role/%s/secret-id", mount, name)

	if wrapTTL != "" {
		// Response-wrap on a clone of the session client so the wrapping
		// lookup func does not leak into other requests on this session.
		wrapped, err := vault.Clone()
		if err != nil {
			logger.WithError(err).Error("Failed to clone Vault client for response wrapping")
			return mcp.NewToolResultError(fmt.Sprintf("Failed to clone Vault client for response wrapping: %v", err)), nil
		}
		wrapped.SetToken(vault.Token())
		// Clone() does not copy headers unless config.CloneHeaders is set, and
		// the namespace is carried as the X-Vault-Namespace header — re-apply
		// it so the wrapped call targets the same namespace as the session.
		wrapped.SetNamespace(vault.Namespace())
		wrapped.SetWrappingLookupFunc(func(string, string) string { return wrapTTL })

		secret, err := wrapped.Logical().Write(path, nil)
		if err != nil {
			logger.WithError(err).WithFields(log.Fields{"role": name, "mount": mount}).Error("Failed to generate wrapped secret-id")
			return mcp.NewToolResultError(fmt.Sprintf("Failed to generate wrapped secret-id for AppRole role '%s': %v", name, err)), nil
		}
		if secret == nil || secret.WrapInfo == nil || secret.WrapInfo.Token == "" {
			return mcp.NewToolResultError(fmt.Sprintf("Vault did not return wrapping information for AppRole role '%s'", name)), nil
		}

		logger.WithFields(log.Fields{"role": name, "mount": mount, "wrap_ttl": wrapTTL}).Info("Generated response-wrapped AppRole secret-id")

		return mcp.NewToolResultText(fmt.Sprintf(
			"Generated a response-wrapped credential for AppRole role '%s' on mount '%s'.\n"+
				"Wrapping token (single use, expires in %ds): %s\n"+
				"Deliver this token to the consuming application and run: vault unwrap %s\n"+
				"The plaintext credential never entered this conversation. If unwrapping fails because the token was already used, the credential may have been intercepted: revoke and regenerate.",
			name, mount, secret.WrapInfo.TTL, secret.WrapInfo.Token, secret.WrapInfo.Token)), nil
	}

	secret, err := vault.Logical().Write(path, nil)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{"role": name, "mount": mount}).Error("Failed to generate secret-id")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to generate secret-id for AppRole role '%s': %v", name, err)), nil
	}
	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError(fmt.Sprintf("Vault returned no secret-id data for AppRole role '%s'", name)), nil
	}

	secretID, _ := secret.Data["secret_id"].(string)
	accessor, _ := secret.Data["secret_id_accessor"].(string)
	if secretID == "" {
		return mcp.NewToolResultError(fmt.Sprintf("Vault returned no secret_id for AppRole role '%s'", name)), nil
	}

	logger.WithFields(log.Fields{"role": name, "mount": mount}).Info("Generated AppRole secret-id")

	return mcp.NewToolResultText(fmt.Sprintf(
		"Generated secret-id for AppRole role '%s' on mount '%s'.\n"+
			"secret_id: %s\n"+
			"secret_id_accessor: %s\n"+
			"WARNING: this plaintext secret-id has entered the conversation context and may persist in logs or transcripts. "+
			"Treat it as exposed: deliver it to the consuming application immediately and rotate it (destroy via the accessor and regenerate) if there is any chance it leaked. "+
			"Next time, prefer 'wrap_ttl' so only a single-use wrapping token enters the context.",
		name, mount, secretID, accessor)), nil
}

// ListSecretIDAccessors creates a tool for listing secret-id accessors of an
// AppRole role. Accessors are safe references: they cannot be used to log in.
func ListSecretIDAccessors(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_approle_secret_id_accessors",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Lists the secret-id accessors of an AppRole role. Accessors identify issued secret-ids for auditing and revocation but are not credentials themselves and cannot be used to log in."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the AppRole role whose secret-id accessors to list."),
			),
			mcp.WithString("mount",
				mcp.Description("The mount path of the AppRole auth method, without the 'auth/' prefix or a trailing slash. Defaults to 'approle'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listSecretIDAccessorsHandler(ctx, req, logger)
		},
	}
}

func listSecretIDAccessorsHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_approle_secret_id_accessors request")

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

	secret, err := vault.Logical().List(fmt.Sprintf("auth/%s/role/%s/secret-id", mount, name))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list secret-id accessors for AppRole role '%s': %v", name, err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultText(fmt.Sprintf("No secret-id accessors found for AppRole role '%s' on mount '%s'.", name, mount)), nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No secret-id accessors found for AppRole role '%s' on mount '%s'.", name, mount)), nil
	}

	accessors := make([]string, 0, len(keys))
	for _, k := range keys {
		accessors = append(accessors, fmt.Sprintf("%v", k))
	}

	return mcp.NewToolResultText(fmt.Sprintf("Secret-id accessors for AppRole role '%s' on mount '%s': %s", name, mount, strings.Join(accessors, ", "))), nil
}

// DestroySecretID creates a tool for destroying a secret-id by its accessor.
func DestroySecretID(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("destroy_approle_secret_id",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Destroys (revokes) a single AppRole secret-id identified by its accessor. The application holding that secret-id can no longer use it to log in. Use list_approle_secret_id_accessors to find accessors."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the AppRole role the secret-id belongs to."),
			),
			mcp.WithString("secret_id_accessor",
				mcp.Required(),
				mcp.Description("The accessor of the secret-id to destroy, as returned by generate_approle_secret_id or list_approle_secret_id_accessors."),
			),
			mcp.WithString("mount",
				mcp.Description("The mount path of the AppRole auth method, without the 'auth/' prefix or a trailing slash. Defaults to 'approle'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return destroySecretIDHandler(ctx, req, logger)
		},
	}
}

func destroySecretIDHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling destroy_approle_secret_id request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	name, ok := args["name"].(string)
	if !ok || name == "" {
		return mcp.NewToolResultError("Missing or invalid 'name' parameter"), nil
	}

	accessor, ok := args["secret_id_accessor"].(string)
	if !ok || accessor == "" {
		return mcp.NewToolResultError("Missing or invalid 'secret_id_accessor' parameter"), nil
	}

	mount := extractMount(args)

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	path := fmt.Sprintf("auth/%s/role/%s/secret-id-accessor/destroy", mount, name)
	if _, err := vault.Logical().Write(path, map[string]interface{}{"secret_id_accessor": accessor}); err != nil {
		logger.WithError(err).WithFields(log.Fields{"role": name, "mount": mount}).Error("Failed to destroy secret-id")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to destroy secret-id for AppRole role '%s': %v", name, err)), nil
	}

	logger.WithFields(log.Fields{"role": name, "mount": mount}).Info("Successfully destroyed AppRole secret-id")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully destroyed secret-id with accessor '%s' for AppRole role '%s' on mount '%s'", accessor, name, mount)), nil
}
