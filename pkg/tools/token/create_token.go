// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package token

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/config"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// maxWrapTTL caps the lifetime of a response-wrapping token. Wrapping tokens
// are meant to be unwrapped promptly by the final consumer; one hour is
// already generous.
const maxWrapTTL = time.Hour

// CreateToken creates a tool for minting new Vault tokens.
//
// This is the highest-privilege-escalation-risk tool in the server (see
// AR-002 in the architecture review). Several guardrails are enforced
// server-side and cannot be bypassed via tool arguments:
//   - the 'root' policy is always refused
//   - the requested TTL must not exceed cfg.TokenMaxTTL
//   - orphan and periodic tokens are refused unless cfg.AllowOrphanTokens
func CreateToken(logger *log.Logger, cfg config.Config) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("create_token",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(false),
				},
			),
			mcp.WithDescription("Creates a new Vault token with the given policies and TTL. "+
				"Server-side guardrails (not bypassable via arguments): the 'root' policy is always refused; "+
				"the TTL is capped by the operator-configured maximum (VAULT_MCP_TOKEN_MAX_TTL, default 768h); "+
				"orphan and periodic tokens are refused unless the operator set VAULT_MCP_ALLOW_ORPHAN_TOKENS=true. "+
				"Strongly recommended: set 'wrap_ttl' so the response contains only a short-lived response-wrapping "+
				"token instead of the real token value — the real token then never enters the conversation context "+
				"and can be retrieved exactly once via 'vault unwrap <wrapping_token>'. "+
				"Without 'wrap_ttl' the raw token value is returned in the tool result and becomes part of the conversation."),
			mcp.WithString("policies",
				mcp.Required(),
				mcp.Description("Comma-separated list of ACL policy names to attach to the token. For example 'app-read,metrics'. The 'root' policy is refused."),
			),
			mcp.WithString("ttl",
				mcp.Required(),
				mcp.Description("Time-to-live of the token as a Go duration string, e.g. '1h', '30m', '24h'. Must be positive and must not exceed the server-side cap."),
			),
			mcp.WithString("display_name",
				mcp.Description("Optional human-readable display name for the token, shown in audit logs and token lookups."),
			),
			mcp.WithBoolean("renewable",
				mcp.Description("Whether the token can be renewed before it expires. Defaults to true."),
			),
			mcp.WithBoolean("orphan",
				mcp.Description("Create the token without a parent so it survives revocation of the creating token. Refused unless the operator enabled VAULT_MCP_ALLOW_ORPHAN_TOKENS."),
			),
			mcp.WithString("period",
				mcp.Description("Optional period duration (e.g. '24h') for a periodic token that can be renewed indefinitely. Refused unless the operator enabled VAULT_MCP_ALLOW_ORPHAN_TOKENS."),
			),
			mcp.WithString("wrap_ttl",
				mcp.Description("Recommended. Response-wrapping TTL as a duration string (e.g. '120s', max '1h'). When set, the result contains only a single-use wrapping token and the real token value never enters the conversation."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return createTokenHandler(ctx, req, logger, cfg)
		},
	}
}

func createTokenHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger, cfg config.Config) (*mcp.CallToolResult, error) {
	logger.Debug("Handling create_token request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	policiesRaw, ok := args["policies"].(string)
	if !ok || strings.TrimSpace(policiesRaw) == "" {
		return mcp.NewToolResultError("Missing or invalid 'policies' parameter: provide a comma-separated list of policy names"), nil
	}

	var policies []string
	for _, p := range strings.Split(policiesRaw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.EqualFold(p, "root") {
			return mcp.NewToolResultError("Refusing to create a token with the 'root' policy: minting root-equivalent credentials through the MCP server is not permitted"), nil
		}
		policies = append(policies, p)
	}
	if len(policies) == 0 {
		return mcp.NewToolResultError("Refusing to create a token with an empty policies list: specify at least one ACL policy"), nil
	}

	ttlRaw, ok := args["ttl"].(string)
	if !ok || ttlRaw == "" {
		return mcp.NewToolResultError("Missing or invalid 'ttl' parameter: provide a duration string such as '1h'"), nil
	}
	ttl, err := time.ParseDuration(ttlRaw)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Invalid 'ttl' value %q: %v (use a Go duration string such as '1h' or '30m')", ttlRaw, err)), nil
	}
	if ttl <= 0 {
		return mcp.NewToolResultError(fmt.Sprintf("Invalid 'ttl' value %q: TTL must be positive", ttlRaw)), nil
	}
	if ttl > cfg.TokenMaxTTL {
		return mcp.NewToolResultError(fmt.Sprintf("Refusing to create token: requested TTL %s exceeds the server-side cap of %s. The cap is operator-controlled via the %s environment variable and cannot be overridden through tool arguments", ttl, cfg.TokenMaxTTL, config.EnvTokenMaxTTL)), nil
	}

	orphan, _ := args["orphan"].(bool)
	period, _ := args["period"].(string)

	if orphan && !cfg.AllowOrphanTokens {
		return mcp.NewToolResultError(fmt.Sprintf("Refusing to create an orphan token: orphan tokens survive revocation of the parent token and defeat the operator's kill switch. The operator must set %s=true to permit this", config.EnvAllowOrphanTokens)), nil
	}
	if period != "" && !cfg.AllowOrphanTokens {
		return mcp.NewToolResultError(fmt.Sprintf("Refusing to create a periodic token: periodic tokens can be renewed indefinitely. The operator must set %s=true to permit this", config.EnvAllowOrphanTokens)), nil
	}

	wrapTTL, _ := args["wrap_ttl"].(string)
	if wrapTTL != "" {
		wd, err := time.ParseDuration(wrapTTL)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid 'wrap_ttl' value %q: %v (use a duration string such as '120s')", wrapTTL, err)), nil
		}
		if wd <= 0 {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid 'wrap_ttl' value %q: must be positive", wrapTTL)), nil
		}
		if wd > maxWrapTTL {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid 'wrap_ttl' value %q: must not exceed %s", wrapTTL, maxWrapTTL)), nil
		}
	}

	renewable := true
	if v, ok := args["renewable"].(bool); ok {
		renewable = v
	}

	displayName, _ := args["display_name"].(string)

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	tokenReq := &api.TokenCreateRequest{
		Policies:    policies,
		TTL:         ttlRaw,
		DisplayName: displayName,
		Renewable:   &renewable,
		Period:      period,
		NoParent:    orphan,
	}

	creator := vault
	if wrapTTL != "" {
		wrapped, err := vault.Clone()
		if err != nil {
			logger.WithError(err).Error("Failed to clone Vault client for response wrapping")
			return mcp.NewToolResultError(fmt.Sprintf("Failed to set up response wrapping: %v", err)), nil
		}
		wrapped.SetToken(vault.Token())
		// Clone() does not copy headers unless config.CloneHeaders is set, and
		// the namespace is carried as the X-Vault-Namespace header — re-apply
		// it so the wrapped call targets the same namespace as the session.
		wrapped.SetNamespace(vault.Namespace())
		wrapped.SetWrappingLookupFunc(func(string, string) string { return wrapTTL })
		creator = wrapped
	}

	var secret *api.Secret
	if orphan {
		secret, err = creator.Auth().Token().CreateOrphan(tokenReq)
	} else {
		secret, err = creator.Auth().Token().Create(tokenReq)
	}
	if err != nil {
		logger.WithError(err).Error("Failed to create token")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create token: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"policies": strings.Join(policies, ","),
		"ttl":      ttlRaw,
		"orphan":   orphan,
		"wrapped":  wrapTTL != "",
	}).Info("Successfully created token")

	if wrapTTL != "" {
		if secret == nil || secret.WrapInfo == nil {
			return mcp.NewToolResultError("Token creation succeeded but Vault did not return wrapping information"), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf(
			"Token created and response-wrapped.\nWrapping token: %s\nWrapping token TTL: %d seconds\n\n"+
				"The real token value was NOT returned and is not part of this conversation. "+
				"To retrieve it exactly once, run: vault unwrap %s (or POST the wrapping token to sys/wrapping/unwrap) before the wrapping TTL expires.",
			secret.WrapInfo.Token, secret.WrapInfo.TTL, secret.WrapInfo.Token)), nil
	}

	if secret == nil || secret.Auth == nil {
		return mcp.NewToolResultError("Token creation succeeded but Vault did not return auth information"), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf(
		"Token created.\nToken: %s\nAccessor: %s\nPolicies: %s\nTTL: %s\n\n"+
			"WARNING: the raw token value above has now entered the conversation context. "+
			"Treat this conversation as sensitive, deliver the token to its consumer promptly, "+
			"and prefer the 'wrap_ttl' parameter in the future so only a single-use wrapping token is exposed. "+
			"The token can be revoked at any time via revoke_token with accessor '%s'.",
		secret.Auth.ClientToken, secret.Auth.Accessor, strings.Join(policies, ", "), ttlRaw, secret.Auth.Accessor)), nil
}
