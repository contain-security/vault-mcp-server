// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package prompts

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault-mcp-server/pkg/config"
	"github.com/mark3labs/mcp-go/mcp"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func testLogger() *log.Logger {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)
	return logger
}

func newPromptRequest(args map[string]string) mcp.GetPromptRequest {
	req := mcp.GetPromptRequest{}
	req.Params.Arguments = args
	return req
}

// promptText returns the concatenated text of all messages in a prompt result.
func promptText(t *testing.T, result *mcp.GetPromptResult) string {
	t.Helper()
	require.NotNil(t, result)
	require.NotEmpty(t, result.Messages)
	var b strings.Builder
	for _, m := range result.Messages {
		tc, ok := m.Content.(mcp.TextContent)
		require.True(t, ok)
		b.WriteString(tc.Text)
	}
	return b.String()
}

func adminConfig() config.Config {
	return config.Config{AdminTools: true, TokenMaxTTL: config.DefaultTokenMaxTTL}
}

func TestPromptsFor_Gating(t *testing.T) {
	logger := testLogger()

	t.Run("registered when admin tools enabled and not read-only", func(t *testing.T) {
		require.Len(t, promptsFor(logger, adminConfig()), 4)
	})

	t.Run("not registered without admin tools", func(t *testing.T) {
		require.Empty(t, promptsFor(logger, config.Config{TokenMaxTTL: config.DefaultTokenMaxTTL}))
	})

	t.Run("not registered in read-only mode", func(t *testing.T) {
		cfg := adminConfig()
		cfg.ReadOnly = true
		require.Empty(t, promptsFor(logger, cfg))
	})
}

func TestPromptsFor_UniqueNames(t *testing.T) {
	seen := map[string]bool{}
	for _, def := range promptsFor(testLogger(), adminConfig()) {
		require.False(t, seen[def.prompt.Name], "duplicate prompt name %q", def.prompt.Name)
		seen[def.prompt.Name] = true
	}
	require.Contains(t, seen, "setup_pki_approle")
	require.Contains(t, seen, "setup_ssh_approle")
	require.Contains(t, seen, "setup_kv_approle")
	require.Contains(t, seen, "decommission_approle")
}

// handlerFor returns the handler for the named prompt.
func handlerFor(t *testing.T, name string) func(context.Context, mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	t.Helper()
	for _, def := range promptsFor(testLogger(), adminConfig()) {
		if def.prompt.Name == name {
			return def.handler
		}
	}
	t.Fatalf("prompt %q not found", name)
	return nil
}

func TestSetupPkiApprole_RendersLeastPrivilege(t *testing.T) {
	h := handlerFor(t, "setup_pki_approle")
	result, err := h(context.Background(), newPromptRequest(map[string]string{
		"app_name":  "payments-api",
		"pki_mount": "pki_int",
		"pki_role":  "example-dot-com",
	}))
	require.NoError(t, err)
	text := promptText(t, result)

	// Default action is issue; the granted path must be the single role path.
	require.Contains(t, text, `path "pki_int/issue/example-dot-com"`)
	require.Contains(t, text, "payments-api-pki-example-dot-com") // policy name
	require.Contains(t, text, "generate_approle_secret_id")
	require.Contains(t, text, "wrap_ttl")
	// Must not suggest wildcard / mount-wide access.
	require.NotContains(t, text, "pki_int/*")
}

func TestSetupPkiApprole_SignAction(t *testing.T) {
	h := handlerFor(t, "setup_pki_approle")
	result, err := h(context.Background(), newPromptRequest(map[string]string{
		"app_name":  "signer",
		"pki_mount": "pki_int",
		"pki_role":  "example-dot-com",
		"action":    "sign",
	}))
	require.NoError(t, err)
	require.Contains(t, promptText(t, result), `path "pki_int/sign/example-dot-com"`)
}

func TestSetupPkiApprole_InvalidAction(t *testing.T) {
	h := handlerFor(t, "setup_pki_approle")
	_, err := h(context.Background(), newPromptRequest(map[string]string{
		"app_name":  "x",
		"pki_mount": "pki_int",
		"pki_role":  "r",
		"action":    "revoke",
	}))
	require.Error(t, err)
}

func TestSetupPkiApprole_MissingRequired(t *testing.T) {
	h := handlerFor(t, "setup_pki_approle")
	_, err := h(context.Background(), newPromptRequest(map[string]string{"app_name": "x"}))
	require.Error(t, err)
}

func TestSetupSshApprole_RendersLeastPrivilege(t *testing.T) {
	h := handlerFor(t, "setup_ssh_approle")
	result, err := h(context.Background(), newPromptRequest(map[string]string{
		"app_name":  "bastion",
		"ssh_mount": "ssh-client-ca",
		"ssh_role":  "clients",
	}))
	require.NoError(t, err)
	text := promptText(t, result)
	require.Contains(t, text, `path "ssh-client-ca/sign/clients"`)
	require.Contains(t, text, "bastion-ssh-clients")
	require.Contains(t, text, "wrap_ttl")
}

func TestSetupKvApprole_ReadVsWrite(t *testing.T) {
	h := handlerFor(t, "setup_kv_approle")

	ro, err := h(context.Background(), newPromptRequest(map[string]string{
		"app_name": "app", "kv_mount": "apps", "kv_path": "web/db",
	}))
	require.NoError(t, err)
	roText := promptText(t, ro)
	require.Contains(t, roText, `"read"`)
	// Policy name must include a sanitized path segment so two KV roles on the
	// same mount but different paths don't collide.
	require.Contains(t, roText, "app-kv-apps-web-db")

	rw, err := h(context.Background(), newPromptRequest(map[string]string{
		"app_name": "app", "kv_mount": "apps", "kv_path": "web/db", "access": "read-write",
	}))
	require.NoError(t, err)
	rwText := promptText(t, rw)
	require.Contains(t, rwText, `"create","update","read"`)
	// Mentions both KV v1 and v2 path handling.
	require.Contains(t, rwText, "apps/data/web/db")
	require.Contains(t, rwText, "apps/metadata/web/db")
}

func TestSetupKvApprole_InvalidAccess(t *testing.T) {
	h := handlerFor(t, "setup_kv_approle")
	_, err := h(context.Background(), newPromptRequest(map[string]string{
		"app_name": "app", "kv_mount": "apps", "kv_path": "p", "access": "delete",
	}))
	require.Error(t, err)
}

func TestDecommissionApprole_DeletePoliciesToggle(t *testing.T) {
	h := handlerFor(t, "decommission_approle")

	del, err := h(context.Background(), newPromptRequest(map[string]string{"app_name": "payments-api"}))
	require.NoError(t, err)
	delText := promptText(t, del)
	require.Contains(t, delText, "destroy_approle_secret_id")
	require.Contains(t, delText, "delete_approle_role")
	require.Contains(t, delText, "delete_policy")
	require.Contains(t, delText, "payments-api-") // dedicated-policy prefix match
	require.Contains(t, delText, "NEVER delete \"default\", \"root\"")

	keep, err := h(context.Background(), newPromptRequest(map[string]string{
		"app_name": "payments-api", "delete_policies": "false",
	}))
	require.NoError(t, err)
	require.NotContains(t, promptText(t, keep), "delete_policy")
}

func TestDecommissionApprole_InvalidToggle(t *testing.T) {
	h := handlerFor(t, "decommission_approle")
	_, err := h(context.Background(), newPromptRequest(map[string]string{
		"app_name": "x", "delete_policies": "maybe",
	}))
	require.Error(t, err)
}
