// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package tools

import (
	"context"
	"testing"

	"github.com/hashicorp/vault-mcp-server/pkg/config"
	"github.com/mark3labs/mcp-go/mcp"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *log.Logger {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)
	return logger
}

// fullConfig enables every tool category so tests see the complete surface.
func fullConfig() config.Config {
	return config.Config{
		AdminTools:  true,
		AuditTools:  true,
		TokenMaxTTL: config.DefaultTokenMaxTTL,
	}
}

// TestReadOnlyAllowlistConsistency keeps the two independent read-only
// enforcement layers (registration classification and static call-time
// allowlist) aligned, per architecture review finding AR-005.
func TestReadOnlyAllowlistConsistency(t *testing.T) {
	all := allTools(testLogger(), fullConfig())
	require.NotEmpty(t, all)

	registered := map[string]bool{} // name -> ReadOnly classification
	for _, tool := range all {
		name := tool.Tool.Name
		_, dup := registered[name]
		require.False(t, dup, "duplicate tool name %q", name)
		registered[name] = tool.ReadOnly
	}

	// Every tool classified read-only must be on the allowlist, and every
	// mutating tool must be absent from it.
	for name, readOnly := range registered {
		if readOnly {
			assert.True(t, IsReadOnlyTool(name),
				"tool %q is classified ReadOnly but missing from the static allowlist", name)
		} else {
			assert.False(t, IsReadOnlyTool(name),
				"tool %q is mutating or credential-minting but present on the static allowlist", name)
		}
	}

	// Every allowlist entry must correspond to a registered read-only tool —
	// stale entries would silently widen read-only mode over time.
	for name := range readOnlyToolNames {
		readOnly, exists := registered[name]
		assert.True(t, exists, "allowlist entry %q does not match any registered tool", name)
		assert.True(t, readOnly, "allowlist entry %q matches a tool not classified ReadOnly", name)
	}
}

// TestReadOnlyAllowlistExcludesCredentialMinting pins the specific
// "read-sounding but credential-producing" operations called out in the
// architecture review. None of these may ever appear on the allowlist.
func TestReadOnlyAllowlistExcludesCredentialMinting(t *testing.T) {
	for _, name := range []string{
		"read_approle_role_id",
		"generate_approle_secret_id",
		"create_token",
		"renew_token",
		"issue_pki_certificate",
		"generate_pki_root",
		"generate_pki_intermediate_csr",
		"sign_pki_intermediate",
		"revoke_lease",
		"write_secret",
		"write_policy",
	} {
		assert.False(t, IsReadOnlyTool(name), "%q must not be on the read-only allowlist", name)
	}
}

func TestSelectToolsReadOnlyMode(t *testing.T) {
	cfg := fullConfig()
	cfg.ReadOnly = true

	selected := SelectTools(testLogger(), cfg)
	require.NotEmpty(t, selected)
	for _, tool := range selected {
		assert.True(t, tool.ReadOnly, "read-only mode registered mutating tool %q", tool.Tool.Name)
		assert.True(t, IsReadOnlyTool(tool.Tool.Name),
			"read-only mode registered tool %q that is not on the allowlist", tool.Tool.Name)
	}
}

func TestSelectToolsCategoryGating(t *testing.T) {
	logger := testLogger()

	t.Run("default config registers only core tools", func(t *testing.T) {
		cfg := config.Config{TokenMaxTTL: config.DefaultTokenMaxTTL}
		for _, tool := range SelectTools(logger, cfg) {
			assert.Equal(t, "core", string(tool.Category),
				"tool %q registered without its category being enabled", tool.Tool.Name)
		}
	})

	t.Run("admin tools require the admin flag", func(t *testing.T) {
		cfg := config.Config{TokenMaxTTL: config.DefaultTokenMaxTTL}
		names := map[string]bool{}
		for _, tool := range SelectTools(logger, cfg) {
			names[tool.Tool.Name] = true
		}
		assert.False(t, names["write_policy"], "admin tool registered without admin flag")

		cfg.AdminTools = true
		names = map[string]bool{}
		for _, tool := range SelectTools(logger, cfg) {
			names[tool.Tool.Name] = true
		}
		assert.True(t, names["write_policy"], "admin tool missing with admin flag enabled")
	})
}

func TestReadOnlyGuardMiddleware(t *testing.T) {
	logger := testLogger()

	nextCalled := false
	next := func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nextCalled = true
		return mcp.NewToolResultText("ok"), nil
	}

	makeReq := func(name string) mcp.CallToolRequest {
		req := mcp.CallToolRequest{}
		req.Params.Name = name
		return req
	}

	t.Run("blocks mutating tool in read-only mode", func(t *testing.T) {
		nextCalled = false
		handler := ReadOnlyGuardMiddleware(true, logger)(next)
		result, err := handler(context.Background(), makeReq("write_secret"))
		require.NoError(t, err)
		assert.True(t, result.IsError)
		assert.False(t, nextCalled)
	})

	t.Run("blocks unknown tool in read-only mode (default deny)", func(t *testing.T) {
		nextCalled = false
		handler := ReadOnlyGuardMiddleware(true, logger)(next)
		result, err := handler(context.Background(), makeReq("some_future_tool"))
		require.NoError(t, err)
		assert.True(t, result.IsError)
		assert.False(t, nextCalled)
	})

	t.Run("allows read-only tool in read-only mode", func(t *testing.T) {
		nextCalled = false
		handler := ReadOnlyGuardMiddleware(true, logger)(next)
		result, err := handler(context.Background(), makeReq("read_secret"))
		require.NoError(t, err)
		assert.False(t, result.IsError)
		assert.True(t, nextCalled)
	})

	t.Run("passes everything through when not read-only", func(t *testing.T) {
		nextCalled = false
		handler := ReadOnlyGuardMiddleware(false, logger)(next)
		result, err := handler(context.Background(), makeReq("write_secret"))
		require.NoError(t, err)
		assert.False(t, result.IsError)
		assert.True(t, nextCalled)
	})
}
