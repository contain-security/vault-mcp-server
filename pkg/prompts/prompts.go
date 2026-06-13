// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package prompts provides MCP prompts: parameterized, opinionated workflow
// templates that compose the server's primitive tools into the higher-level
// operations a Vault administrator is repeatedly asked for (for example,
// provisioning a least-privilege AppRole for PKI or SSH certificate signing).
//
// Prompts orchestrate the existing tools; they do not call Vault directly.
// Because the workflows here all mutate Vault (writing policies, creating
// AppRoles, generating credentials), they are only registered when admin
// tools are enabled and the server is not in read-only mode — otherwise the
// tools they drive would be unavailable and the prompts would mislead.
package prompts

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault-mcp-server/pkg/config"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// promptDef pairs an MCP prompt with its handler.
type promptDef struct {
	prompt  mcp.Prompt
	handler server.PromptHandlerFunc
}

// arg returns the trimmed value of a prompt argument, or def when absent/empty.
func arg(req mcp.GetPromptRequest, name, def string) string {
	if req.Params.Arguments != nil {
		if v, ok := req.Params.Arguments[name]; ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return def
}

// requireArgs returns an error naming the first missing required argument.
func requireArgs(req mcp.GetPromptRequest, names ...string) error {
	for _, name := range names {
		if arg(req, name, "") == "" {
			return fmt.Errorf("missing required argument '%s'", name)
		}
	}
	return nil
}

// userMessage wraps an instruction string as a single user-role prompt result.
func userMessage(description, instruction string) *mcp.GetPromptResult {
	return mcp.NewGetPromptResult(description, []mcp.PromptMessage{
		mcp.NewPromptMessage(mcp.RoleUser, mcp.NewTextContent(instruction)),
	})
}

// promptsFor returns the prompts that should be registered for the given
// configuration. All current prompts drive mutating admin tools, so they are
// gated behind admin tools being enabled and read-only mode being off.
func promptsFor(logger *log.Logger, cfg config.Config) []promptDef {
	if cfg.ReadOnly || !cfg.AdminTools {
		return nil
	}
	return []promptDef{
		setupPkiApprolePrompt(logger),
		setupSshApprolePrompt(logger),
		setupKvApprolePrompt(logger),
		decommissionApprolePrompt(logger),
	}
}

// InitPrompts registers the configured prompts on the MCP server.
func InitPrompts(hcServer *server.MCPServer, logger *log.Logger, cfg config.Config) {
	defs := promptsFor(logger, cfg)
	for _, def := range defs {
		hcServer.AddPrompt(def.prompt, def.handler)
	}
	logger.WithField("prompts", len(defs)).Info("Registered MCP prompts")
}
