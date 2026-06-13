// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package config holds server-side security configuration for the Vault MCP
// server. All values here are operator-controlled (environment variables or
// CLI flags) and deliberately cannot be set or overridden by the MCP client,
// per session, or via HTTP headers.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Environment variable names.
const (
	EnvReadOnly          = "VAULT_MCP_READ_ONLY"
	EnvAdminTools        = "VAULT_MCP_ADMIN_TOOLS"
	EnvAuditTools        = "VAULT_MCP_AUDIT_TOOLS"
	EnvAllowOrphanTokens = "VAULT_MCP_ALLOW_ORPHAN_TOKENS"
	EnvTokenMaxTTL       = "VAULT_MCP_TOKEN_MAX_TTL"
)

// DefaultTokenMaxTTL caps the TTL of tokens minted through the create_token
// tool. Matches Vault's own default maximum token TTL (768h / 32 days).
const DefaultTokenMaxTTL = 768 * time.Hour

// Config is the operator-controlled security configuration.
type Config struct {
	// ReadOnly hides every mutating or credential-minting tool from the MCP
	// client and additionally blocks them at call time via an independent
	// allowlist middleware.
	ReadOnly bool

	// AdminTools enables the admin tool group: ACL policies, auth methods,
	// userpass users, AppRole, tokens, identity, and leases. Default off —
	// these tools can reconfigure Vault's security model, so they must be
	// an explicit operator decision.
	AdminTools bool

	// AuditTools enables audit device management. Default off — disabling
	// an audit device destroys the audit trail.
	AuditTools bool

	// AllowOrphanTokens permits create_token to mint orphan and periodic
	// tokens. Default off: such tokens survive revocation of the parent
	// token and defeat the operator's natural kill switch.
	AllowOrphanTokens bool

	// TokenMaxTTL caps the TTL of tokens minted via create_token.
	TokenMaxTTL time.Duration
}

// parseBoolEnv parses a boolean environment variable, failing closed: an
// unparseable value is a startup error, never silently treated as false.
func parseBoolEnv(name string) (bool, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return false, nil
	}
	val, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid boolean value %q for %s: must be true or false", raw, name)
	}
	return val, nil
}

// FromEnv builds the configuration from environment variables. Any invalid
// value is an error so the server refuses to start rather than guessing.
func FromEnv() (Config, error) {
	cfg := Config{TokenMaxTTL: DefaultTokenMaxTTL}

	var err error
	if cfg.ReadOnly, err = parseBoolEnv(EnvReadOnly); err != nil {
		return Config{}, err
	}
	if cfg.AdminTools, err = parseBoolEnv(EnvAdminTools); err != nil {
		return Config{}, err
	}
	if cfg.AuditTools, err = parseBoolEnv(EnvAuditTools); err != nil {
		return Config{}, err
	}
	if cfg.AllowOrphanTokens, err = parseBoolEnv(EnvAllowOrphanTokens); err != nil {
		return Config{}, err
	}

	if raw, ok := os.LookupEnv(EnvTokenMaxTTL); ok && raw != "" {
		ttl, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid duration %q for %s: %w", raw, EnvTokenMaxTTL, err)
		}
		if ttl <= 0 {
			return Config{}, fmt.Errorf("%s must be a positive duration, got %q", EnvTokenMaxTTL, raw)
		}
		cfg.TokenMaxTTL = ttl
	}

	return cfg, nil
}
