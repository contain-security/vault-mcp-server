// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

var (
	activeClients sync.Map
)

const (
	VaultAddress         = "VAULT_ADDR"
	VaultToken           = "VAULT_TOKEN"
	VaultNamespace       = "VAULT_NAMESPACE"
	VaultSkipTLSVerify   = "VAULT_SKIP_VERIFY"
	VaultHeaderToken     = "X-Vault-Token"
	VaultHeaderNamespace = "X-Vault-Namespace"
)

const DefaultVaultAddress = "http://127.0.0.1:8200"

// contextKey is a type alias to avoid lint warnings while maintaining compatibility
type contextKey string

// getEnv retrieves the value of an environment variable or returns a fallback value if not set
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// NewVaultClient creates a new Vault client for the given session
func NewVaultClient(sessionId string, vaultAddress string, vaultSkipTLSVerify bool, vaultToken string, vaultNamespace string) (*api.Client, error) {
	// Initialize Vault client. api.DefaultConfig() reads the standard Vault TLS
	// environment (VAULT_CACERT, VAULT_CAPATH, VAULT_CLIENT_CERT,
	// VAULT_CLIENT_KEY, VAULT_TLS_SERVER_NAME) and loads it into the client's
	// TLS config; an unparseable value is surfaced below by api.NewClient.
	config := api.DefaultConfig()
	config.Address = vaultAddress

	// Layer the operator's skip-verify decision on top of that config. We must
	// NOT replace config.HttpClient here: doing so would throw away the CA pool
	// loaded above, leaving VAULT_CACERT (pinning a self-signed CA) silently
	// ineffective. ConfigureTLS only flips InsecureSkipVerify and leaves the
	// configured RootCAs intact.
	if vaultSkipTLSVerify {
		if err := config.ConfigureTLS(&api.TLSConfig{Insecure: true}); err != nil {
			return nil, fmt.Errorf("failed to apply VAULT_SKIP_VERIFY: %w", err)
		}
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("api.NewClient failed to create Vault client: %v", err)
	}

	client.SetToken(vaultToken)

	if vaultNamespace != "" {
		client.SetNamespace(vaultNamespace)
	}

	activeClients.Store(sessionId, client)

	return client, nil
}

// GetVaultClient retrieves the Vault client for the given session
func GetVaultClient(sessionId string) *api.Client {
	if value, ok := activeClients.Load(sessionId); ok {
		return value.(*api.Client)
	}
	return nil
}

// DeleteVaultClient removes the Vault client for the given session
func DeleteVaultClient(sessionId string) {
	activeClients.Delete(sessionId)
}

// GetVaultClientFromContext extracts Vault client from the MCP context
func GetVaultClientFromContext(ctx context.Context, logger *log.Logger) (*api.Client, error) {
	session := server.ClientSessionFromContext(ctx)
	if session == nil {
		return nil, fmt.Errorf("no active session")
	}

	// Log the session ID for debugging
	logger.WithField("session_id", session.SessionID()).Debug("Retrieving Vault client for session")

	// Try to get existing client
	client := GetVaultClient(session.SessionID())
	if client != nil {
		return client, nil
	}

	logger.WithField("session_id", session.SessionID()).Warn("Vault client not found, creating a new one")

	return CreateVaultClientForSession(ctx, session, logger)
}

func CreateVaultClientForSession(ctx context.Context, session server.ClientSession, logger *log.Logger) (*api.Client, error) {

	// Initialize a new Vault client for this session. Context values are only
	// present when the MCP client supplied them (HTTP headers); otherwise we
	// fall back to the server's own environment.
	vaultAddress, ok := ctx.Value(contextKey(VaultAddress)).(string)
	addressFromClient := ok && vaultAddress != ""
	if !addressFromClient {
		vaultAddress = getEnv(VaultAddress, DefaultVaultAddress)
	}

	vaultToken, ok := ctx.Value(contextKey(VaultToken)).(string)
	tokenFromClient := ok && vaultToken != ""
	if !tokenFromClient {
		// Never pair the server's environment token with a client-supplied
		// Vault address: a session could otherwise point the server at an
		// attacker-controlled endpoint and have the operator's token sent to
		// it. Sessions that override VAULT_ADDR must supply their own token.
		if addressFromClient {
			return nil, fmt.Errorf("a per-session vault token (X-Vault-Token header) is required when VAULT_ADDR is supplied by the client")
		}
		vaultToken = getEnv(VaultToken, "")
		if vaultToken == "" {
			return nil, fmt.Errorf("vault token not provided for session")
		}
	}

	vaultNamespace, ok := ctx.Value(contextKey(VaultNamespace)).(string)
	if !ok || vaultNamespace == "" {
		vaultNamespace = getEnv(VaultNamespace, "")
	}

	// TLS verification of the server->Vault connection is server-side
	// configuration only; it is never accepted from the client session.
	var vaultSkipTLSVerify bool
	envVal := getEnv(VaultSkipTLSVerify, "false")
	parsed, err := strconv.ParseBool(envVal)
	if err != nil {
		logger.WithFields(log.Fields{
			"session_id": session.SessionID(),
			"value":      envVal,
		}).Warn("Invalid boolean value for VAULT_SKIP_VERIFY; using default value false")
	} else {
		vaultSkipTLSVerify = parsed
	}

	newClient, err := NewVaultClient(session.SessionID(), vaultAddress, vaultSkipTLSVerify, vaultToken, vaultNamespace)
	if err != nil {
		return nil, fmt.Errorf("NewVaultClient failed to create Vault client: %v", err)
	}

	logger.WithFields(log.Fields{
		"session_id": session.SessionID(),
		"vault_addr": vaultAddress,
	}).Info("Created Vault client for session")

	return newClient, nil
}

// NewSessionHandler initializes a new Vault client for the session
func NewSessionHandler(ctx context.Context, session server.ClientSession, logger *log.Logger) {

	_, err := CreateVaultClientForSession(ctx, session, logger)
	if err != nil {
		logger.WithError(err).Error("NewSessionHandler failed to create Vault client")
		return
	}
}

// EndSessionHandler cleans up the Vault client when the session ends
func EndSessionHandler(_ context.Context, session server.ClientSession, logger *log.Logger) {
	DeleteVaultClient(session.SessionID())
	logger.WithField("session_id", session.SessionID()).Info("Cleaned up Vault client for session")
}
