// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package token

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/config"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// fakeSession implements server.ClientSession for testing.
type fakeSession struct {
	id      string
	notifCh chan mcp.JSONRPCNotification
}

func (f fakeSession) Initialize()                                         {}
func (f fakeSession) Initialized() bool                                   { return true }
func (f fakeSession) NotificationChannel() chan<- mcp.JSONRPCNotification { return f.notifCh }
func (f fakeSession) SessionID() string                                   { return f.id }

// newTestContext creates a context wired to a mock Vault HTTP server.
func newTestContext(t *testing.T, handler http.Handler) (context.Context, func()) {
	return newTestContextWithNamespace(t, "", handler)
}

func newTestContextWithNamespace(t *testing.T, namespace string, handler http.Handler) (context.Context, func()) {
	t.Helper()
	mockVault := httptest.NewServer(handler)

	sessionID := "test-" + t.Name()
	_, err := client.NewVaultClient(sessionID, mockVault.URL, false, "test-token", namespace)
	require.NoError(t, err)

	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx := mcpSrv.WithContext(context.Background(), fakeSession{
		id:      sessionID,
		notifCh: make(chan mcp.JSONRPCNotification, 10),
	})

	return ctx, func() {
		mockVault.Close()
		client.DeleteVaultClient(sessionID)
	}
}

func newLogger() *log.Logger {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)
	return logger
}

func newRequest(args map[string]interface{}) mcp.CallToolRequest {
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	return req
}

func getResultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	require.NotNil(t, result)
	require.NotEmpty(t, result.Content)
	tc, ok := mcp.AsTextContent(result.Content[0])
	require.True(t, ok)
	return tc.Text
}

func testConfig() config.Config {
	return config.Config{TokenMaxTTL: 768 * time.Hour}
}

func TestCreateToken_RefusesRootPolicy(t *testing.T) {
	result, err := createTokenHandler(context.Background(), newRequest(map[string]interface{}{
		"policies": "app-read, Root",
		"ttl":      "1h",
	}), newLogger(), testConfig())
	require.NoError(t, err)
	require.True(t, result.IsError, "creating a token with the root policy must be refused")
	require.Contains(t, getResultText(t, result), "root")
}

func TestCreateToken_RefusesEmptyPolicies(t *testing.T) {
	for _, policies := range []string{"", " ", ", ,"} {
		result, err := createTokenHandler(context.Background(), newRequest(map[string]interface{}{
			"policies": policies,
			"ttl":      "1h",
		}), newLogger(), testConfig())
		require.NoError(t, err)
		require.True(t, result.IsError, "policies %q must be refused", policies)
	}
}

func TestCreateToken_RefusesTTLAboveCap(t *testing.T) {
	result, err := createTokenHandler(context.Background(), newRequest(map[string]interface{}{
		"policies": "app-read",
		"ttl":      "769h",
	}), newLogger(), testConfig())
	require.NoError(t, err)
	require.True(t, result.IsError, "ttl above the cap must be refused")
	text := getResultText(t, result)
	require.Contains(t, text, "768h")
	require.Contains(t, text, config.EnvTokenMaxTTL)
}

func TestCreateToken_RefusesInvalidOrMissingTTL(t *testing.T) {
	for _, args := range []map[string]interface{}{
		{"policies": "app-read"},                          // missing
		{"policies": "app-read", "ttl": "not-a-duration"}, // invalid
		{"policies": "app-read", "ttl": "-1h"},            // non-positive
		{"policies": "app-read", "ttl": "0s"},             // non-positive
	} {
		result, err := createTokenHandler(context.Background(), newRequest(args), newLogger(), testConfig())
		require.NoError(t, err)
		require.True(t, result.IsError, "ttl %v must be refused", args["ttl"])
	}
}

func TestCreateToken_RefusesOrphanWhenNotAllowed(t *testing.T) {
	result, err := createTokenHandler(context.Background(), newRequest(map[string]interface{}{
		"policies": "app-read",
		"ttl":      "1h",
		"orphan":   true,
	}), newLogger(), testConfig())
	require.NoError(t, err)
	require.True(t, result.IsError, "orphan token must be refused when AllowOrphanTokens is false")
	require.Contains(t, getResultText(t, result), config.EnvAllowOrphanTokens)
}

func TestCreateToken_RefusesPeriodWhenNotAllowed(t *testing.T) {
	result, err := createTokenHandler(context.Background(), newRequest(map[string]interface{}{
		"policies": "app-read",
		"ttl":      "1h",
		"period":   "24h",
	}), newLogger(), testConfig())
	require.NoError(t, err)
	require.True(t, result.IsError, "periodic token must be refused when AllowOrphanTokens is false")
	require.Contains(t, getResultText(t, result), config.EnvAllowOrphanTokens)
}

func TestCreateToken_AllowsOrphanWhenEnabled(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/token/create-orphan", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token": "hvs.orphan-token",
				"accessor":     "orphan-accessor",
			},
		})
	}))
	defer cleanup()

	cfg := testConfig()
	cfg.AllowOrphanTokens = true

	result, err := createTokenHandler(ctx, newRequest(map[string]interface{}{
		"policies": "app-read",
		"ttl":      "1h",
		"orphan":   true,
	}), newLogger(), cfg)
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Contains(t, getResultText(t, result), "orphan-accessor")
}

func TestCreateToken(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/token/create", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token": "hvs.new-token",
				"accessor":     "new-accessor",
			},
		})
	}))
	defer cleanup()

	result, err := createTokenHandler(ctx, newRequest(map[string]interface{}{
		"policies":     "app-read, metrics",
		"ttl":          "1h",
		"display_name": "test-app",
	}), newLogger(), testConfig())
	require.NoError(t, err)
	require.False(t, result.IsError)

	text := getResultText(t, result)
	require.Contains(t, text, "hvs.new-token")
	require.Contains(t, text, "new-accessor")
	require.Contains(t, text, "WARNING")

	require.Equal(t, []interface{}{"app-read", "metrics"}, gotBody["policies"])
	require.Equal(t, "1h", gotBody["ttl"])
	require.Equal(t, "test-app", gotBody["display_name"])
}

func TestCreateToken_WithWrapTTL(t *testing.T) {
	var gotWrapHeader string

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/token/create", r.URL.Path)
		gotWrapHeader = r.Header.Get("X-Vault-Wrap-TTL")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"wrap_info": map[string]interface{}{
				"token": "hvs.wrapping-token",
				"ttl":   120,
			},
		})
	}))
	defer cleanup()

	result, err := createTokenHandler(ctx, newRequest(map[string]interface{}{
		"policies": "app-read",
		"ttl":      "1h",
		"wrap_ttl": "120s",
	}), newLogger(), testConfig())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, "120s", gotWrapHeader, "the wrap TTL must be sent via the X-Vault-Wrap-TTL header")

	text := getResultText(t, result)
	require.Contains(t, text, "hvs.wrapping-token")
	require.Contains(t, text, "120")
	require.NotContains(t, text, "client_token")
	require.NotContains(t, text, "hvs.new-token")
}

// TestCreateToken_WrapTTLPreservesNamespace guards against the
// response-wrapping clone dropping the session namespace.
func TestCreateToken_WrapTTLPreservesNamespace(t *testing.T) {
	ctx, cleanup := newTestContextWithNamespace(t, "team-a", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "120s", r.Header.Get("X-Vault-Wrap-TTL"))
		require.Equal(t, "team-a", r.Header.Get("X-Vault-Namespace"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"wrap_info": map[string]interface{}{
				"token": "hvs.wrapping-token",
				"ttl":   120,
			},
		})
	}))
	defer cleanup()

	result, err := createTokenHandler(ctx, newRequest(map[string]interface{}{
		"policies": "app-read",
		"ttl":      "1h",
		"wrap_ttl": "120s",
	}), newLogger(), testConfig())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Contains(t, getResultText(t, result), "hvs.wrapping-token")
}

func TestCreateToken_RefusesInvalidWrapTTL(t *testing.T) {
	for _, wrapTTL := range []string{"bogus", "-1m", "2h"} {
		result, err := createTokenHandler(context.Background(), newRequest(map[string]interface{}{
			"policies": "app-read",
			"ttl":      "1h",
			"wrap_ttl": wrapTTL,
		}), newLogger(), testConfig())
		require.NoError(t, err)
		require.True(t, result.IsError, "wrap_ttl %q must be refused", wrapTTL)
	}
}

func TestLookupToken_ViaAccessor(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/token/lookup-accessor", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "some-accessor", body["accessor"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"display_name": "token-test-app",
				"policies":     []string{"default", "app-read"},
				"ttl":          3600,
			},
		})
	}))
	defer cleanup()

	result, err := lookupTokenHandler(ctx, newRequest(map[string]interface{}{
		"accessor": "some-accessor",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)

	text := getResultText(t, result)
	require.Contains(t, text, "token-test-app")
	require.Contains(t, text, "app-read")
}

func TestLookupToken_SelfStripsTokenID(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/token/lookup-self", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id":           "hvs.secret-token-value",
				"display_name": "token-self",
				"policies":     []string{"root"},
			},
		})
	}))
	defer cleanup()

	result, err := lookupTokenHandler(ctx, newRequest(nil), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)

	text := getResultText(t, result)
	require.Contains(t, text, "token-self")
	require.NotContains(t, text, "hvs.secret-token-value", "lookup_token must never reveal the token value")
}

func TestRenewToken_ViaAccessor(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/token/renew-accessor", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "some-accessor", body["accessor"])
		require.Equal(t, float64(3600), body["increment"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token":   "hvs.renewed-token",
				"accessor":       "some-accessor",
				"lease_duration": 3600,
				"renewable":      true,
			},
		})
	}))
	defer cleanup()

	result, err := renewTokenHandler(ctx, newRequest(map[string]interface{}{
		"accessor":  "some-accessor",
		"increment": "1h",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)

	text := getResultText(t, result)
	require.Contains(t, text, "3600")
	require.NotContains(t, text, "hvs.renewed-token", "renew_token must never echo the token value")
}

func TestRenewToken_RefusesInvalidIncrement(t *testing.T) {
	result, err := renewTokenHandler(context.Background(), newRequest(map[string]interface{}{
		"increment": "bogus",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestRevokeToken(t *testing.T) {
	revoked := false

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/token/revoke-accessor", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "some-accessor", body["accessor"])

		revoked = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := revokeTokenHandler(ctx, newRequest(map[string]interface{}{
		"accessor": "some-accessor",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.True(t, revoked)
}

func TestRevokeToken_MissingAccessor(t *testing.T) {
	result, err := revokeTokenHandler(context.Background(), newRequest(map[string]interface{}{}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestListTokenAccessors(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/token/accessors", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "true", r.URL.Query().Get("list"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{"accessor-one", "accessor-two"},
			},
		})
	}))
	defer cleanup()

	result, err := listTokenAccessorsHandler(ctx, newRequest(nil), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)

	text := getResultText(t, result)
	require.Contains(t, text, "accessor-one")
	require.Contains(t, text, "accessor-two")
}

func TestListTokenAccessors_Empty(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{}})
	}))
	defer cleanup()

	result, err := listTokenAccessorsHandler(ctx, newRequest(nil), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Contains(t, getResultText(t, result), "No token accessors found")
}

func TestTools_Classification(t *testing.T) {
	tools := Tools(newLogger(), testConfig())
	require.Len(t, tools, 5)

	readOnly := map[string]bool{}
	for _, tool := range tools {
		readOnly[tool.Tool.Name] = tool.ReadOnly
	}

	require.False(t, readOnly["create_token"])
	require.True(t, readOnly["lookup_token"])
	require.False(t, readOnly["renew_token"])
	require.False(t, readOnly["revoke_token"])
	require.True(t, readOnly["list_token_accessors"])
}
