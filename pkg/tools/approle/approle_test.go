// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package approle

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
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

// newTestContextWithNamespace is like newTestContext but configures the
// session's Vault client with a namespace, used to verify the namespace
// survives the response-wrapping client clone.
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

func TestListRoles(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/approle/role", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "true", r.URL.Query().Get("list"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{"web-app", "batch-job"},
			},
		})
	}))
	defer cleanup()

	result, err := listRolesHandler(ctx, newRequest(nil), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "web-app")
	require.Contains(t, text, "batch-job")
}

func TestListRoles_Empty(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{}})
	}))
	defer cleanup()

	result, err := listRolesHandler(ctx, newRequest(nil), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Contains(t, getResultText(t, result), "No AppRole roles found")
}

func TestReadRole(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/approle/role/web-app", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"token_policies":     []string{"app-read"},
				"token_ttl":          3600,
				"token_max_ttl":      14400,
				"secret_id_ttl":      86400,
				"secret_id_num_uses": 1,
				"token_num_uses":     0,
			},
		})
	}))
	defer cleanup()

	result, err := readRoleHandler(ctx, newRequest(map[string]interface{}{"name": "web-app"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "app-read")
	require.Contains(t, text, "token_ttl")
	require.Contains(t, text, "secret_id_num_uses")
}

func TestReadRole_MissingName(t *testing.T) {
	result, err := readRoleHandler(context.Background(), newRequest(map[string]interface{}{}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestWriteRole(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/approle/role/web-app", r.URL.Path)
		require.Equal(t, http.MethodPut, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := writeRoleHandler(ctx, newRequest(map[string]interface{}{
		"name":               "web-app",
		"token_policies":     "app-read, app-write",
		"token_ttl":          "1h",
		"token_max_ttl":      "4h",
		"secret_id_ttl":      "24h",
		"secret_id_num_uses": float64(1),
		"token_num_uses":     float64(0),
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)

	policies, ok := gotBody["token_policies"].([]interface{})
	require.True(t, ok)
	require.ElementsMatch(t, []interface{}{"app-read", "app-write"}, policies)
	require.Equal(t, "1h", gotBody["token_ttl"])
	require.Equal(t, "4h", gotBody["token_max_ttl"])
	require.Equal(t, "24h", gotBody["secret_id_ttl"])
	require.Equal(t, float64(1), gotBody["secret_id_num_uses"])
	require.Equal(t, float64(0), gotBody["token_num_uses"])
}

func TestWriteRole_RefusesRootPolicy(t *testing.T) {
	for _, policies := range []string{"root", "app-read,root", "app-read, ROOT ", "Root"} {
		result, err := writeRoleHandler(context.Background(), newRequest(map[string]interface{}{
			"name":           "evil",
			"token_policies": policies,
		}), newLogger())
		require.NoError(t, err)
		require.True(t, result.IsError, "token_policies %q must be refused", policies)
	}
}

func TestWriteRole_MissingName(t *testing.T) {
	result, err := writeRoleHandler(context.Background(), newRequest(map[string]interface{}{
		"token_policies": "app-read",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestDeleteRole(t *testing.T) {
	deleted := false

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/approle/role/web-app", r.URL.Path)
		require.Equal(t, http.MethodDelete, r.Method)
		deleted = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := deleteRoleHandler(ctx, newRequest(map[string]interface{}{"name": "web-app"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.True(t, deleted)
}

func TestReadRoleID(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/approle/role/web-app/role-id", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"role_id": "fake-role-id",
			},
		})
	}))
	defer cleanup()

	result, err := readRoleIDHandler(ctx, newRequest(map[string]interface{}{"name": "web-app"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Contains(t, getResultText(t, result), "fake-role-id")
}

func TestGenerateSecretID_Unwrapped(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/approle/role/web-app/secret-id", r.URL.Path)
		require.Equal(t, http.MethodPut, r.Method)
		require.Empty(t, r.Header.Get("X-Vault-Wrap-TTL"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"secret_id":          "fake-sid-value",
				"secret_id_accessor": "fake-accessor",
			},
		})
	}))
	defer cleanup()

	result, err := generateSecretIDHandler(ctx, newRequest(map[string]interface{}{"name": "web-app"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "fake-sid-value")
	require.Contains(t, text, "fake-accessor")
	require.Contains(t, text, "WARNING")
	require.Contains(t, text, "conversation context")
}

func TestGenerateSecretID_Wrapped(t *testing.T) {
	const wrapToken = "fake-wrap-token"

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/approle/role/web-app/secret-id", r.URL.Path)
		require.Equal(t, http.MethodPut, r.Method)
		require.Equal(t, "120s", r.Header.Get("X-Vault-Wrap-TTL"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"wrap_info": map[string]interface{}{
				"token":         wrapToken,
				"ttl":           120,
				"creation_time": "2026-06-12T00:00:00Z",
				"creation_path": "auth/approle/role/web-app/secret-id",
			},
		})
	}))
	defer cleanup()

	result, err := generateSecretIDHandler(ctx, newRequest(map[string]interface{}{
		"name":     "web-app",
		"wrap_ttl": "120s",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, wrapToken)
	require.Contains(t, text, "vault unwrap")
	require.Contains(t, text, "120")
	require.NotContains(t, text, "secret_id")
}

// TestGenerateSecretID_WrappedPreservesNamespace guards against the
// response-wrapping clone dropping the session namespace (the namespace is
// carried as the X-Vault-Namespace header, which Clone() does not copy).
func TestGenerateSecretID_WrappedPreservesNamespace(t *testing.T) {
	const wrapToken = "fake-wrap-token"

	ctx, cleanup := newTestContextWithNamespace(t, "team-a", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "120s", r.Header.Get("X-Vault-Wrap-TTL"))
		require.Equal(t, "team-a", r.Header.Get("X-Vault-Namespace"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"wrap_info": map[string]interface{}{
				"token": wrapToken,
				"ttl":   120,
			},
		})
	}))
	defer cleanup()

	result, err := generateSecretIDHandler(ctx, newRequest(map[string]interface{}{
		"name":     "web-app",
		"wrap_ttl": "120s",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Contains(t, getResultText(t, result), wrapToken)
}

func TestGenerateSecretID_InvalidWrapTTL(t *testing.T) {
	for _, wrapTTL := range []string{"not-a-duration", "-30s", "0s", "2h"} {
		result, err := generateSecretIDHandler(context.Background(), newRequest(map[string]interface{}{
			"name":     "web-app",
			"wrap_ttl": wrapTTL,
		}), newLogger())
		require.NoError(t, err)
		require.True(t, result.IsError, "wrap_ttl %q must be rejected", wrapTTL)
	}
}

func TestGenerateSecretID_MissingName(t *testing.T) {
	result, err := generateSecretIDHandler(context.Background(), newRequest(map[string]interface{}{}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestListSecretIDAccessors(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/approle/role/web-app/secret-id", r.URL.Path)
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

	result, err := listSecretIDAccessorsHandler(ctx, newRequest(map[string]interface{}{"name": "web-app"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "accessor-one")
	require.Contains(t, text, "accessor-two")
}

func TestDestroySecretID(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/approle/role/web-app/secret-id-accessor/destroy", r.URL.Path)
		require.Equal(t, http.MethodPut, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := destroySecretIDHandler(ctx, newRequest(map[string]interface{}{
		"name":               "web-app",
		"secret_id_accessor": "fake-accessor",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, "fake-accessor", gotBody["secret_id_accessor"])
}

func TestDestroySecretID_MissingAccessor(t *testing.T) {
	result, err := destroySecretIDHandler(context.Background(), newRequest(map[string]interface{}{
		"name": "web-app",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestTools_Classification(t *testing.T) {
	tools := Tools(newLogger())
	require.Len(t, tools, 8)

	readOnly := map[string]bool{}
	for _, tool := range tools {
		readOnly[tool.Tool.Name] = tool.ReadOnly
	}

	require.True(t, readOnly["list_approle_roles"])
	require.True(t, readOnly["read_approle_role"])
	require.False(t, readOnly["write_approle_role"])
	require.False(t, readOnly["delete_approle_role"])
	require.False(t, readOnly["read_approle_role_id"])
	require.False(t, readOnly["generate_approle_secret_id"])
	require.True(t, readOnly["list_approle_secret_id_accessors"])
	require.False(t, readOnly["destroy_approle_secret_id"])
}
