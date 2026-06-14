// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

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
	t.Helper()
	mockVault := httptest.NewServer(handler)

	sessionID := "test-" + t.Name()
	_, err := client.NewVaultClient(sessionID, mockVault.URL, false, "test-token", "")
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

func TestListAuthMethods(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/auth", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"token/": map[string]interface{}{
					"type":        "token",
					"description": "token based credentials",
					"accessor":    "auth_token_abc123",
				},
				"userpass/": map[string]interface{}{
					"type":        "userpass",
					"description": "human logins",
					"accessor":    "auth_userpass_def456",
				},
			},
		})
	}))
	defer cleanup()

	result, err := listAuthMethodsHandler(ctx, newRequest(nil), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "userpass/")
	require.Contains(t, text, "token/")
	require.Contains(t, text, "auth_userpass_def456")
	require.Contains(t, text, "human logins")
}

func TestEnableAuthMethod(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/auth/userpass", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := enableAuthMethodHandler(ctx, newRequest(map[string]interface{}{
		"path":        "userpass/",
		"type":        "userpass",
		"description": "human logins",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, "userpass", gotBody["type"])
	require.Equal(t, "human logins", gotBody["description"])
}

func TestEnableAuthMethod_RejectsInvalidType(t *testing.T) {
	result, err := enableAuthMethodHandler(context.Background(), newRequest(map[string]interface{}{
		"path": "evil",
		"type": "plugin-backdoor",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, getResultText(t, result), "Invalid auth method type")
}

func TestEnableAuthMethod_MissingPath(t *testing.T) {
	result, err := enableAuthMethodHandler(context.Background(), newRequest(map[string]interface{}{
		"type": "userpass",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestDisableAuthMethod(t *testing.T) {
	disabled := false

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/auth/old-ldap", r.URL.Path)
		require.Equal(t, http.MethodDelete, r.Method)
		disabled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := disableAuthMethodHandler(ctx, newRequest(map[string]interface{}{"path": "old-ldap"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.True(t, disabled)
}

func TestDisableAuthMethod_RefusesToken(t *testing.T) {
	for _, path := range []string{"token", "token/"} {
		result, err := disableAuthMethodHandler(context.Background(), newRequest(map[string]interface{}{
			"path": path,
		}), newLogger())
		require.NoError(t, err)
		require.True(t, result.IsError, "disabling auth method %q must be refused", path)
		require.Contains(t, getResultText(t, result), "token")
	}
}

func TestTuneAuthMethod(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TuneMount("auth/"+path) hits /v1/sys/mounts/auth/<path>/tune.
		require.Equal(t, "/v1/sys/mounts/auth/userpass/tune", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := tuneAuthMethodHandler(ctx, newRequest(map[string]interface{}{
		"path":              "userpass",
		"default_lease_ttl": "1h",
		"max_lease_ttl":     "24h",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, "1h", gotBody["default_lease_ttl"])
	require.Equal(t, "24h", gotBody["max_lease_ttl"])
}

func TestTuneAuthMethod_RequiresAField(t *testing.T) {
	result, err := tuneAuthMethodHandler(context.Background(), newRequest(map[string]interface{}{
		"path": "userpass",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestListUserpassUsers(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/userpass/users", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{"alice", "bob"},
			},
		})
	}))
	defer cleanup()

	result, err := listUserpassUsersHandler(ctx, newRequest(nil), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "alice")
	require.Contains(t, text, "bob")
}

func TestListUserpassUsers_NoUsers(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vault returns 404 when the list is empty; the client maps that to a nil secret.
		w.WriteHeader(http.StatusNotFound)
	}))
	defer cleanup()

	result, err := listUserpassUsersHandler(ctx, newRequest(map[string]interface{}{"mount": "people/"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Contains(t, getResultText(t, result), "No users found")
}

func TestReadUserpassUser(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/userpass/users/alice", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"token_policies": []string{"app-read"},
				"token_ttl":      3600,
				"token_max_ttl":  86400,
			},
		})
	}))
	defer cleanup()

	result, err := readUserpassUserHandler(ctx, newRequest(map[string]interface{}{"username": "alice"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "app-read")
	require.Contains(t, text, "token_ttl")
}

func TestReadUserpassUser_MissingUsername(t *testing.T) {
	result, err := readUserpassUserHandler(context.Background(), newRequest(map[string]interface{}{}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestWriteUserpassUser(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/userpass/users/alice", r.URL.Path)
		require.Equal(t, http.MethodPut, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := writeUserpassUserHandler(ctx, newRequest(map[string]interface{}{
		"username":       "alice",
		"password":       "s3cret-pass",
		"token_policies": "app-read,app-write",
		"token_ttl":      "1h",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, "s3cret-pass", gotBody["password"])
	require.Equal(t, "app-read,app-write", gotBody["token_policies"])
	require.Equal(t, "1h", gotBody["token_ttl"])
	// The password must never appear in the tool result.
	require.NotContains(t, getResultText(t, result), "s3cret-pass")
}

func TestWriteUserpassUser_RefusesRootPolicy(t *testing.T) {
	for _, policies := range []string{"root", "app-read, ROOT", "app-read,Root,app-write"} {
		result, err := writeUserpassUserHandler(context.Background(), newRequest(map[string]interface{}{
			"username":       "mallory",
			"password":       "pw",
			"token_policies": policies,
		}), newLogger())
		require.NoError(t, err)
		require.True(t, result.IsError, "token_policies %q must be refused", policies)
		require.Contains(t, getResultText(t, result), "root")
	}
}

func TestDeleteUserpassUser(t *testing.T) {
	deleted := false

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/userpass/users/bob", r.URL.Path)
		require.Equal(t, http.MethodDelete, r.Method)
		deleted = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := deleteUserpassUserHandler(ctx, newRequest(map[string]interface{}{"username": "bob"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.True(t, deleted)
}

func TestDeleteUserpassUser_MissingUsername(t *testing.T) {
	result, err := deleteUserpassUserHandler(context.Background(), newRequest(map[string]interface{}{}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestTools_Classification(t *testing.T) {
	tools := Tools(newLogger())
	require.Len(t, tools, 8)

	readOnly := map[string]bool{}
	for _, tool := range tools {
		require.Equal(t, "admin", string(tool.Category))
		readOnly[tool.Tool.Name] = tool.ReadOnly
	}
	require.Len(t, readOnly, 8)

	require.True(t, readOnly["list_auth_methods"])
	require.False(t, readOnly["enable_auth_method"])
	require.False(t, readOnly["disable_auth_method"])
	require.False(t, readOnly["tune_auth_method"])
	require.True(t, readOnly["list_userpass_users"])
	require.True(t, readOnly["read_userpass_user"])
	require.False(t, readOnly["write_userpass_user"])
	require.False(t, readOnly["delete_userpass_user"])
}
