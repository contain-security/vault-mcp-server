// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package policy

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

func TestListPolicies(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/policies/acl", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{"default", "app-read", "root"},
			},
		})
	}))
	defer cleanup()

	result, err := listPoliciesHandler(ctx, newRequest(nil), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "app-read")
	require.Contains(t, text, "default")
}

func TestReadPolicy(t *testing.T) {
	const policyHCL = `path "apps/data/web/*" { capabilities = ["read"] }`

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/policies/acl/app-read", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"name":   "app-read",
				"policy": policyHCL,
			},
		})
	}))
	defer cleanup()

	result, err := readPolicyHandler(ctx, newRequest(map[string]interface{}{"name": "app-read"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Contains(t, getResultText(t, result), "apps/data/web/*")
}

func TestReadPolicy_MissingName(t *testing.T) {
	result, err := readPolicyHandler(context.Background(), newRequest(map[string]interface{}{}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestWritePolicy(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/policies/acl/app-write", r.URL.Path)
		require.Equal(t, http.MethodPut, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := writePolicyHandler(ctx, newRequest(map[string]interface{}{
		"name":   "app-write",
		"policy": `path "apps/data/web/*" { capabilities = ["create", "update"] }`,
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Contains(t, gotBody["policy"], "apps/data/web/*")
}

func TestWritePolicy_RefusesProtectedPolicies(t *testing.T) {
	// Vault normalizes policy names to lowercase, so the guard must catch
	// case and whitespace variants too — otherwise "Default" rewrites the
	// built-in default policy attached to every token.
	for _, name := range []string{"root", "default", "Default", "ROOT", " root ", "Root"} {
		result, err := writePolicyHandler(context.Background(), newRequest(map[string]interface{}{
			"name":   name,
			"policy": `path "*" { capabilities = ["sudo"] }`,
		}), newLogger())
		require.NoError(t, err)
		require.True(t, result.IsError, "writing policy %q must be refused", name)
	}
}

func TestDeletePolicy(t *testing.T) {
	deleted := false

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/policies/acl/app-read", r.URL.Path)
		require.Equal(t, http.MethodDelete, r.Method)
		deleted = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := deletePolicyHandler(ctx, newRequest(map[string]interface{}{"name": "app-read"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.True(t, deleted)
}

func TestDeletePolicy_RefusesProtectedPolicies(t *testing.T) {
	for _, name := range []string{"root", "default", "Default", "ROOT", " default "} {
		result, err := deletePolicyHandler(context.Background(), newRequest(map[string]interface{}{
			"name": name,
		}), newLogger())
		require.NoError(t, err)
		require.True(t, result.IsError, "deleting policy %q must be refused", name)
	}
}

func TestTools_Classification(t *testing.T) {
	tools := Tools(newLogger())
	require.Len(t, tools, 4)

	readOnly := map[string]bool{}
	for _, tool := range tools {
		readOnly[tool.Tool.Name] = tool.ReadOnly
	}

	require.True(t, readOnly["list_policies"])
	require.True(t, readOnly["read_policy"])
	require.False(t, readOnly["write_policy"])
	require.False(t, readOnly["delete_policy"])
}
