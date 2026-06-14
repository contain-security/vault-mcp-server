// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package lease

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/registry"
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

func TestLookupLease(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/leases/lookup", r.URL.Path)
		require.Equal(t, http.MethodPut, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id":          "auth/approle/login/abc123",
				"issue_time":  "2026-06-12T10:00:00Z",
				"expire_time": "2026-06-12T11:00:00Z",
				"ttl":         3142,
				"renewable":   true,
			},
		})
	}))
	defer cleanup()

	result, err := lookupLeaseHandler(ctx, newRequest(map[string]interface{}{
		"lease_id": "auth/approle/login/abc123",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, "auth/approle/login/abc123", gotBody["lease_id"])
	text := getResultText(t, result)
	require.Contains(t, text, "2026-06-12T10:00:00Z")
	require.Contains(t, text, "2026-06-12T11:00:00Z")
	require.Contains(t, text, "3142")
	require.Contains(t, text, "true")
}

func TestLookupLease_MissingLeaseID(t *testing.T) {
	result, err := lookupLeaseHandler(context.Background(), newRequest(map[string]interface{}{}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestListLeases(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Logical().List sends LIST requests as GET with ?list=true.
		require.Equal(t, "/v1/sys/leases/lookup/auth/approle/login", r.URL.Path)
		require.Equal(t, "true", r.URL.Query().Get("list"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{"abc123", "def456"},
			},
		})
	}))
	defer cleanup()

	result, err := listLeasesHandler(ctx, newRequest(map[string]interface{}{
		"prefix": "auth/approle/login",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "abc123")
	require.Contains(t, text, "def456")
}

func TestListLeases_NoneFound(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{}})
	}))
	defer cleanup()

	result, err := listLeasesHandler(ctx, newRequest(map[string]interface{}{
		"prefix": "pki/issue/example-dot-com",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Contains(t, getResultText(t, result), "No leases found")
}

func TestListLeases_MissingPrefix(t *testing.T) {
	result, err := listLeasesHandler(context.Background(), newRequest(map[string]interface{}{}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestRevokeLease(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/leases/revoke", r.URL.Path)
		require.Equal(t, http.MethodPut, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := revokeLeaseHandler(ctx, newRequest(map[string]interface{}{
		"lease_id": "auth/approle/login/abc123",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, "auth/approle/login/abc123", gotBody["lease_id"])
}

func TestRevokeLease_RefusesPrefixes(t *testing.T) {
	for _, leaseID := range []string{"auth/approle/login/", "pki"} {
		result, err := revokeLeaseHandler(context.Background(), newRequest(map[string]interface{}{
			"lease_id": leaseID,
		}), newLogger())
		require.NoError(t, err)
		require.True(t, result.IsError, "revoking lease ID %q must be refused", leaseID)
		require.Contains(t, getResultText(t, result), "Refusing to revoke")
	}
}

func TestRevokeLease_MissingLeaseID(t *testing.T) {
	result, err := revokeLeaseHandler(context.Background(), newRequest(map[string]interface{}{}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestTools_Classification(t *testing.T) {
	tools := Tools(newLogger())
	require.Len(t, tools, 3)

	readOnly := map[string]bool{}
	for _, tool := range tools {
		readOnly[tool.Tool.Name] = tool.ReadOnly
		require.Equal(t, registry.CategoryAdmin, tool.Category, "tool %q must be in the admin category", tool.Tool.Name)
	}

	require.True(t, readOnly["lookup_lease"])
	require.True(t, readOnly["list_leases"])
	require.False(t, readOnly["revoke_lease"])
}
