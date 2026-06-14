// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package audit

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

func TestListAuditDevices(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/audit", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"file/": map[string]interface{}{
					"type":        "file",
					"description": "main audit log",
					"options": map[string]string{
						"file_path": "/var/log/vault_audit.log",
					},
				},
			},
		})
	}))
	defer cleanup()

	result, err := listAuditDevicesHandler(ctx, newRequest(nil), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "file/")
	require.Contains(t, text, "main audit log")
	require.Contains(t, text, "/var/log/vault_audit.log")
}

func TestEnableAuditDevice(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/audit/file", r.URL.Path)
		require.Equal(t, http.MethodPut, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := enableAuditDeviceHandler(ctx, newRequest(map[string]interface{}{
		"path":        "file",
		"type":        "file",
		"description": "main audit log",
		"options": map[string]interface{}{
			"file_path": "/var/log/vault_audit.log",
		},
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, "file", gotBody["type"])
	options, ok := gotBody["options"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "/var/log/vault_audit.log", options["file_path"])
}

func TestEnableAuditDevice_MissingFilePath(t *testing.T) {
	result, err := enableAuditDeviceHandler(context.Background(), newRequest(map[string]interface{}{
		"path": "file",
		"type": "file",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, getResultText(t, result), "file_path")
}

func TestEnableAuditDevice_InvalidType(t *testing.T) {
	result, err := enableAuditDeviceHandler(context.Background(), newRequest(map[string]interface{}{
		"path": "db-audit",
		"type": "database",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestEnableAuditDevice_MissingPath(t *testing.T) {
	result, err := enableAuditDeviceHandler(context.Background(), newRequest(map[string]interface{}{
		"type": "syslog",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestDisableAuditDevice(t *testing.T) {
	disabled := false

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/audit/file", r.URL.Path)
		require.Equal(t, http.MethodDelete, r.Method)
		disabled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := disableAuditDeviceHandler(ctx, newRequest(map[string]interface{}{"path": "file"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.True(t, disabled)
}

func TestDisableAuditDevice_MissingPath(t *testing.T) {
	result, err := disableAuditDeviceHandler(context.Background(), newRequest(map[string]interface{}{}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestTools_Classification(t *testing.T) {
	tools := Tools(newLogger())
	require.Len(t, tools, 3)

	readOnly := map[string]bool{}
	for _, tool := range tools {
		readOnly[tool.Tool.Name] = tool.ReadOnly
		require.Equal(t, registry.CategoryAudit, tool.Category, "tool %q must be in the audit category", tool.Tool.Name)
	}

	require.True(t, readOnly["list_audit_devices"])
	require.False(t, readOnly["enable_audit_device"])
	require.False(t, readOnly["disable_audit_device"])
}
