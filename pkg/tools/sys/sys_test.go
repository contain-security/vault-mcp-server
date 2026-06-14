// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package sys

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

func TestCreateMount_AcceptsTransit(t *testing.T) {
	mounted := false

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/sys/mounts":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{},
			})
		case "/v1/sys/mounts/transit":
			var body map[string]interface{}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			require.Equal(t, "transit", body["type"])
			mounted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
	}))
	defer cleanup()

	result, err := createMountHandler(ctx, newRequest(map[string]interface{}{
		"type": "transit",
		"path": "transit",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.True(t, mounted)
	require.Contains(t, getResultText(t, result), "transit")
}

func TestCreateMount_RejectsUnsupportedType(t *testing.T) {
	result, err := createMountHandler(context.Background(), newRequest(map[string]interface{}{
		"type": "nfs",
		"path": "storage",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, getResultText(t, result), "type")
}

func TestTuneMount(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/mounts/secret/tune", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := tuneMountHandler(ctx, newRequest(map[string]interface{}{
		"path":              "secret",
		"default_lease_ttl": "768h",
		"max_lease_ttl":     "8760h",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, "768h", gotBody["default_lease_ttl"])
	require.Equal(t, "8760h", gotBody["max_lease_ttl"])
	require.Contains(t, getResultText(t, result), "secret")
}

func TestTuneMount_RefusesWhenNoFieldsProvided(t *testing.T) {
	result, err := tuneMountHandler(context.Background(), newRequest(map[string]interface{}{
		"path": "secret",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, getResultText(t, result), "At least one")
}

func TestTuneMount_MissingPath(t *testing.T) {
	result, err := tuneMountHandler(context.Background(), newRequest(map[string]interface{}{
		"default_lease_ttl": "768h",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestSealStatus(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/seal-status", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type":         "shamir",
			"initialized":  true,
			"sealed":       false,
			"t":            3,
			"n":            5,
			"progress":     0,
			"version":      "1.17.0",
			"cluster_name": "vault-cluster-test",
		})
	}))
	defer cleanup()

	result, err := sealStatusHandler(ctx, newRequest(nil), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "Sealed: false")
	require.Contains(t, text, "shamir")
	require.Contains(t, text, "Key threshold: 3")
	require.Contains(t, text, "Total key shares: 5")
	require.Contains(t, text, "1.17.0")
	require.Contains(t, text, "vault-cluster-test")
}

func TestHealthStatus(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/health", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"initialized":  true,
			"sealed":       false,
			"standby":      false,
			"version":      "1.17.0",
			"cluster_id":   "c9b29071-test",
			"cluster_name": "vault-cluster-test",
		})
	}))
	defer cleanup()

	result, err := healthStatusHandler(ctx, newRequest(nil), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "Initialized: true")
	require.Contains(t, text, "Sealed: false")
	require.Contains(t, text, "Standby: false")
	require.Contains(t, text, "1.17.0")
	require.Contains(t, text, "c9b29071-test")
	require.Contains(t, text, "vault-cluster-test")
}

func TestTools_Classification(t *testing.T) {
	tools := Tools(newLogger())
	require.Len(t, tools, 6)

	readOnly := map[string]bool{}
	for _, tool := range tools {
		readOnly[tool.Tool.Name] = tool.ReadOnly
	}

	require.True(t, readOnly["list_mounts"])
	require.False(t, readOnly["create_mount"])
	require.False(t, readOnly["delete_mount"])
	require.False(t, readOnly["tune_mount"])
	require.True(t, readOnly["seal_status"])
	require.True(t, readOnly["health_status"])
}
