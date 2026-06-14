// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package ssh

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

func TestConfigureSshCa_Generate(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/ssh-client-ca/config/ca", r.URL.Path)
		require.Equal(t, http.MethodPut, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"public_key": "ssh-rsa AAAAB3-test-ca"},
		})
	}))
	defer cleanup()

	result, err := configureSshCaHandler(ctx, newRequest(map[string]interface{}{
		"mount": "ssh-client-ca",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, true, gotBody["generate_signing_key"])
	require.Contains(t, getResultText(t, result), "ssh-rsa AAAAB3-test-ca")
}

func TestConfigureSshCa_ProvidedKeysRequireBoth(t *testing.T) {
	result, err := configureSshCaHandler(context.Background(), newRequest(map[string]interface{}{
		"mount":                "ssh-client-ca",
		"generate_signing_key": false,
		"public_key":           "ssh-rsa AAAA",
		// private_key omitted
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestReadSshCa(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/ssh-client-ca/config/ca", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"public_key": "ssh-rsa AAAAB3-test-ca"},
		})
	}))
	defer cleanup()

	result, err := readSshCaHandler(ctx, newRequest(map[string]interface{}{"mount": "ssh-client-ca"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Contains(t, getResultText(t, result), "ssh-rsa AAAAB3-test-ca")
}

func TestCreateSshRole_User(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/ssh-client-ca/roles/clients", r.URL.Path)
		require.Equal(t, http.MethodPut, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := createSshRoleHandler(ctx, newRequest(map[string]interface{}{
		"mount":              "ssh-client-ca",
		"name":               "clients",
		"cert_type":          "user",
		"allowed_users":      "*",
		"default_extensions": "permit-pty,permit-port-forwarding",
		"ttl":                "30m",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, "ca", gotBody["key_type"])
	require.Equal(t, "user", gotBody["cert_type"])
	require.Equal(t, true, gotBody["allow_user_certificates"])
	require.Equal(t, "*", gotBody["allowed_users"])
	require.Equal(t, "30m", gotBody["ttl"])
	// default_extensions must be sent as a map (Vault rejects a string here),
	// converted from the comma-separated convenience input.
	require.Equal(t, map[string]interface{}{
		"permit-pty":             "",
		"permit-port-forwarding": "",
	}, gotBody["default_extensions"])
}

func TestCreateSshRole_Host(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := createSshRoleHandler(ctx, newRequest(map[string]interface{}{
		"mount":           "ssh-client-ca",
		"name":            "hosts",
		"cert_type":       "host",
		"allowed_domains": "example.com",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, true, gotBody["allow_host_certificates"])
	require.Equal(t, "host", gotBody["cert_type"])
}

func TestCreateSshRole_InvalidCertType(t *testing.T) {
	result, err := createSshRoleHandler(context.Background(), newRequest(map[string]interface{}{
		"mount":     "ssh-client-ca",
		"name":      "bad",
		"cert_type": "bogus",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestCreateSshRole_MissingName(t *testing.T) {
	result, err := createSshRoleHandler(context.Background(), newRequest(map[string]interface{}{
		"mount": "ssh-client-ca",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestListSshRoles(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/ssh-client-ca/roles", r.URL.Path)
		require.Equal(t, "true", r.URL.Query().Get("list"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"keys": []string{"clients", "hosts"}},
		})
	}))
	defer cleanup()

	result, err := listSshRolesHandler(ctx, newRequest(map[string]interface{}{"mount": "ssh-client-ca"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "clients")
	require.Contains(t, text, "hosts")
}

func TestListSshRoles_Empty(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer cleanup()

	result, err := listSshRolesHandler(ctx, newRequest(map[string]interface{}{"mount": "ssh-client-ca"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Contains(t, getResultText(t, result), "No roles found")
}

func TestSignSshKey(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/ssh-client-ca/sign/clients", r.URL.Path)
		require.Equal(t, http.MethodPut, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"signed_key":    "ssh-rsa-cert-v01@openssh.com AAAA-signed-cert",
				"serial_number": "abc123",
			},
		})
	}))
	defer cleanup()

	result, err := signSshKeyHandler(ctx, newRequest(map[string]interface{}{
		"mount":            "ssh-client-ca",
		"role":             "clients",
		"public_key":       "ssh-ed25519 AAAAC3-user-key",
		"valid_principals": "ubuntu",
		"ttl":              "30m",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, "ssh-ed25519 AAAAC3-user-key", gotBody["public_key"])
	require.Equal(t, "ubuntu", gotBody["valid_principals"])
	require.Contains(t, getResultText(t, result), "AAAA-signed-cert")
}

func TestSignSshKey_MissingPublicKey(t *testing.T) {
	result, err := signSshKeyHandler(context.Background(), newRequest(map[string]interface{}{
		"mount": "ssh-client-ca",
		"role":  "clients",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestDeleteSshRole(t *testing.T) {
	deleted := false
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/ssh-client-ca/roles/clients", r.URL.Path)
		require.Equal(t, http.MethodDelete, r.Method)
		deleted = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := deleteSshRoleHandler(ctx, newRequest(map[string]interface{}{
		"mount": "ssh-client-ca",
		"name":  "clients",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.True(t, deleted)
}

func TestTools_Classification(t *testing.T) {
	tools := Tools(newLogger())
	require.Len(t, tools, 8)

	readOnly := map[string]bool{}
	for _, tool := range tools {
		readOnly[tool.Tool.Name] = tool.ReadOnly
	}

	require.True(t, readOnly["read_ssh_ca"])
	require.True(t, readOnly["read_ssh_role"])
	require.True(t, readOnly["list_ssh_roles"])
	require.False(t, readOnly["configure_ssh_ca"])
	require.False(t, readOnly["delete_ssh_ca"])
	require.False(t, readOnly["create_ssh_role"])
	require.False(t, readOnly["delete_ssh_role"])
	require.False(t, readOnly["sign_ssh_key"], "sign_ssh_key mints a credential and must not be read-only")
}
