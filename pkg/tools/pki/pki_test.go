// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package pki

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

const testSerial = "39:dd:2e:90:b7:23:1f:8d:d3:7d:31:c5:1b:da:84:d0:5b:65:31:58"

const testCertPEM = "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIUTEST\n-----END CERTIFICATE-----"

const testCsrPEM = "-----BEGIN CERTIFICATE REQUEST-----\nMIICijCCAXICAQAwTEST\n-----END CERTIFICATE REQUEST-----"

func TestListPkiCertificates(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/pki/certs", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{testSerial, "17:67:16:b0:b9:45:58:c0"},
			},
		})
	}))
	defer cleanup()

	result, err := listPkiCertificatesHandler(ctx, newRequest(map[string]interface{}{
		"mount": "pki",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, testSerial)
	require.Contains(t, text, "17:67:16:b0:b9:45:58:c0")
}

func TestListPkiCertificates_Empty(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{}})
	}))
	defer cleanup()

	result, err := listPkiCertificatesHandler(ctx, newRequest(map[string]interface{}{
		"mount": "pki",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Contains(t, getResultText(t, result), "No certificates found")
}

func TestReadPkiCertificate(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/pki/cert/"+testSerial, r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"certificate":     testCertPEM,
				"revocation_time": 0,
			},
		})
	}))
	defer cleanup()

	result, err := readPkiCertificateHandler(ctx, newRequest(map[string]interface{}{
		"mount":  "pki",
		"serial": testSerial,
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "BEGIN CERTIFICATE")
	require.NotContains(t, text, "revoked")
}

func TestReadPkiCertificate_MissingSerial(t *testing.T) {
	result, err := readPkiCertificateHandler(context.Background(), newRequest(map[string]interface{}{
		"mount": "pki",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, getResultText(t, result), "serial")
}

func TestRevokePkiCertificate(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/pki/revoke", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"revocation_time": 1765000000,
			},
		})
	}))
	defer cleanup()

	result, err := revokePkiCertificateHandler(ctx, newRequest(map[string]interface{}{
		"mount":  "pki",
		"serial": testSerial,
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, testSerial, gotBody["serial_number"])
	text := getResultText(t, result)
	require.Contains(t, text, "Successfully revoked")
	require.Contains(t, text, "CRL")
}

func TestRevokePkiCertificate_MissingSerial(t *testing.T) {
	result, err := revokePkiCertificateHandler(context.Background(), newRequest(map[string]interface{}{
		"mount": "pki",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestGeneratePkiRoot(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/pki/root/generate/internal", r.URL.Path)
		require.Contains(t, []string{http.MethodPost, http.MethodPut}, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"certificate":   testCertPEM,
				"issuer_id":     "f4c8a1aa-test-issuer-id",
				"serial_number": testSerial,
			},
		})
	}))
	defer cleanup()

	result, err := generatePkiRootHandler(ctx, newRequest(map[string]interface{}{
		"mount":       "pki",
		"common_name": "example.com Root CA",
		"issuer_name": "root-2026",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, "example.com Root CA", gotBody["common_name"])
	require.Equal(t, "87600h", gotBody["ttl"])
	require.Equal(t, "root-2026", gotBody["issuer_name"])
	text := getResultText(t, result)
	require.Contains(t, text, "BEGIN CERTIFICATE")
	require.Contains(t, text, "f4c8a1aa-test-issuer-id")
	require.Contains(t, text, testSerial)
}

func TestGeneratePkiRoot_MissingCommonName(t *testing.T) {
	result, err := generatePkiRootHandler(context.Background(), newRequest(map[string]interface{}{
		"mount": "pki",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, getResultText(t, result), "common_name")
}

func TestGeneratePkiIntermediateCsr(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/pki_int/intermediate/generate/internal", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"csr": testCsrPEM,
			},
		})
	}))
	defer cleanup()

	result, err := generatePkiIntermediateCsrHandler(ctx, newRequest(map[string]interface{}{
		"mount":       "pki_int",
		"common_name": "example.com Intermediate CA",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, "example.com Intermediate CA", gotBody["common_name"])
	require.Contains(t, getResultText(t, result), "BEGIN CERTIFICATE REQUEST")
}

func TestSignPkiIntermediate(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/pki/root/sign-intermediate", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"certificate": testCertPEM,
			},
		})
	}))
	defer cleanup()

	result, err := signPkiIntermediateHandler(ctx, newRequest(map[string]interface{}{
		"mount": "pki",
		"csr":   testCsrPEM,
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, testCsrPEM, gotBody["csr"])
	require.Equal(t, "pem_bundle", gotBody["format"])
	require.Equal(t, "43800h", gotBody["ttl"])
	require.Contains(t, getResultText(t, result), "BEGIN CERTIFICATE")
}

func TestSignPkiIntermediate_MissingCsr(t *testing.T) {
	result, err := signPkiIntermediateHandler(context.Background(), newRequest(map[string]interface{}{
		"mount": "pki",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, getResultText(t, result), "csr")
}

func TestSetPkiSignedIntermediate(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/pki_int/intermediate/set-signed", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := setPkiSignedIntermediateHandler(ctx, newRequest(map[string]interface{}{
		"mount":       "pki_int",
		"certificate": testCertPEM,
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, testCertPEM, gotBody["certificate"])
	require.Contains(t, getResultText(t, result), "Successfully installed")
}

func TestSetPkiSignedIntermediate_MissingCertificate(t *testing.T) {
	result, err := setPkiSignedIntermediateHandler(context.Background(), newRequest(map[string]interface{}{
		"mount": "pki_int",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestTools_Classification(t *testing.T) {
	tools := Tools(newLogger())
	require.Len(t, tools, 16)

	readOnly := map[string]bool{}
	for _, tool := range tools {
		readOnly[tool.Tool.Name] = tool.ReadOnly
	}
	require.Len(t, readOnly, 16, "tool names must be unique")

	// Read-only tools.
	require.True(t, readOnly["list_pki_issuers"])
	require.True(t, readOnly["read_pki_issuer"])
	require.True(t, readOnly["list_pki_roles"])
	require.True(t, readOnly["read_pki_role"])
	require.True(t, readOnly["list_pki_certificates"])
	require.True(t, readOnly["read_pki_certificate"])

	// Mutating tools, including everything that mints key material.
	require.False(t, readOnly["enable_pki"])
	require.False(t, readOnly["create_pki_issuer"])
	require.False(t, readOnly["create_pki_role"])
	require.False(t, readOnly["delete_pki_role"])
	require.False(t, readOnly["issue_pki_certificate"])
	require.False(t, readOnly["revoke_pki_certificate"])
	require.False(t, readOnly["generate_pki_root"])
	require.False(t, readOnly["generate_pki_intermediate_csr"])
	require.False(t, readOnly["sign_pki_intermediate"])
	require.False(t, readOnly["set_pki_signed_intermediate"])
}
