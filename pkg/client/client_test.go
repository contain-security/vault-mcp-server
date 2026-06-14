// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/mcp"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		fallback string
		expected string
	}{
		{
			name:     "returns fallback when env var not set",
			key:      "NON_EXISTENT_VAR",
			fallback: "default_value",
			expected: "default_value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getEnv(tt.key, tt.fallback)
			if result != tt.expected {
				t.Errorf("getEnv() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNewVaultClient(t *testing.T) {
	// This is a basic test that checks if the function doesn't panic
	// In a real scenario, you'd want to mock the Vault API
	sessionID := "test-session"
	vaultAddress := "http://127.0.0.1:8200"
	vaultToken := "test-token"
	vaultNamespace := "test-namespace"

	client, err := NewVaultClient(sessionID, vaultAddress, false, vaultToken, vaultNamespace)
	if err != nil {
		t.Logf("NewVaultClient() error = %v (expected in test environment)", err)
	}

	if client != nil {
		// Clean up
		DeleteVaultClient(sessionID)
	}
}

// mockClientSession implements server.ClientSession for testing.
type mockClientSession struct {
	id string
}

func (m *mockClientSession) Initialize()                                        {}
func (m *mockClientSession) Initialized() bool                                  { return true }
func (m *mockClientSession) NotificationChannel() chan<- mcp.JSONRPCNotification { return make(chan mcp.JSONRPCNotification, 1) }
func (m *mockClientSession) SessionID() string                                  { return m.id }

func TestCreateVaultClientForSession_SkipTLSVerify(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.WarnLevel)

	newCtx := func(vals map[contextKey]string) context.Context {
		ctx := context.Background()
		for k, v := range vals {
			ctx = context.WithValue(ctx, k, v)
		}
		return ctx
	}

	getTLSSkip := func(t *testing.T, c *api.Client) bool {
		t.Helper()
		httpClient := c.CloneConfig().HttpClient
		tr, ok := httpClient.Transport.(*http.Transport)
		if !ok || tr.TLSClientConfig == nil {
			return false
		}
		return tr.TLSClientConfig.InsecureSkipVerify
	}

	baseCtx := map[contextKey]string{
		contextKey(VaultAddress): "http://127.0.0.1:8200",
		contextKey(VaultToken):   "test-token",
	}

	t.Run("env var fallback when context key absent", func(t *testing.T) {
		t.Setenv(VaultSkipTLSVerify, "true")

		session := &mockClientSession{id: "test-env-fallback"}
		client, err := CreateVaultClientForSession(newCtx(baseCtx), session, logger)
		assert.NoError(t, err)
		assert.True(t, getTLSSkip(t, client), "expected InsecureSkipVerify=true from env fallback")
		DeleteVaultClient(session.id)
	})

	t.Run("client-supplied skip-verify is ignored when env is false", func(t *testing.T) {
		t.Setenv(VaultSkipTLSVerify, "false")

		ctxVals := map[contextKey]string{
			contextKey(VaultAddress):      "http://127.0.0.1:8200",
			contextKey(VaultToken):        "test-token",
			contextKey(VaultSkipTLSVerify): "true",
		}
		session := &mockClientSession{id: "test-ctx-true-env-false"}
		client, err := CreateVaultClientForSession(newCtx(ctxVals), session, logger)
		assert.NoError(t, err)
		assert.False(t, getTLSSkip(t, client), "skip-verify is server-side config only; client context must be ignored")
		DeleteVaultClient(session.id)
	})

	t.Run("client-supplied skip-verify is ignored when env is true", func(t *testing.T) {
		t.Setenv(VaultSkipTLSVerify, "true")

		ctxVals := map[contextKey]string{
			contextKey(VaultAddress):      "http://127.0.0.1:8200",
			contextKey(VaultToken):        "test-token",
			contextKey(VaultSkipTLSVerify): "false",
		}
		session := &mockClientSession{id: "test-ctx-false-env-true"}
		client, err := CreateVaultClientForSession(newCtx(ctxVals), session, logger)
		assert.NoError(t, err)
		assert.True(t, getTLSSkip(t, client), "skip-verify is server-side config only; client context must be ignored")
		DeleteVaultClient(session.id)
	})

	t.Run("defaults to false when neither context nor env set", func(t *testing.T) {
		prevVal, wasSet := os.LookupEnv(VaultSkipTLSVerify)
		os.Unsetenv(VaultSkipTLSVerify)
		t.Cleanup(func() {
			if wasSet {
				os.Setenv(VaultSkipTLSVerify, prevVal)
			}
		})

		session := &mockClientSession{id: "test-default-false"}
		client, err := CreateVaultClientForSession(newCtx(baseCtx), session, logger)
		assert.NoError(t, err)
		assert.False(t, getTLSSkip(t, client), "should default to InsecureSkipVerify=false")
		DeleteVaultClient(session.id)
	})

	t.Run("invalid env value fails client creation", func(t *testing.T) {
		// vault/api's DefaultConfig also parses VAULT_SKIP_VERIFY and refuses
		// an unparseable value — client creation fails closed.
		t.Setenv(VaultSkipTLSVerify, "not-a-bool")

		session := &mockClientSession{id: "test-invalid-env"}
		client, err := CreateVaultClientForSession(newCtx(baseCtx), session, logger)
		assert.Error(t, err, "invalid VAULT_SKIP_VERIFY should fail client creation")
		assert.Nil(t, client)
	})
}

func TestCreateVaultClientForSession_EnvTokenPairing(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	newCtx := func(vals map[contextKey]string) context.Context {
		ctx := context.Background()
		for k, v := range vals {
			ctx = context.WithValue(ctx, k, v)
		}
		return ctx
	}

	t.Run("env token is refused when address is client-supplied", func(t *testing.T) {
		t.Setenv(VaultToken, "operator-env-token")

		ctxVals := map[contextKey]string{
			contextKey(VaultAddress): "http://attacker.example.com:8200",
		}
		session := &mockClientSession{id: "test-env-token-client-addr"}
		client, err := CreateVaultClientForSession(newCtx(ctxVals), session, logger)
		assert.Error(t, err, "the server's env token must never be sent to a client-chosen address")
		assert.Nil(t, client)
	})

	t.Run("client-supplied address with client-supplied token is allowed", func(t *testing.T) {
		t.Setenv(VaultToken, "operator-env-token")

		ctxVals := map[contextKey]string{
			contextKey(VaultAddress): "http://127.0.0.1:8200",
			contextKey(VaultToken):   "session-token",
		}
		session := &mockClientSession{id: "test-client-addr-client-token"}
		client, err := CreateVaultClientForSession(newCtx(ctxVals), session, logger)
		assert.NoError(t, err)
		assert.NotNil(t, client)
		DeleteVaultClient(session.id)
	})

	t.Run("env token with env address is allowed", func(t *testing.T) {
		t.Setenv(VaultToken, "operator-env-token")

		session := &mockClientSession{id: "test-env-token-env-addr"}
		client, err := CreateVaultClientForSession(newCtx(nil), session, logger)
		assert.NoError(t, err)
		assert.NotNil(t, client)
		DeleteVaultClient(session.id)
	})
}

func TestVaultNamespaceSupport(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	t.Run("namespace via header", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			namespace := ctx.Value(contextKey(VaultNamespace))
			assert.Equal(t, "test-namespace", namespace)
			w.WriteHeader(http.StatusOK)
		})

		middleware := VaultContextMiddleware(logger)
		handler := middleware(mockHandler)

		req := httptest.NewRequest("GET", "/mcp", nil)
		req.Header.Set(VaultHeaderNamespace, "test-namespace")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("namespace env var is not injected by middleware", func(t *testing.T) {
		// Env fallback happens at client creation, not in the middleware.
		os.Setenv(VaultNamespace, "env-namespace")
		defer os.Unsetenv(VaultNamespace)

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			namespace := ctx.Value(contextKey(VaultNamespace))
			assert.Nil(t, namespace)
			w.WriteHeader(http.StatusOK)
		})

		middleware := VaultContextMiddleware(logger)
		handler := middleware(mockHandler)

		req := httptest.NewRequest("GET", "/mcp", nil)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("header takes precedence over environment", func(t *testing.T) {
		os.Setenv(VaultNamespace, "env-namespace")
		defer os.Unsetenv(VaultNamespace)

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			namespace := ctx.Value(contextKey(VaultNamespace))
			assert.Equal(t, "header-namespace", namespace)
			w.WriteHeader(http.StatusOK)
		})

		middleware := VaultContextMiddleware(logger)
		handler := middleware(mockHandler)

		req := httptest.NewRequest("GET", "/mcp", nil)
		req.Header.Set(VaultHeaderNamespace, "header-namespace")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}
