// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"fmt"
	"net/http"
	"net/textproto"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins []string
	Mode           string // "strict", "development", "disabled"
}

// LoadCORSConfigFromEnv loads CORS configuration from environment variables
func LoadCORSConfigFromEnv() CORSConfig {
	originsStr := os.Getenv("MCP_ALLOWED_ORIGINS")
	mode := os.Getenv("MCP_CORS_MODE")

	// Default to strict mode if not specified
	if mode == "" {
		mode = "strict"
	}

	var origins []string
	if originsStr != "" {
		origins = strings.Split(originsStr, ",")
		// Trim spaces
		for i := range origins {
			origins[i] = strings.TrimSpace(origins[i])
		}
	}

	return CORSConfig{
		AllowedOrigins: origins,
		Mode:           mode,
	}
}

// isOriginAllowed checks if the given origin is allowed based on the configuration
func isOriginAllowed(origin string, allowedOrigins []string, mode string) bool {
	// If mode is disabled, allow all origins
	if mode == "disabled" {
		return true
	}

	// Check if origin is in the allowed list
	for _, allowed := range allowedOrigins {
		if origin == allowed {
			return true
		}
	}

	// In development mode, also allow localhost origins
	if mode == "development" {
		if strings.HasPrefix(origin, "http://localhost:") ||
			strings.HasPrefix(origin, "https://localhost:") ||
			strings.HasPrefix(origin, "http://127.0.0.1:") ||
			strings.HasPrefix(origin, "https://127.0.0.1:") ||
			strings.HasPrefix(origin, "http://[::1]:") ||
			strings.HasPrefix(origin, "https://[::1]:") {
			return true
		}
	}

	return false
}

// securityHandler wraps the StreamableHTTP handler with origin validation
type securityHandler struct {
	handler        http.Handler
	allowedOrigins []string
	corsMode       string
	logger         *log.Logger
}

// NewSecurityHandler creates a new security handler
func NewSecurityHandler(handler http.Handler, allowedOrigins []string, corsMode string, logger *log.Logger) http.Handler {
	return &securityHandler{
		handler:        handler,
		allowedOrigins: allowedOrigins,
		corsMode:       corsMode,
		logger:         logger,
	}
}

// ServeHTTP implements the http.Handler interface
func (h *securityHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Validate Origin header
	origin := r.Header.Get("Origin")
	if origin != "" {
		if !isOriginAllowed(origin, h.allowedOrigins, h.corsMode) {
			h.logger.Warnf("Rejected request from unauthorized origin: %s (CORS mode: %s)", origin, h.corsMode)
			http.Error(w, "Origin not allowed", http.StatusForbidden)
			return
		}

		// Log allowed origins at debug level to avoid too much noise in production
		h.logger.Debugf("Allowed request from origin: %s", origin)

		// If we have a valid origin, add CORS headers
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, VAULT_ADDR, X-Vault-Token, X-Vault-Namespace")
	}

	// Handle OPTIONS requests for CORS preflight
	if r.Method == http.MethodOptions {
		h.logger.Debugf("Handling OPTIONS preflight request from origin: %s", origin)
		w.WriteHeader(http.StatusOK)
		return
	}

	// If origin is valid or not present, delegate to the wrapped handler
	h.handler.ServeHTTP(w, r)
}

// VaultContextMiddleware adds Vault-related header values to the request context.
// Only values the client actually supplied are placed in the context;
// environment-variable fallback happens later in the client package, where it
// can refuse unsafe combinations (e.g. the server's env token paired with a
// client-supplied Vault address).
//
// Security notes:
//   - The Vault token is accepted from headers only, never query parameters
//     (they end up in logs and proxies).
//   - VAULT_ADDR is accepted from headers only. Accepting it from query
//     parameters allowed any local process to redirect the server's Vault
//     traffic via a crafted URL.
//   - VAULT_SKIP_VERIFY is server-side configuration only and is deliberately
//     not read from the request: a client must not be able to disable TLS
//     verification of the server's connection to Vault.
func VaultContextMiddleware(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Reject tokens in query parameters outright.
			if r.URL.Query().Get(VaultToken) != "" || r.URL.Query().Get(VaultHeaderToken) != "" {
				logger.Info(fmt.Sprintf("Vault token was provided in query parameters by client %v, terminating request", r.RemoteAddr))
				http.Error(w, "Vault token should not be provided in query parameters for security reasons, use the X-Vault-Token header", http.StatusBadRequest)
				return
			}

			// Vault address: header only.
			if addr := r.Header.Get(textproto.CanonicalMIMEHeaderKey(VaultAddress)); addr != "" {
				ctx = context.WithValue(ctx, contextKey(VaultAddress), addr)
				logger.Debug("Vault address configured via request header")
			}

			// Vault token: X-Vault-Token (preferred) or VAULT_TOKEN header.
			token := r.Header.Get(textproto.CanonicalMIMEHeaderKey(VaultHeaderToken))
			if token == "" {
				token = r.Header.Get(textproto.CanonicalMIMEHeaderKey(VaultToken))
			}
			if token != "" {
				ctx = context.WithValue(ctx, contextKey(VaultToken), token)
				logger.Debug("Vault token provided via request header")
			}

			// Namespace: X-Vault-Namespace header only.
			if ns := r.Header.Get(textproto.CanonicalMIMEHeaderKey(VaultHeaderNamespace)); ns != "" {
				ctx = context.WithValue(ctx, contextKey(VaultNamespace), ns)
				logger.Debug("Vault namespace configured via request header")
			}

			// Call the next handler with the enriched context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// LoggingMiddleware logs HTTP requests with structured logging
func LoggingMiddleware(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.WithFields(log.Fields{
				"method":     r.Method,
				"path":       r.URL.Path,
				"remote_ip":  r.RemoteAddr,
				"user_agent": r.UserAgent(),
			}).Info("HTTP request received")

			next.ServeHTTP(w, r)
		})
	}
}
