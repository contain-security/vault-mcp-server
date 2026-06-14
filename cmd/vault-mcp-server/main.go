// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/config"
	"github.com/hashicorp/vault-mcp-server/pkg/prompts"
	"github.com/hashicorp/vault-mcp-server/pkg/tools"

	"github.com/hashicorp/vault-mcp-server/version"

	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	DefaultBindAddress  = "127.0.0.1"
	DefaultBindPort     = "8080"
	DefaultEndPointPath = "/mcp"
)

var (
	rootCmd = &cobra.Command{
		Use:     "vault-mcp-server",
		Short:   "Vault MCP Server",
		Long:    `A Vault MCP server that handles various tools and resources for HashiCorp Vault.`,
		Version: fmt.Sprintf("Version: %s\nCommit: %s\nBuild Date: %s", version.GetHumanVersion(), version.GitCommit, version.BuildDate),
		Run:     runDefaultCommand,
	}

	stdioCmd = &cobra.Command{
		Use:   "stdio",
		Short: "Start stdio server",
		Long:  `Start a server that communicates via standard input/output streams using JSON-RPC messages.`,
		Run: func(_ *cobra.Command, _ []string) {
			logFile, err := rootCmd.PersistentFlags().GetString("log-file")
			if err != nil {
				stdlog.Fatal("Failed to get log file:", err)
			}
			logger, err := initLogger(logFile)
			if err != nil {
				stdlog.Fatal("Failed to initialize logger:", err)
			}

			if err := runStdioServer(logger); err != nil {
				stdlog.Fatal("failed to run stdio server:", err)
			}
		},
	}

	streamableHTTPCmd = &cobra.Command{
		Use:   "streamable-http",
		Short: "Start StreamableHTTP server",
		Long: `Start a server that communicates using the StreamableHTTP transport.
This mode allows clients to interact with the Vault MCP server over HTTP.
You can specify the host, port, and endpoint path to customize where the server listens.`,
		Run: func(cmd *cobra.Command, _ []string) {
			logFile, err := rootCmd.PersistentFlags().GetString("log-file")
			if err != nil {
				stdlog.Fatal("Failed to get log file:", err)
			}
			logger, err := initLogger(logFile)
			if err != nil {
				stdlog.Fatal("Failed to initialize logger:", err)
			}

			port, err := cmd.Flags().GetString("transport-port")
			if err != nil {
				stdlog.Fatal("Failed to get streamableHTTP port:", err)
			}
			host, err := cmd.Flags().GetString("transport-host")
			if err != nil {
				stdlog.Fatal("Failed to get streamableHTTP host:", err)
			}

			endpointPath, err := cmd.Flags().GetString("mcp-endpoint")
			if err != nil {
				stdlog.Fatal("Failed to get endpoint path:", err)
			}

			if err := runHTTPServer(logger, host, port, endpointPath); err != nil {
				stdlog.Fatal("failed to run streamableHTTP server:", err)
			}
		},
	}

	// Create an alias for backward compatibility
	httpCmdAlias = &cobra.Command{
		Use:        "http",
		Short:      "Start StreamableHTTP server (deprecated, use 'streamable-http' instead)",
		Long:       `This command is deprecated. Please use 'streamable-http' instead.`,
		Deprecated: "Use 'streamable-http' instead",
		Run: func(cmd *cobra.Command, args []string) {
			// Forward to the new command
			streamableHTTPCmd.Run(cmd, args)
		},
	}
)

// securityFlags is set in init() to the root command's persistent flag set.
// It is accessed via this variable (rather than rootCmd directly) to avoid a
// package initialization cycle: rootCmd's initializer references the run
// functions, which call loadServerConfig.
var securityFlags *pflag.FlagSet

// loadServerConfig builds the security configuration from the environment
// and CLI flags (either source can enable a gate). Invalid configuration is
// a fatal startup error — the server fails closed rather than guessing.
func loadServerConfig(logger *log.Logger) (config.Config, error) {
	cfg, err := config.FromEnv()
	if err != nil {
		return config.Config{}, err
	}

	if securityFlags != nil {
		if v, err := securityFlags.GetBool("read-only"); err == nil && v {
			cfg.ReadOnly = true
		}
		if v, err := securityFlags.GetBool("admin-tools"); err == nil && v {
			cfg.AdminTools = true
		}
		if v, err := securityFlags.GetBool("audit-tools"); err == nil && v {
			cfg.AuditTools = true
		}
	}

	logger.WithFields(log.Fields{
		"read_only":   cfg.ReadOnly,
		"admin_tools": cfg.AdminTools,
		"audit_tools": cfg.AuditTools,
	}).Info("Loaded server security configuration")

	if cfg.ReadOnly {
		logger.Info("Read-only mode is ON: mutating and credential-minting tools are disabled")
	}

	return cfg, nil
}

func runHTTPServer(logger *log.Logger, host string, port string, endpointPath string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := loadServerConfig(logger)
	if err != nil {
		return fmt.Errorf("invalid server configuration: %w", err)
	}

	hcServer := NewServer(version.Version, logger, cfg)
	tools.InitTools(hcServer, logger, cfg)
	prompts.InitPrompts(hcServer, logger, cfg)

	return httpServerInit(ctx, hcServer, logger, host, port, endpointPath)
}

func httpServerInit(ctx context.Context, hcServer *server.MCPServer, logger *log.Logger, host string, port string, endpointPath string) error {
	// Ensure endpoint path starts with /
	endpointPath = path.Join("/", endpointPath)
	// Create StreamableHTTP server which implements the new streamable-http transport
	// This is the modern MCP transport that supports both direct HTTP responses and SSE streams
	opts := []server.StreamableHTTPOption{
		server.WithEndpointPath(endpointPath),
		server.WithLogger(logger),
	}

	// Load TLS configuration
	tlsConfig, err := client.GetTLSConfigFromEnv()
	if err != nil {
		return fmt.Errorf("TLS configuration error: %w", err)
	}
	if tlsConfig != nil {
		opts = append(opts, server.WithTLSCert(tlsConfig.CertFile, tlsConfig.KeyFile))
	}

	// Log the endpoint path being used
	logger.Infof("Using endpoint path: %s", endpointPath)

	// Create StreamableHTTP server which implements the new streamable-http transport
	// This is the modern MCP transport that supports both direct HTTP responses and SSE streams
	baseStreamableServer := server.NewStreamableHTTPServer(hcServer, opts...)

	// Load CORS configuration
	corsConfig := client.LoadCORSConfigFromEnv()

	// Log CORS configuration
	logger.Infof("CORS Mode: %s", corsConfig.Mode)
	if len(corsConfig.AllowedOrigins) > 0 {
		logger.Infof("Allowed Origins: %s", strings.Join(corsConfig.AllowedOrigins, ", "))
	} else if corsConfig.Mode == "strict" {
		logger.Warnf("No allowed origins configured in strict mode. All cross-origin requests will be rejected.")
	} else if corsConfig.Mode == "development" {
		logger.Infof("Development mode: localhost origins are automatically allowed")
	} else if corsConfig.Mode == "disabled" {
		logger.Warnf("CORS validation is disabled. This is not recommended for production.")
	}

	// Create a security wrapper around the streamable server
	streamableServer := client.NewSecurityHandler(baseStreamableServer, corsConfig.AllowedOrigins, corsConfig.Mode, logger)

	mux := http.NewServeMux()

	// Apply middleware
	streamableServer = client.VaultContextMiddleware(logger)(streamableServer)
	streamableServer = client.LoggingMiddleware(logger)(streamableServer)

	// Handle the /mcp endpoint with the streamable server (with security wrapper)
	mux.Handle(endpointPath, streamableServer)
	mux.Handle(endpointPath+"/", streamableServer)

	// Add health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := fmt.Sprintf(`{"status":"ok","service":"vault-mcp-server","transport":"streamable-http","endpoint":"%s"}`, endpointPath)
		if _, err := w.Write([]byte(response)); err != nil {
			logger.WithError(err).Error("Failed to write health check response")
		}
	})

	addr := fmt.Sprintf("%s:%s", host, port)
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Minute, // Set to 60 minutes to support long-lived connections
	}

	if tlsConfig != nil {
		httpServer.TLSConfig = tlsConfig.Config
		logger.Infof("TLS enabled with certificate: %s", tlsConfig.CertFile)
	} else {
		if !client.IsLocalHost(host) {
			// 0.0.0.0 is deliberately not exempt: it exposes plaintext,
			// admin-capable traffic on every interface. Containerized
			// deployments that terminate TLS elsewhere must opt in
			// explicitly.
			if allowInsecure, _ := strconv.ParseBool(os.Getenv("MCP_ALLOW_INSECURE_TRANSPORT")); !allowInsecure {
				return fmt.Errorf("TLS is required for non-localhost binding (%s). Set MCP_TLS_CERT_FILE and MCP_TLS_KEY_FILE, or set MCP_ALLOW_INSECURE_TRANSPORT=true only if TLS is terminated by a trusted proxy", host)
			}
			logger.Warnf("MCP_ALLOW_INSECURE_TRANSPORT is set: serving plaintext HTTP on non-localhost binding %s. Do NOT use this outside a trusted network with external TLS termination", host)
		} else {
			logger.Warnf("TLS is disabled on StreamableHTTP server; this is not recommended for production")
		}
	}

	// Start server in goroutine
	errC := make(chan error, 1)
	go func() {
		logger.Infof("Starting StreamableHTTP server on %s%s", addr, endpointPath)
		errC <- httpServer.ListenAndServe()
	}()

	// Wait for shutdown signal
	select {
	case <-ctx.Done():
		logger.Infof("Shutting down StreamableHTTP server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errC:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("StreamableHTTP server error: %w", err)
		}
	}

	return nil
}

func runStdioServer(logger *log.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := loadServerConfig(logger)
	if err != nil {
		return fmt.Errorf("invalid server configuration: %w", err)
	}

	hcServer := NewServer(version.Version, logger, cfg)
	tools.InitTools(hcServer, logger, cfg)
	prompts.InitPrompts(hcServer, logger, cfg)

	return serverInit(ctx, hcServer, logger)
}

func NewServer(version string, logger *log.Logger, cfg config.Config, opts ...server.ServerOption) *server.MCPServer {
	// Create rate limiting middleware with environment-based configuration
	rateLimitConfig := client.LoadRateLimitConfigFromEnv()
	rateLimitMiddleware := client.NewRateLimitMiddleware(rateLimitConfig, logger)

	// Add default options. The read-only guard is the call-time enforcement
	// layer for read-only mode; mutating tools are additionally never
	// registered (see pkg/tools).
	defaultOpts := []server.ServerOption{
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(false),
		// Recover from a panic in any tool handler so a single malformed
		// request cannot crash the process (relevant under stdio transport).
		server.WithRecovery(),
		server.WithToolHandlerMiddleware(rateLimitMiddleware.Middleware()),
		server.WithToolHandlerMiddleware(tools.ReadOnlyGuardMiddleware(cfg.ReadOnly, logger)),
	}
	opts = append(defaultOpts, opts...)

	// Create hooks for session management
	hooks := &server.Hooks{}
	hooks.AddOnRegisterSession(func(ctx context.Context, session server.ClientSession) {
		client.NewSessionHandler(ctx, session, logger)
	})
	hooks.AddOnUnregisterSession(func(ctx context.Context, session server.ClientSession) {
		client.EndSessionHandler(ctx, session, logger)
	})

	// Add hooks to options
	opts = append(opts, server.WithHooks(hooks))

	// Create a new MCP server
	s := server.NewMCPServer(
		"vault-mcp-server",
		version,
		opts...,
	)
	return s
}

// runDefaultCommand handles the default behavior when no subcommand is provided
func runDefaultCommand(cmd *cobra.Command, _ []string) {
	// Default to stdio mode when no subcommand is provided
	logFile, err := cmd.PersistentFlags().GetString("log-file")
	if err != nil {
		stdlog.Fatal("Failed to get log file:", err)
	}
	logger, err := initLogger(logFile)
	if err != nil {
		stdlog.Fatal("Failed to initialize logger:", err)
	}

	if err := runStdioServer(logger); err != nil {
		stdlog.Fatal("failed to run stdio server:", err)
	}
}

func main() {
	// Check environment variables first - they override command line args
	if shouldUseHTTPMode() {
		port := getHTTPPort()
		host := getHTTPHost()
		endpointPath := getEndpointPath(nil)

		logFile, _ := rootCmd.PersistentFlags().GetString("log-file")
		logger, err := initLogger(logFile)
		if err != nil {
			stdlog.Fatal("Failed to initialize logger:", err)
		}

		if err := runHTTPServer(logger, host, port, endpointPath); err != nil {
			stdlog.Fatal("failed to run HTTP server:", err)
		}
		return
	}

	// Fall back to normal CLI behavior
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// shouldUseHTTPMode checks if environment variables indicate HTTP mode
func shouldUseHTTPMode() bool {
	transportMode := os.Getenv("TRANSPORT_MODE")
	return transportMode == "http" || transportMode == "streamable-http" ||
		os.Getenv("TRANSPORT_PORT") != "" ||
		os.Getenv("TRANSPORT_HOST") != "" ||
		os.Getenv("MCP_ENDPOINT") != ""
}

// getHTTPPort returns the port from environment variables or default
func getHTTPPort() string {
	if port := os.Getenv("TRANSPORT_PORT"); port != "" {
		return port
	}
	return DefaultBindPort
}

// getHTTPHost returns the host from environment variables or default
func getHTTPHost() string {
	if host := os.Getenv("TRANSPORT_HOST"); host != "" {
		return host
	}
	return DefaultBindAddress
}

// Add function to get endpoint path from environment or flag
func getEndpointPath(cmd *cobra.Command) string {
	// First check environment variable
	if envPath := os.Getenv("MCP_ENDPOINT"); envPath != "" {
		return envPath
	}

	// Fall back to command line flag
	if cmd != nil {
		if path, err := cmd.Flags().GetString("mcp-endpoint"); err == nil && path != "" {
			return path
		}
	}

	return DefaultEndPointPath
}
