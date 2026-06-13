// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package audit

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// allowedAuditTypes are the audit device types this server is willing to enable.
var allowedAuditTypes = map[string]bool{
	"file":   true,
	"syslog": true,
	"socket": true,
}

// EnableAuditDevice creates a tool for enabling an audit device.
func EnableAuditDevice(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("enable_audit_device",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:   utils.ToBoolPtr(false),
					IdempotentHint: utils.ToBoolPtr(false),
				},
			),
			mcp.WithDescription("Enables a new audit device in Vault at the given path. Audit devices record every request and response Vault handles. Type 'file' requires the 'file_path' option (an absolute path on the Vault server where the audit log is written, for example '/var/log/vault_audit.log'). Fails if a device is already enabled at the path."),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The path where the audit device will be enabled. For example 'file' or 'main-audit'."),
			),
			mcp.WithString("type",
				mcp.Required(),
				mcp.Enum("file", "syslog", "socket"),
				mcp.Description("The type of audit device. Must be one of 'file', 'syslog', or 'socket'."),
			),
			mcp.WithString("description",
				mcp.Description("An optional human-readable description for the audit device."),
			),
			mcp.WithObject("options",
				mcp.Description("Configuration options for the audit device as string key/value pairs. Type 'file' requires 'file_path'. Type 'socket' typically takes 'address' and 'socket_type'. Type 'syslog' typically takes 'facility' and 'tag'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return enableAuditDeviceHandler(ctx, req, logger)
		},
	}
}

func enableAuditDeviceHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling enable_audit_device request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	path, ok := args["path"].(string)
	if !ok || path == "" {
		return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
	}

	auditType, ok := args["type"].(string)
	if !ok || auditType == "" || !allowedAuditTypes[auditType] {
		return mcp.NewToolResultError("Missing or invalid 'type' parameter: must be one of 'file', 'syslog', or 'socket'"), nil
	}

	description, _ := args["description"].(string)

	options := make(map[string]string)
	if rawOptions, ok := args["options"].(map[string]interface{}); ok {
		for key, value := range rawOptions {
			if s, ok := value.(string); ok {
				options[key] = s
			} else {
				options[key] = fmt.Sprintf("%v", value)
			}
		}
	}

	if auditType == "file" && options["file_path"] == "" {
		return mcp.NewToolResultError("Audit device type 'file' requires the 'file_path' option, for example {\"file_path\": \"/var/log/vault_audit.log\"}"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	enableOptions := &api.EnableAuditOptions{
		Type:        auditType,
		Description: description,
		Options:     options,
	}

	if err := vault.Sys().EnableAuditWithOptions(path, enableOptions); err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"path": path,
			"type": auditType,
		}).Error("Failed to enable audit device")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to enable audit device at path '%s': %v", path, err)), nil
	}

	logger.WithFields(log.Fields{
		"path": path,
		"type": auditType,
	}).Info("Successfully enabled audit device")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully enabled audit device of type '%s' at path '%s'", auditType, path)), nil
}

// DisableAuditDevice creates a tool for disabling an audit device.
func DisableAuditDevice(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("disable_audit_device",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Disables the audit device at the given path in Vault. WARNING: disabling an audit device permanently stops the audit trail for that device; the events that would have been recorded are lost and cannot be recovered. This should normally be a human decision - do not call this tool unless a human operator has explicitly asked for this specific device to be disabled."),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The path of the audit device to disable. For example 'file'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return disableAuditDeviceHandler(ctx, req, logger)
		},
	}
}

func disableAuditDeviceHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling disable_audit_device request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	path, ok := args["path"].(string)
	if !ok || path == "" {
		return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	if err := vault.Sys().DisableAudit(path); err != nil {
		logger.WithError(err).WithField("path", path).Error("Failed to disable audit device")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to disable audit device at path '%s': %v", path, err)), nil
	}

	// AR-004: disabling an audit device destroys its audit trail, so a
	// successful invocation is logged at Warn level.
	logger.WithField("path", path).Warn("Audit device disabled - the audit trail for this device has permanently stopped")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully disabled audit device at path '%s'. The audit trail for this device has permanently stopped.", path)), nil
}
