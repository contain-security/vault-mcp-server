// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// ListPkiCertificates creates a tool for listing issued PKI certificates.
func ListPkiCertificates(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_pki_certificates",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:   utils.ToBoolPtr(true),
					IdempotentHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Lists the serial numbers of all certificates issued by a PKI mount in Vault. Use read_pki_certificate with one of the returned serial numbers to fetch the certificate itself."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The PKI mount to list certificates from. For example 'pki'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listPkiCertificatesHandler(ctx, req, logger)
		},
	}
}

func listPkiCertificatesHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_pki_certificates request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	fullPath := fmt.Sprintf("%s/certs", mount)

	secret, err := vault.Logical().List(fullPath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to list path '%s': %v", fullPath, err)), nil
	}

	if secret == nil || secret.Data == nil || secret.Data["keys"] == nil {
		return mcp.NewToolResultText(fmt.Sprintf("No certificates found on mount '%s'.", mount)), nil
	}

	jsonData, err := json.Marshal(secret.Data["keys"])
	if err != nil {
		logger.WithError(err).Error("Failed to marshal certificate serial numbers to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithField("mount", mount).Debug("Successfully listed pki certificates")

	return mcp.NewToolResultText(fmt.Sprintf("Certificate serial numbers on mount '%s': %s", mount, string(jsonData))), nil
}

// ReadPkiCertificate creates a tool for reading a single issued PKI certificate.
func ReadPkiCertificate(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_pki_certificate",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:   utils.ToBoolPtr(true),
					IdempotentHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Reads an issued certificate from a PKI mount in Vault by its serial number. Returns the PEM-encoded certificate and, if the certificate has been revoked, its revocation time. Only the public certificate is returned, never the private key."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The PKI mount to read the certificate from. For example 'pki'."),
			),
			mcp.WithString("serial",
				mcp.Required(),
				mcp.Description("The colon-separated serial number of the certificate to read. For example '39:dd:2e:90:b7:23:1f:8d:d3:7d:31:c5:1b:da:84:d0:5b:65:31:58'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readPkiCertificateHandler(ctx, req, logger)
		},
	}
}

func readPkiCertificateHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_pki_certificate request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	serial, ok := args["serial"].(string)
	if !ok || serial == "" {
		return mcp.NewToolResultError("Missing or invalid 'serial' parameter"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	fullPath := fmt.Sprintf("%s/cert/%s", mount, serial)

	secret, err := vault.Logical().Read(fullPath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to read path '%s': %v", fullPath, err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError(fmt.Sprintf("Certificate with serial '%s' not found on mount '%s'", serial, mount)), nil
	}

	certificate, _ := secret.Data["certificate"].(string)

	result := fmt.Sprintf("Certificate '%s' on mount '%s':\n%s", serial, mount, certificate)

	if revocationTime, ok := secret.Data["revocation_time"]; ok {
		if rt := fmt.Sprintf("%v", revocationTime); rt != "" && rt != "0" {
			result += fmt.Sprintf("\nRevocation time: %s (this certificate has been revoked)", rt)
		}
	}

	logger.WithFields(log.Fields{
		"mount":  mount,
		"serial": serial,
	}).Debug("Successfully read pki certificate")

	return mcp.NewToolResultText(result), nil
}

// RevokePkiCertificate creates a tool for revoking an issued PKI certificate.
func RevokePkiCertificate(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("revoke_pki_certificate",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(false),
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Revokes an issued certificate on a PKI mount in Vault by its serial number. Revocation is permanent and cannot be undone: the certificate is added to the mount's Certificate Revocation List (CRL) and clients that check the CRL will reject it."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The PKI mount the certificate was issued from. For example 'pki'."),
			),
			mcp.WithString("serial",
				mcp.Required(),
				mcp.Description("The colon-separated serial number of the certificate to revoke. For example '39:dd:2e:90:b7:23:1f:8d:d3:7d:31:c5:1b:da:84:d0:5b:65:31:58'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return revokePkiCertificateHandler(ctx, req, logger)
		},
	}
}

func revokePkiCertificateHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling revoke_pki_certificate request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	serial, ok := args["serial"].(string)
	if !ok || serial == "" {
		return mcp.NewToolResultError("Missing or invalid 'serial' parameter"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	fullPath := fmt.Sprintf("%s/revoke", mount)

	secret, err := vault.Logical().Write(fullPath, map[string]interface{}{
		"serial_number": serial,
	})
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":  mount,
			"serial": serial,
		}).Error("Failed to revoke pki certificate")
		return mcp.NewToolResultError(fmt.Sprintf("failed to revoke certificate '%s' on mount '%s': %v", serial, mount, err)), nil
	}

	result := fmt.Sprintf("Successfully revoked certificate '%s' on mount '%s'. The certificate has been added to the CRL.", serial, mount)

	if secret != nil && secret.Data != nil {
		if revocationTime, ok := secret.Data["revocation_time"]; ok {
			result += fmt.Sprintf(" Revocation time: %v", revocationTime)
		}
	}

	logger.WithFields(log.Fields{
		"mount":  mount,
		"serial": serial,
	}).Info("Successfully revoked pki certificate")

	return mcp.NewToolResultText(result), nil
}
