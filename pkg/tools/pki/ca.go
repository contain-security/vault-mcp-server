// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// GeneratePkiRoot creates a tool for generating a root CA on a PKI mount.
func GeneratePkiRoot(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("generate_pki_root",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:   utils.ToBoolPtr(false),
					IdempotentHint: utils.ToBoolPtr(false),
				},
			),
			mcp.WithDescription("Generates a new self-signed root CA on a PKI mount in Vault. Only the 'internal' key type is supported: the CA private key is generated inside Vault, never leaves Vault and is never returned by this tool. Returns the root CA certificate (public), the issuer id and the serial number."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The PKI mount to generate the root CA on. For example 'pki'."),
			),
			mcp.WithString("common_name",
				mcp.Required(),
				mcp.Description("Common Name (CN) for the root CA certificate. For example 'example.com Root CA'."),
			),
			mcp.WithString("ttl",
				mcp.DefaultString("87600h"),
				mcp.Description("Optional TTL for the root CA certificate. Defaults to '87600h' (10 years)."),
			),
			mcp.WithString("issuer_name",
				mcp.Description("Optional unique name used to reference this issuer within the mount. For example 'root-2026'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return generatePkiRootHandler(ctx, req, logger)
		},
	}
}

func generatePkiRootHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling generate_pki_root request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	commonName, ok := args["common_name"].(string)
	if !ok || commonName == "" {
		return mcp.NewToolResultError("Missing or invalid 'common_name' parameter"), nil
	}

	ttl, _ := args["ttl"].(string)
	if ttl == "" {
		ttl = "87600h"
	}

	issuerName, _ := args["issuer_name"].(string)

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// SECURITY: only the "internal" key type is supported, so the CA private
	// key is generated inside Vault and never returned.
	fullPath := fmt.Sprintf("%s/root/generate/internal", mount)

	requestData := map[string]interface{}{
		"common_name": commonName,
		"ttl":         ttl,
	}
	if issuerName != "" {
		requestData["issuer_name"] = issuerName
	}

	secret, err := vault.Logical().Write(fullPath, requestData)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":       mount,
			"common_name": commonName,
		}).Error("Failed to generate pki root CA")
		return mcp.NewToolResultError(fmt.Sprintf("failed to write to path '%s': %v", fullPath, err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError(fmt.Sprintf("Vault returned no data when generating root CA on mount '%s'", mount)), nil
	}

	certificate := secret.Data["certificate"]
	issuerID := secret.Data["issuer_id"]
	serialNumber := secret.Data["serial_number"]

	logger.WithFields(log.Fields{
		"mount":       mount,
		"common_name": commonName,
		"serial":      serialNumber,
	}).Info("Successfully generated pki root CA")

	return mcp.NewToolResultText(fmt.Sprintf(
		"Successfully generated root CA on mount '%s'.\nIssuer id: %v\nSerial number: %v\nCertificate:\n%v",
		mount, issuerID, serialNumber, certificate,
	)), nil
}

// GeneratePkiIntermediateCsr creates a tool for generating an intermediate CA CSR.
func GeneratePkiIntermediateCsr(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("generate_pki_intermediate_csr",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:   utils.ToBoolPtr(false),
					IdempotentHint: utils.ToBoolPtr(false),
				},
			),
			mcp.WithDescription("Generates a new intermediate CA key pair and Certificate Signing Request (CSR) on a PKI mount in Vault. Only the 'internal' key type is supported: the private key is generated inside Vault, never leaves Vault and is never returned. Returns the PEM-encoded CSR, which should be signed by a root CA (see sign_pki_intermediate) and then installed with set_pki_signed_intermediate."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The PKI mount to generate the intermediate CSR on. For example 'pki_int'."),
			),
			mcp.WithString("common_name",
				mcp.Required(),
				mcp.Description("Common Name (CN) for the intermediate CA certificate. For example 'example.com Intermediate CA'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return generatePkiIntermediateCsrHandler(ctx, req, logger)
		},
	}
}

func generatePkiIntermediateCsrHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling generate_pki_intermediate_csr request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	commonName, ok := args["common_name"].(string)
	if !ok || commonName == "" {
		return mcp.NewToolResultError("Missing or invalid 'common_name' parameter"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// SECURITY: only the "internal" key type is supported, so the private key
	// is generated inside Vault and never returned.
	fullPath := fmt.Sprintf("%s/intermediate/generate/internal", mount)

	secret, err := vault.Logical().Write(fullPath, map[string]interface{}{
		"common_name": commonName,
	})
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":       mount,
			"common_name": commonName,
		}).Error("Failed to generate pki intermediate CSR")
		return mcp.NewToolResultError(fmt.Sprintf("failed to write to path '%s': %v", fullPath, err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError(fmt.Sprintf("Vault returned no data when generating intermediate CSR on mount '%s'", mount)), nil
	}

	csr := secret.Data["csr"]

	logger.WithFields(log.Fields{
		"mount":       mount,
		"common_name": commonName,
	}).Info("Successfully generated pki intermediate CSR")

	return mcp.NewToolResultText(fmt.Sprintf(
		"Successfully generated intermediate CSR on mount '%s'. Sign it with sign_pki_intermediate on the root mount, then install the result with set_pki_signed_intermediate.\nCSR:\n%v",
		mount, csr,
	)), nil
}

// SignPkiIntermediate creates a tool for signing an intermediate CSR with a root CA.
func SignPkiIntermediate(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("sign_pki_intermediate",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:   utils.ToBoolPtr(false),
					IdempotentHint: utils.ToBoolPtr(false),
				},
			),
			mcp.WithDescription("Signs an intermediate CA Certificate Signing Request (CSR) using the root CA on a PKI mount in Vault. The 'mount' must be the root CA mount. Returns the signed intermediate certificate as a PEM bundle; install it on the intermediate mount with set_pki_signed_intermediate."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The PKI mount holding the root CA that will sign the CSR. For example 'pki'."),
			),
			mcp.WithString("csr",
				mcp.Required(),
				mcp.Description("The PEM-encoded Certificate Signing Request to sign, as returned by generate_pki_intermediate_csr."),
			),
			mcp.WithString("common_name",
				mcp.Description("Optional Common Name (CN) override for the signed certificate. If omitted, the common name from the CSR is used."),
			),
			mcp.WithString("ttl",
				mcp.DefaultString("43800h"),
				mcp.Description("Optional TTL for the signed intermediate certificate. Defaults to '43800h' (5 years)."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return signPkiIntermediateHandler(ctx, req, logger)
		},
	}
}

func signPkiIntermediateHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling sign_pki_intermediate request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	csr, ok := args["csr"].(string)
	if !ok || csr == "" {
		return mcp.NewToolResultError("Missing or invalid 'csr' parameter"), nil
	}

	commonName, _ := args["common_name"].(string)

	ttl, _ := args["ttl"].(string)
	if ttl == "" {
		ttl = "43800h"
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	fullPath := fmt.Sprintf("%s/root/sign-intermediate", mount)

	requestData := map[string]interface{}{
		"csr":    csr,
		"format": "pem_bundle",
		"ttl":    ttl,
	}
	if commonName != "" {
		requestData["common_name"] = commonName
	}

	secret, err := vault.Logical().Write(fullPath, requestData)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":       mount,
			"common_name": commonName,
		}).Error("Failed to sign pki intermediate")
		return mcp.NewToolResultError(fmt.Sprintf("failed to write to path '%s': %v", fullPath, err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError(fmt.Sprintf("Vault returned no data when signing intermediate on mount '%s'", mount)), nil
	}

	certificate := secret.Data["certificate"]

	logger.WithFields(log.Fields{
		"mount":       mount,
		"common_name": commonName,
	}).Info("Successfully signed pki intermediate certificate")

	return mcp.NewToolResultText(fmt.Sprintf(
		"Successfully signed intermediate certificate on mount '%s'. Install it on the intermediate mount with set_pki_signed_intermediate.\nCertificate:\n%v",
		mount, certificate,
	)), nil
}

// SetPkiSignedIntermediate creates a tool for installing a signed intermediate certificate.
func SetPkiSignedIntermediate(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("set_pki_signed_intermediate",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:   utils.ToBoolPtr(false),
					IdempotentHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Installs a signed intermediate CA certificate on a PKI mount in Vault, completing the intermediate CA setup. The 'mount' must be the intermediate mount where the CSR was generated (see generate_pki_intermediate_csr); the certificate is the PEM bundle returned by sign_pki_intermediate."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The intermediate PKI mount to install the signed certificate on. For example 'pki_int'."),
			),
			mcp.WithString("certificate",
				mcp.Required(),
				mcp.Description("The PEM-encoded signed certificate bundle, as returned by sign_pki_intermediate."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return setPkiSignedIntermediateHandler(ctx, req, logger)
		},
	}
}

func setPkiSignedIntermediateHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling set_pki_signed_intermediate request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	certificate, ok := args["certificate"].(string)
	if !ok || certificate == "" {
		return mcp.NewToolResultError("Missing or invalid 'certificate' parameter"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	fullPath := fmt.Sprintf("%s/intermediate/set-signed", mount)

	if _, err := vault.Logical().Write(fullPath, map[string]interface{}{
		"certificate": certificate,
	}); err != nil {
		logger.WithError(err).WithField("mount", mount).Error("Failed to set signed pki intermediate certificate")
		return mcp.NewToolResultError(fmt.Sprintf("failed to write to path '%s': %v", fullPath, err)), nil
	}

	logger.WithField("mount", mount).Info("Successfully set signed pki intermediate certificate")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully installed the signed intermediate certificate on mount '%s'. The mount can now issue certificates chained to the root CA.", mount)), nil
}
