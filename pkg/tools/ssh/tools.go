// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package ssh provides MCP tools for the Vault SSH secrets engine in its
// certificate-signing (CA) mode: configuring the CA key, managing signing
// roles, and signing SSH public keys into short-lived certificates.
package ssh

import (
	"github.com/hashicorp/vault-mcp-server/pkg/tools/registry"
	log "github.com/sirupsen/logrus"
)

// Tools returns all SSH tools with their security classification.
// sign_ssh_key mints a credential (a certificate), so — like
// issue_pki_certificate — it is never read-only.
func Tools(logger *log.Logger) []registry.Tool {
	return []registry.Tool{
		{ServerTool: ConfigureSshCa(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: ReadSshCa(logger), ReadOnly: true, Category: registry.CategoryCore},
		{ServerTool: DeleteSshCa(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: CreateSshRole(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: ReadSshRole(logger), ReadOnly: true, Category: registry.CategoryCore},
		{ServerTool: ListSshRoles(logger), ReadOnly: true, Category: registry.CategoryCore},
		{ServerTool: DeleteSshRole(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: SignSshKey(logger), ReadOnly: false, Category: registry.CategoryCore},
	}
}
