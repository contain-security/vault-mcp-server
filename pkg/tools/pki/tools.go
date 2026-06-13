// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"github.com/hashicorp/vault-mcp-server/pkg/tools/registry"
	log "github.com/sirupsen/logrus"
)

// Tools returns all PKI tools with their security classification.
// Note: issue_pki_certificate mints key material, so it is never read-only.
func Tools(logger *log.Logger) []registry.Tool {
	return []registry.Tool{
		{ServerTool: EnablePki(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: CreatePkiIssuer(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: ListPkiIssuers(logger), ReadOnly: true, Category: registry.CategoryCore},
		{ServerTool: ReadPkiIssuer(logger), ReadOnly: true, Category: registry.CategoryCore},
		{ServerTool: ListPkiRoles(logger), ReadOnly: true, Category: registry.CategoryCore},
		{ServerTool: ReadPkiRole(logger), ReadOnly: true, Category: registry.CategoryCore},
		{ServerTool: CreatePkiRole(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: DeletePkiRole(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: IssuePkiCertificate(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: ListPkiCertificates(logger), ReadOnly: true, Category: registry.CategoryCore},
		{ServerTool: ReadPkiCertificate(logger), ReadOnly: true, Category: registry.CategoryCore},
		{ServerTool: RevokePkiCertificate(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: GeneratePkiRoot(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: GeneratePkiIntermediateCsr(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: SignPkiIntermediate(logger), ReadOnly: false, Category: registry.CategoryCore},
		{ServerTool: SetPkiSignedIntermediate(logger), ReadOnly: false, Category: registry.CategoryCore},
	}
}
