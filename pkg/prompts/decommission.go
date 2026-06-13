// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package prompts

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	log "github.com/sirupsen/logrus"
)

func decommissionApprolePrompt(logger *log.Logger) promptDef {
	prompt := mcp.NewPrompt("decommission_approle",
		mcp.WithPromptDescription("Cleanly tear down an AppRole provisioned by the setup prompts: destroy its secret IDs, delete the AppRole role, and (optionally) delete the dedicated ACL policies created for it. Refuses to touch shared or built-in policies."),
		mcp.WithArgument("app_name", mcp.RequiredArgument(), mcp.ArgumentDescription("The AppRole role name to decommission (the 'app_name' used at setup, e.g. 'payments-api').")),
		mcp.WithArgument("approle_mount", mcp.ArgumentDescription("The AppRole auth mount. Defaults to 'approle'.")),
		mcp.WithArgument("delete_policies", mcp.ArgumentDescription("Whether to also delete the app's dedicated ACL policies ('true' or 'false'). Defaults to 'true'.")),
	)

	handler := func(_ context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		if err := requireArgs(req, "app_name"); err != nil {
			return nil, err
		}

		appName := arg(req, "app_name", "")
		approleMount := arg(req, "approle_mount", "approle")
		deletePolicies := arg(req, "delete_policies", "true")
		if deletePolicies != "true" && deletePolicies != "false" {
			return nil, fmt.Errorf("argument 'delete_policies' must be 'true' or 'false', got %q", deletePolicies)
		}

		logger.WithFields(log.Fields{"prompt": "decommission_approle", "app": appName}).Debug("Rendering prompt")

		policyStep := fmt.Sprintf(`5. Because delete_policies=%q, do NOT delete any policies; instead list the role's policies for the operator to review.`, deletePolicies)
		if deletePolicies == "true" {
			policyStep = fmt.Sprintf(`5. Delete the app's DEDICATED policies only:
   - From the token_policies captured in step 1, select only policies whose name begins with %q (the naming convention used by the setup prompts, e.g. "%s-pki-...", "%s-ssh-...", "%s-kv-...").
   - NEVER delete "default", "root", or any policy not matching that prefix — those may be shared. List any skipped policies for the operator.
   - Delete each selected policy with delete_policy.`, appName+"-", appName, appName, appName)
		}

		instruction := fmt.Sprintf(`You are decommissioning the Vault AppRole %q on auth mount %q. This is destructive: be careful and report exactly what you remove. Use the vault MCP tools and follow these steps in order. Before performing any deletion, print a short summary of what you are about to delete and proceed.

Steps:
1. Confirm the role exists and capture its policies: call read_approle_role with mount=%q name=%q. If it does not exist, STOP and report that there is nothing to decommission. Record its token_policies for step 5.
2. Revoke all outstanding secret IDs: call list_approle_secret_id_accessors with mount=%q name=%q. For each accessor returned, call destroy_approle_secret_id with mount=%q name=%q and the secret_id_accessor. (If none are listed, note that and continue.)
3. Summarize for the operator what will be deleted: the role %q and, if applicable, which policies.
4. Delete the AppRole role: delete_approle_role with mount=%q name=%q.
%s
6. Report a final summary: the role deleted, the number of secret IDs destroyed, the policies deleted, and any policies deliberately skipped (with the reason).`,
			appName, approleMount,
			approleMount, appName,
			approleMount, appName,
			approleMount, appName,
			appName,
			approleMount, appName,
			policyStep,
		)

		return userMessage(fmt.Sprintf("Decommission the AppRole %s", appName), instruction), nil
	}

	return promptDef{prompt: prompt, handler: handler}
}
