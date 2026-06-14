// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package prompts

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	log "github.com/sirupsen/logrus"
)

func setupSshApprolePrompt(logger *log.Logger) promptDef {
	prompt := mcp.NewPrompt("setup_ssh_approle",
		mcp.WithPromptDescription("Provision a least-privilege AppRole that lets an application sign SSH keys against a single SSH CA signing role. Creates a scoped ACL policy, an AppRole role, and delivers the credentials response-wrapped."),
		mcp.WithArgument("app_name", mcp.RequiredArgument(), mcp.ArgumentDescription("Logical application name; used to name the policy and AppRole role (e.g. 'bastion-fleet').")),
		mcp.WithArgument("ssh_mount", mcp.RequiredArgument(), mcp.ArgumentDescription("The SSH secrets engine mount (e.g. 'ssh-client-ca').")),
		mcp.WithArgument("ssh_role", mcp.RequiredArgument(), mcp.ArgumentDescription("The SSH CA signing role to grant access to (e.g. 'clients').")),
		mcp.WithArgument("token_ttl", mcp.ArgumentDescription("AppRole token TTL. Defaults to '1h'.")),
		mcp.WithArgument("token_max_ttl", mcp.ArgumentDescription("AppRole token max TTL. Defaults to '4h'.")),
		mcp.WithArgument("secret_id_ttl", mcp.ArgumentDescription("Secret ID TTL. Defaults to '24h'.")),
		mcp.WithArgument("wrap_ttl", mcp.ArgumentDescription("Response-wrapping TTL for the generated secret ID. Defaults to '120s'.")),
	)

	handler := func(_ context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		if err := requireArgs(req, "app_name", "ssh_mount", "ssh_role"); err != nil {
			return nil, err
		}

		appName := arg(req, "app_name", "")
		sshMount := arg(req, "ssh_mount", "")
		sshRole := arg(req, "ssh_role", "")
		tokenTTL := arg(req, "token_ttl", "1h")
		tokenMaxTTL := arg(req, "token_max_ttl", "4h")
		secretIDTTL := arg(req, "secret_id_ttl", "24h")
		wrapTTL := arg(req, "wrap_ttl", "120s")

		policyName := fmt.Sprintf("%s-ssh-%s", appName, sshRole)
		grantedPath := fmt.Sprintf("%s/sign/%s", sshMount, sshRole)

		logger.WithFields(log.Fields{"prompt": "setup_ssh_approle", "app": appName}).Debug("Rendering prompt")

		instruction := fmt.Sprintf(`You are provisioning a least-privilege Vault AppRole so the application %q can sign SSH keys against the SSH CA role %q on mount %q. Use the vault MCP tools and follow these steps exactly. Stop and report clearly if any verification step fails — do not improvise broader access.

Conventions (do not deviate):
- ACL policy name: %q
- AppRole role name: %q
- Least privilege: the policy grants ONLY ["create","update"] on the single path %q. Never widen to the whole mount or use wildcards.
- Deliver credentials response-wrapped; never print a raw secret_id.

Steps:
1. Verify prerequisites:
   a. Call read_ssh_role with mount=%q name=%q. If it does not exist, STOP and report that the SSH role must be created first (and that the mount needs a CA signing key via configure_ssh_ca).
   b. Call list_auth_methods. If there is no "approle/" entry, enable it: enable_auth_method with type="approle" path="approle".
2. Write the scoped policy with write_policy:
   name=%q
   policy:
     path "%s" {
       capabilities = ["create", "update"]
     }
3. Create or update the AppRole role:
   a. First call read_approle_role with name=%q. If it already exists, capture its current token_policies so you can MERGE — never drop policies that belong to other engines.
   b. Call write_approle_role with name=%q, token_policies set to the union of any existing policies and %q, token_ttl=%q, token_max_ttl=%q, secret_id_ttl=%q.
4. Fetch the role id: read_approle_role_id with name=%q.
5. Generate a wrapped secret id: generate_approle_secret_id with name=%q wrap_ttl=%q.
6. Report back to the operator:
   - the AppRole role name (%q) and the policy name (%q)
   - the role_id (this value is not secret)
   - the secret_id WRAPPING TOKEN and its TTL, with the unwrap command: vault unwrap <wrapping_token>
   - the application login: vault write auth/approle/login role_id=<role_id> secret_id=<unwrapped_secret_id>
   - a one-line summary: "%s may sign SSH certs via %s only".`,
			appName, sshRole, sshMount,
			policyName, appName, grantedPath,
			sshMount, sshRole,
			policyName, grantedPath,
			appName, appName, policyName, tokenTTL, tokenMaxTTL, secretIDTTL,
			appName, appName, wrapTTL,
			appName, policyName,
			appName, grantedPath,
		)

		return userMessage(fmt.Sprintf("Set up a least-privilege SSH signing AppRole for %s", appName), instruction), nil
	}

	return promptDef{prompt: prompt, handler: handler}
}
