// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package prompts

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	log "github.com/sirupsen/logrus"
)

func setupKvApprolePrompt(logger *log.Logger) promptDef {
	prompt := mcp.NewPrompt("setup_kv_approle",
		mcp.WithPromptDescription("Provision a least-privilege AppRole that lets an application read (or read/write) a single KV path. Handles KV v1 and v2 path shapes, creates a scoped ACL policy and an AppRole role, and delivers the credentials response-wrapped."),
		mcp.WithArgument("app_name", mcp.RequiredArgument(), mcp.ArgumentDescription("Logical application name; used to name the policy and AppRole role (e.g. 'payments-api').")),
		mcp.WithArgument("kv_mount", mcp.RequiredArgument(), mcp.ArgumentDescription("The KV secrets engine mount (e.g. 'apps' or 'secret').")),
		mcp.WithArgument("kv_path", mcp.RequiredArgument(), mcp.ArgumentDescription("The path within the mount to grant access to, without the mount prefix (e.g. 'web/db'). A trailing '/*' grants the subtree.")),
		mcp.WithArgument("access", mcp.ArgumentDescription("Either 'read' or 'read-write'. Defaults to 'read'.")),
		mcp.WithArgument("token_ttl", mcp.ArgumentDescription("AppRole token TTL. Defaults to '1h'.")),
		mcp.WithArgument("token_max_ttl", mcp.ArgumentDescription("AppRole token max TTL. Defaults to '4h'.")),
		mcp.WithArgument("secret_id_ttl", mcp.ArgumentDescription("Secret ID TTL. Defaults to '24h'.")),
		mcp.WithArgument("wrap_ttl", mcp.ArgumentDescription("Response-wrapping TTL for the generated secret ID. Defaults to '120s'.")),
	)

	handler := func(_ context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		if err := requireArgs(req, "app_name", "kv_mount", "kv_path"); err != nil {
			return nil, err
		}

		appName := arg(req, "app_name", "")
		kvMount := arg(req, "kv_mount", "")
		kvPath := arg(req, "kv_path", "")
		access := arg(req, "access", "read")
		if access != "read" && access != "read-write" {
			return nil, fmt.Errorf("argument 'access' must be 'read' or 'read-write', got %q", access)
		}
		tokenTTL := arg(req, "token_ttl", "1h")
		tokenMaxTTL := arg(req, "token_max_ttl", "4h")
		secretIDTTL := arg(req, "secret_id_ttl", "24h")
		wrapTTL := arg(req, "wrap_ttl", "120s")

		// Include a sanitized path segment so two KV AppRoles on the same
		// mount but different paths don't collide on the policy name.
		policyName := fmt.Sprintf("%s-kv-%s-%s", appName, kvMount, sanitizePathSegment(kvPath))

		// Describe the capability set the model should grant per KV version.
		var capsDescription string
		if access == "read" {
			capsDescription = `read-only: ["read"] on the data path (and ["read","list"] on the metadata path for KV v2)`
		} else {
			capsDescription = `read-write: ["create","update","read"] on the data path (and ["read","list"] on the metadata path for KV v2)`
		}

		logger.WithFields(log.Fields{"prompt": "setup_kv_approle", "app": appName}).Debug("Rendering prompt")

		instruction := fmt.Sprintf(`You are provisioning a least-privilege Vault AppRole so the application %q can have %s access to the KV path %q under mount %q. Use the vault MCP tools and follow these steps exactly. Stop and report clearly if any verification step fails — do not improvise broader access.

Conventions (do not deviate):
- ACL policy name: %q
- AppRole role name: %q
- Least privilege: grant %s. Do not grant delete/sudo, and do not widen the path beyond %q.
- Deliver credentials response-wrapped; never print a raw secret_id.

Steps:
1. Determine the KV version (this changes the policy paths):
   - Call list_mounts and find %q. If its options show version "2", it is KV v2; otherwise treat it as KV v1.
   - KV v2 data path:     "%s/data/%s"
     KV v2 metadata path: "%s/metadata/%s"
   - KV v1 path:          "%s/%s"
2. Ensure approle auth is enabled: call list_auth_methods; if there is no "approle/" entry, enable_auth_method with type="approle" path="approle".
3. Write the scoped policy with write_policy (name=%q), using the path shape for the detected version:
   - For KV v2, %s access means:
       path "<data_path>" { capabilities = [%s] }
       path "<metadata_path>" { capabilities = ["read","list"] }
   - For KV v1, %s access means:
       path "<v1_path>" { capabilities = [%s] }
4. Create or update the AppRole role:
   a. First call read_approle_role with name=%q; if it exists, MERGE its token_policies rather than dropping any.
   b. Call write_approle_role with name=%q, token_policies including %q, token_ttl=%q, token_max_ttl=%q, secret_id_ttl=%q.
5. Fetch the role id: read_approle_role_id with name=%q.
6. Generate a wrapped secret id: generate_approle_secret_id with name=%q wrap_ttl=%q.
7. Report back to the operator: the role name (%q), policy name (%q), the role_id (not secret), the secret_id WRAPPING TOKEN + TTL with "vault unwrap <wrapping_token>", the login command "vault write auth/approle/login role_id=<role_id> secret_id=<unwrapped_secret_id>", and a one-line summary of the exact path and capabilities granted.`,
			appName, access, kvPath, kvMount,
			policyName, appName,
			capsDescription, kvPath,
			kvMount,
			kvMount, kvPath,
			kvMount, kvPath,
			kvMount, kvPath,
			policyName,
			access, kvCaps(access),
			access, kvCaps(access),
			appName, appName, policyName, tokenTTL, tokenMaxTTL, secretIDTTL,
			appName, appName, wrapTTL,
			appName, policyName,
		)

		return userMessage(fmt.Sprintf("Set up a least-privilege KV %s AppRole for %s", access, appName), instruction), nil
	}

	return promptDef{prompt: prompt, handler: handler}
}

// sanitizePathSegment turns a KV path into a policy-name-safe segment by
// replacing path separators and wildcards with hyphens.
func sanitizePathSegment(path string) string {
	r := strings.NewReplacer("/", "-", "*", "", " ", "-")
	return strings.Trim(r.Replace(strings.TrimSpace(path)), "-")
}

// kvCaps returns the data-path capability list literal for the access level.
func kvCaps(access string) string {
	if access == "read-write" {
		return `"create","update","read"`
	}
	return `"read"`
}
