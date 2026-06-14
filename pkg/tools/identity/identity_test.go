// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// fakeSession implements server.ClientSession for testing.
type fakeSession struct {
	id      string
	notifCh chan mcp.JSONRPCNotification
}

func (f fakeSession) Initialize()                                         {}
func (f fakeSession) Initialized() bool                                   { return true }
func (f fakeSession) NotificationChannel() chan<- mcp.JSONRPCNotification { return f.notifCh }
func (f fakeSession) SessionID() string                                   { return f.id }

// newTestContext creates a context wired to a mock Vault HTTP server.
func newTestContext(t *testing.T, handler http.Handler) (context.Context, func()) {
	t.Helper()
	mockVault := httptest.NewServer(handler)

	sessionID := "test-" + t.Name()
	_, err := client.NewVaultClient(sessionID, mockVault.URL, false, "test-token", "")
	require.NoError(t, err)

	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx := mcpSrv.WithContext(context.Background(), fakeSession{
		id:      sessionID,
		notifCh: make(chan mcp.JSONRPCNotification, 10),
	})

	return ctx, func() {
		mockVault.Close()
		client.DeleteVaultClient(sessionID)
	}
}

func newLogger() *log.Logger {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)
	return logger
}

func newRequest(args map[string]interface{}) mcp.CallToolRequest {
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	return req
}

func getResultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	require.NotNil(t, result)
	require.NotEmpty(t, result.Content)
	tc, ok := mcp.AsTextContent(result.Content[0])
	require.True(t, ok)
	return tc.Text
}

func TestListEntities(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/identity/entity/name", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "true", r.URL.Query().Get("list"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{"dev-user", "ops-user"},
			},
		})
	}))
	defer cleanup()

	result, err := listEntitiesHandler(ctx, newRequest(nil), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "dev-user")
	require.Contains(t, text, "ops-user")
}

func TestListEntities_Empty(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer cleanup()

	result, err := listEntitiesHandler(ctx, newRequest(nil), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Contains(t, getResultText(t, result), "No identity entities found")
}

func TestReadEntity(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/identity/entity/name/dev-user", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id":       "entity-uuid-1234",
				"name":     "dev-user",
				"disabled": false,
				"policies": []string{"app-read", "app-write"},
				"metadata": map[string]interface{}{"team": "payments"},
				"aliases": []map[string]interface{}{
					{
						"id":             "alias-uuid-5678",
						"name":           "alice",
						"mount_accessor": "auth_userpass_b2c3d4",
					},
				},
			},
		})
	}))
	defer cleanup()

	result, err := readEntityHandler(ctx, newRequest(map[string]interface{}{"name": "dev-user"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "entity-uuid-1234")
	require.Contains(t, text, "app-read")
	require.Contains(t, text, "team: payments")
	require.Contains(t, text, "alias-uuid-5678")
	require.Contains(t, text, "auth_userpass_b2c3d4")
}

func TestReadEntity_MissingName(t *testing.T) {
	result, err := readEntityHandler(context.Background(), newRequest(map[string]interface{}{}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestWriteEntity(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/identity/entity/name/dev-user", r.URL.Path)
		require.Equal(t, http.MethodPut, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := writeEntityHandler(ctx, newRequest(map[string]interface{}{
		"name":     "dev-user",
		"policies": "app-read, app-write",
		"metadata": map[string]interface{}{"team": "payments"},
		"disabled": true,
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)

	policies, ok := gotBody["policies"].([]interface{})
	require.True(t, ok)
	require.ElementsMatch(t, []interface{}{"app-read", "app-write"}, policies)
	metadata, ok := gotBody["metadata"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "payments", metadata["team"])
	require.Equal(t, true, gotBody["disabled"])
}

func TestWriteEntity_RefusesRootPolicy(t *testing.T) {
	for _, policies := range []string{"root", "app-read, Root", "ROOT,app-write"} {
		result, err := writeEntityHandler(context.Background(), newRequest(map[string]interface{}{
			"name":     "dev-user",
			"policies": policies,
		}), newLogger())
		require.NoError(t, err)
		require.True(t, result.IsError, "writing entity with policies %q must be refused", policies)
	}
}

func TestWriteEntity_MissingName(t *testing.T) {
	result, err := writeEntityHandler(context.Background(), newRequest(map[string]interface{}{
		"policies": "app-read",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestDeleteEntity(t *testing.T) {
	deleted := false

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/identity/entity/name/dev-user", r.URL.Path)
		require.Equal(t, http.MethodDelete, r.Method)
		deleted = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := deleteEntityHandler(ctx, newRequest(map[string]interface{}{"name": "dev-user"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.True(t, deleted)
}

func TestCreateEntityAlias(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/identity/entity-alias", r.URL.Path)
		require.Equal(t, http.MethodPut, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id":           "alias-uuid-5678",
				"canonical_id": "entity-uuid-1234",
			},
		})
	}))
	defer cleanup()

	result, err := createEntityAliasHandler(ctx, newRequest(map[string]interface{}{
		"name":           "alice",
		"canonical_id":   "entity-uuid-1234",
		"mount_accessor": "auth_userpass_b2c3d4",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)

	require.Equal(t, "alice", gotBody["name"])
	require.Equal(t, "entity-uuid-1234", gotBody["canonical_id"])
	require.Equal(t, "auth_userpass_b2c3d4", gotBody["mount_accessor"])
	require.Contains(t, getResultText(t, result), "alias-uuid-5678")
}

func TestCreateEntityAlias_MissingMountAccessor(t *testing.T) {
	result, err := createEntityAliasHandler(context.Background(), newRequest(map[string]interface{}{
		"name":         "alice",
		"canonical_id": "entity-uuid-1234",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestDeleteEntityAlias(t *testing.T) {
	deleted := false

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/identity/entity-alias/id/alias-uuid-5678", r.URL.Path)
		require.Equal(t, http.MethodDelete, r.Method)
		deleted = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := deleteEntityAliasHandler(ctx, newRequest(map[string]interface{}{"id": "alias-uuid-5678"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.True(t, deleted)
}

func TestDeleteEntityAlias_MissingID(t *testing.T) {
	result, err := deleteEntityAliasHandler(context.Background(), newRequest(map[string]interface{}{}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestListGroups(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/identity/group/name", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "true", r.URL.Query().Get("list"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{"developers", "operators"},
			},
		})
	}))
	defer cleanup()

	result, err := listGroupsHandler(ctx, newRequest(nil), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "developers")
	require.Contains(t, text, "operators")
}

func TestWriteGroup(t *testing.T) {
	var gotBody map[string]interface{}

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/identity/group/name/developers", r.URL.Path)
		require.Equal(t, http.MethodPut, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := writeGroupHandler(ctx, newRequest(map[string]interface{}{
		"name":              "developers",
		"policies":          "app-read,app-write",
		"member_entity_ids": "entity-uuid-1234, entity-uuid-9999",
		"member_group_ids":  "group-uuid-0001",
	}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)

	require.Equal(t, "internal", gotBody["type"])
	policies, ok := gotBody["policies"].([]interface{})
	require.True(t, ok)
	require.ElementsMatch(t, []interface{}{"app-read", "app-write"}, policies)
	memberEntityIDs, ok := gotBody["member_entity_ids"].([]interface{})
	require.True(t, ok)
	require.ElementsMatch(t, []interface{}{"entity-uuid-1234", "entity-uuid-9999"}, memberEntityIDs)
	memberGroupIDs, ok := gotBody["member_group_ids"].([]interface{})
	require.True(t, ok)
	require.ElementsMatch(t, []interface{}{"group-uuid-0001"}, memberGroupIDs)
}

func TestWriteGroup_RefusesRootPolicy(t *testing.T) {
	result, err := writeGroupHandler(context.Background(), newRequest(map[string]interface{}{
		"name":     "developers",
		"policies": "app-read, ROOT",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestWriteGroup_RejectsInvalidType(t *testing.T) {
	result, err := writeGroupHandler(context.Background(), newRequest(map[string]interface{}{
		"name": "developers",
		"type": "hybrid",
	}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, getResultText(t, result), "internal")
}

func TestReadGroup(t *testing.T) {
	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/identity/group/name/developers", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id":                "group-uuid-0001",
				"name":              "developers",
				"type":              "internal",
				"policies":          []string{"app-read"},
				"member_entity_ids": []string{"entity-uuid-1234"},
				"member_group_ids":  []string{"group-uuid-0002"},
			},
		})
	}))
	defer cleanup()

	result, err := readGroupHandler(ctx, newRequest(map[string]interface{}{"name": "developers"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := getResultText(t, result)
	require.Contains(t, text, "group-uuid-0001")
	require.Contains(t, text, "internal")
	require.Contains(t, text, "app-read")
	require.Contains(t, text, "entity-uuid-1234")
	require.Contains(t, text, "group-uuid-0002")
}

func TestReadGroup_MissingName(t *testing.T) {
	result, err := readGroupHandler(context.Background(), newRequest(map[string]interface{}{}), newLogger())
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestDeleteGroup(t *testing.T) {
	deleted := false

	ctx, cleanup := newTestContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/identity/group/name/developers", r.URL.Path)
		require.Equal(t, http.MethodDelete, r.Method)
		deleted = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cleanup()

	result, err := deleteGroupHandler(ctx, newRequest(map[string]interface{}{"name": "developers"}), newLogger())
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.True(t, deleted)
}

func TestTools_Classification(t *testing.T) {
	tools := Tools(newLogger())
	require.Len(t, tools, 10)

	readOnly := map[string]bool{}
	for _, tool := range tools {
		readOnly[tool.Tool.Name] = tool.ReadOnly
	}

	require.True(t, readOnly["list_entities"])
	require.True(t, readOnly["read_entity"])
	require.False(t, readOnly["write_entity"])
	require.False(t, readOnly["delete_entity"])
	require.False(t, readOnly["create_entity_alias"])
	require.False(t, readOnly["delete_entity_alias"])
	require.True(t, readOnly["list_groups"])
	require.True(t, readOnly["read_group"])
	require.False(t, readOnly["write_group"])
	require.False(t, readOnly["delete_group"])
}
