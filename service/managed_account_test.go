package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestManagedAccountCapabilityBindsEveryRequest(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(public)
	require.NoError(t, err)
	keys, err := common.Marshal(map[string]any{"schema_version": "sai-authz-public-keys.v1", "keys": map[string]string{"fixture": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}})
	require.NoError(t, err)
	keyFile := t.TempDir() + "/keys.json"
	require.NoError(t, os.WriteFile(keyFile, keys, 0600))
	credential := t.TempDir() + "/credential"
	require.NoError(t, os.WriteFile(credential, []byte(strings.Repeat("x", 48)), 0600))
	t.Setenv("MODEL_MANAGEMENT_AUTHZ_KEYS_FILE", keyFile)
	t.Setenv("MODEL_MANAGEMENT_AUTHZ_POLICY_EPOCH", "2")
	t.Setenv("MODEL_MANAGEMENT_SITE_ID", "fixture-site")
	t.Setenv("MODEL_BILLING_INSTANCE_REF", "fixture-gateway")
	t.Setenv("MODEL_BILLING_ADMISSION_KEY_FILE", credential)
	var mutate func(jwt.MapClaims, map[string]any)
	calls, denied := 0, false
	method, target, body := "PUT", "/api/token/?status_only=true&token=private-key", `{"id":42,"status":2}`
	responseVersion := 2
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		require.Equal(t, "Bearer "+strings.Repeat("x", 48), r.Header.Get("Authorization"))
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var request ManagementRequest
		require.NoError(t, common.Unmarshal(raw, &request))
		require.Equal(t, 7, request.ActorID)
		require.Equal(t, "session-fixture", request.SessionID)
		require.Equal(t, 2, request.SchemaVersion)
		digest := sha256.Sum256([]byte(method + "\n" + target + "\n" + body))
		require.Equal(t, hex.EncodeToString(digest[:]), request.SHA256)
		if denied {
			w.WriteHeader(403)
			return
		}
		require.Equal(t, strings.Split(target, "?")[0], request.Path)
		require.NotContains(t, string(raw), "private-key")
		grant := map[string]any{}
		require.NoError(t, common.Unmarshal(raw, &grant))
		require.Contains(t, grant, "assignee_ref", "the real v2 request must send the default field that Core signs")
		if request.Operation != "model.keys.create" {
			require.Equal(t, "", grant["assignee_ref"])
		}
		grant["actor_ref"], grant["native_owner_id"], grant["account_label"], grant["account_kind"] = "11111111-1111-4111-8111-111111111111", 41, "Research lab", "org"
		grant["resource_scope"] = map[string]any{"kind": "all", "subject_ref": ""}
		grant["allowed_actions"] = []string{request.Operation}
		grant["allowed_update_fields"] = []string{"name"}
		grant["allowed_statuses"] = []int{2}
		if responseVersion == 1 {
			grant["schema_version"] = 1
			for _, field := range []string{"assignee_ref", "resource_scope", "allowed_actions", "allowed_update_fields", "allowed_statuses"} {
				delete(grant, field)
			}
		}
		now := time.Now().Unix()
		claims := jwt.MapClaims{"version": 1, "iss": "sai-portal", "aud": "sai-model-governance", "surface": "model-governance", "site": "fixture-site", "operations": []string{request.Operation}, "policy_epoch": 2, "jti": request.RequestID, "nbf": now, "exp": now + 15, "grant": grant}
		if mutate != nil {
			mutate(claims, grant)
		}
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
		token.Header["typ"], token.Header["kid"] = "SAI-CAPABILITY", "fixture"
		signed, err := token.SignedString(private)
		require.NoError(t, err)
		response, _ := common.Marshal(map[string]any{"schema_version": responseVersion, "capability": signed})
		_, _ = w.Write(response)
	}))
	defer server.Close()
	t.Setenv("MODEL_MANAGEMENT_AUTHORIZATION_URL", server.URL)
	request := func() *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(method, target, strings.NewReader(body))
		c.Request.Header.Set(ManagedWorkspaceHeader, "org:fixture")
		c.Set("id", 7)
		c.Set("session_id", "session-fixture")
		return c
	}
	c := request()
	require.NoError(t, AuthorizeManagedAccount(c, "model.keys.update"))
	require.Equal(t, 41, ManagementOwnerID(c))
	require.Equal(t, 7, c.GetInt("id"))
	denied = true
	require.ErrorIs(t, AuthorizeManagedAccount(request(), "model.keys.update"), ErrManagedAccountDenied)
	denied = false
	for _, test := range []struct {
		name   string
		change func(jwt.MapClaims, map[string]any)
	}{
		{"actor", func(_ jwt.MapClaims, g map[string]any) { g["native_actor_id"] = 8 }},
		{"session", func(_ jwt.MapClaims, g map[string]any) { g["session_id"] = "another-session" }},
		{"workspace", func(_ jwt.MapClaims, g map[string]any) { g["workspace_key"] = "org:other" }},
		{"body", func(_ jwt.MapClaims, g map[string]any) { g["request_sha256"] = "wrong" }},
		{"path", func(_ jwt.MapClaims, g map[string]any) { g["request_path"] = "/api/token/search" }},
		{"audience", func(c jwt.MapClaims, _ map[string]any) { c["aud"] = "other" }},
		{"operation", func(c jwt.MapClaims, _ map[string]any) { c["operations"] = []string{"model.keys.delete"} }},
		{"expired", func(c jwt.MapClaims, _ map[string]any) {
			c["nbf"] = time.Now().Unix() - 20
			c["exp"] = time.Now().Unix() - 5
		}},
		{"site", func(c jwt.MapClaims, _ map[string]any) { c["site"] = "other-site" }},
		{"revision", func(c jwt.MapClaims, _ map[string]any) { c["policy_epoch"] = 3 }},
		{"extra-claim", func(c jwt.MapClaims, _ map[string]any) { c["sub"] = "unrelated" }},
		{"wrong-subject", func(_ jwt.MapClaims, g map[string]any) {
			g["resource_scope"] = map[string]any{"kind": "subject", "subject_ref": "22222222-2222-4222-8222-222222222222"}
		}},
		{"missing-scope", func(_ jwt.MapClaims, g map[string]any) { delete(g, "resource_scope") }},
		{"subject-quota-permission", func(_ jwt.MapClaims, g map[string]any) {
			g["resource_scope"] = map[string]any{"kind": "subject", "subject_ref": g["actor_ref"]}
			g["allowed_update_fields"] = []string{"quota_delta"}
		}},
		{"subject-enable-permission", func(_ jwt.MapClaims, g map[string]any) {
			g["resource_scope"] = map[string]any{"kind": "subject", "subject_ref": g["actor_ref"]}
			g["allowed_statuses"] = []int{1}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutate = test.change
			require.Error(t, AuthorizeManagedAccount(request(), "model.keys.update"))
		})
	}
	require.Equal(t, 17, calls)
	before := calls
	pat := request()
	pat.Set("use_access_token", true)
	require.Error(t, AuthorizeManagedAccount(pat, "model.keys.update"))
	require.Equal(t, before, calls)
	mutate = nil
	responseVersion = 1
	require.Error(t, AuthorizeManagedAccount(request(), "model.keys.update"), "v2 must not accept a v1 response")
	responseVersion = 2

	member := func(_ jwt.MapClaims, grant map[string]any) {
		grant["resource_scope"] = map[string]any{"kind": "subject", "subject_ref": grant["actor_ref"]}
	}
	mutate = member
	c = request()
	require.NoError(t, AuthorizeManagedAccount(c, "model.keys.update"))
	require.Equal(t, 0, ManagementOwnerID(c), "legacy owner-wide readers must not receive a member capability")
	scope := ManagementResourceScope(c)
	require.Equal(t, 41, scope.OwnerID)
	require.True(t, scope.Restricted)
	require.True(t, scope.StrictBatch)
	require.Equal(t, "11111111-1111-4111-8111-111111111111", scope.SubjectRef)

	method, body = http.MethodGet, ""
	for _, selector := range []struct {
		value string
		valid bool
	}{{"11111111-1111-4111-8111-111111111111", true}, {"22222222-2222-4222-8222-222222222222", false}, {"not-a-subject", false}} {
		t.Run("member selector "+selector.value, func(t *testing.T) {
			target = "/api/token/?subject_ref=" + selector.value
			err := AuthorizeManagedAccount(request(), "model.keys.read")
			if selector.valid {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrManagedAccountDenied)
			}
		})
	}
	mutate = nil
	target = "/api/token/?subject_ref=22222222-2222-4222-8222-222222222222"
	c = request()
	require.NoError(t, AuthorizeManagedAccount(c, "model.keys.read"))
	require.Equal(t, "22222222-2222-4222-8222-222222222222", ManagementResourceScope(c).SubjectRef)
	require.True(t, ManagementResourceScope(c).Restricted, "an administrator selector narrows the all grant")
	method, target, body = http.MethodPost, "/api/token/", `{"name":"my device"}`
	mutate = member
	require.NoError(t, AuthorizeManagedAccount(request(), "model.keys.create"))
	body = `{"name":"my device","assignee_ref":"22222222-2222-4222-8222-222222222222"}`
	require.ErrorIs(t, AuthorizeManagedAccount(request(), "model.keys.create"), ErrManagedAccountDenied)
	mutate = nil
	require.NoError(t, AuthorizeManagedAccount(request(), "model.keys.create"), "an administrator can explicitly assign a member")
	body = `{"name":"missing member"}`
	require.ErrorIs(t, AuthorizeManagedAccount(request(), "model.keys.create"), ErrManagedAccountDenied)

	method, target, body = http.MethodGet, "/api/log/self/export", ""
	mutate = member
	c = request()
	require.NoError(t, AuthorizeManagedAccount(c, "model.usage.read"))
	before = calls
	require.NoError(t, RefreshManagedExportAuthorization(c))
	require.Equal(t, before, calls, "a current page capability needs no extra RPC")
	ManagementAccount(c).expiresAt = time.Now().Unix() - 1
	require.NoError(t, RefreshManagedExportAuthorization(c))
	require.Equal(t, before+1, calls)
	ManagementAccount(c).expiresAt = time.Now().Unix() - 1
	mutate = nil
	require.ErrorIs(t, RefreshManagedExportAuthorization(c), ErrManagedAccountDenied, "a role change must not widen a running export")
	mutate = member
	c = request()
	require.NoError(t, AuthorizeManagedAccount(c, "model.usage.read"))
	ManagementAccount(c).expiresAt = time.Now().Unix() - 1
	denied = true
	require.ErrorIs(t, RefreshManagedExportAuthorization(c), ErrManagedAccountDenied)
}

func TestManagedContextAttributionReadsOneExactPage(t *testing.T) {
	credential := t.TempDir() + "/credential"
	require.NoError(t, os.WriteFile(credential, []byte(strings.Repeat("x", 48)), 0600))
	t.Setenv("MODEL_BILLING_ADMISSION_KEY_FILE", credential)
	t.Setenv("MODEL_BILLING_INSTANCE_REF", "fixture-gateway")
	references := []ManagedContextReference{
		{TokenID: 3, ContextRef: "11111111-1111-4111-8111-111111111111"},
		{TokenID: 0, ContextRef: "22222222-2222-4222-8222-222222222222"},
		{TokenID: 0, ContextRef: "33333333-3333-4333-8333-333333333333"},
	}
	subject := "44444444-4444-4444-8444-444444444444"
	calls, mode := 0, "ready"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		require.Equal(t, "/v1/internal/models/key-attributions", r.URL.Path)
		require.Equal(t, "Bearer "+strings.Repeat("x", 48), r.Header.Get("Authorization"))
		var body map[string]any
		require.NoError(t, common.DecodeJson(r.Body, &body))
		require.Len(t, body, 7)
		require.EqualValues(t, 2, body["schema_version"])
		require.EqualValues(t, 7, body["native_actor_id"])
		require.EqualValues(t, 41, body["native_owner_id"])
		require.Len(t, body["tokens"], 3)
		for i, item := range body["tokens"].([]any) {
			entry := item.(map[string]any)
			require.Len(t, entry, 2)
			require.Equal(t, references[i].ContextRef, entry["billing_context_ref"])
			require.EqualValues(t, references[i].TokenID, entry["native_token_id"])
		}
		if mode == "denied" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		items := []map[string]any{}
		for _, ref := range references {
			items = append(items, map[string]any{"native_token_id": ref.TokenID, "billing_context_ref": ref.ContextRef, "managed_subject_ref": subject,
				"attribution": ManagedKeyAttribution{State: "ready", Actor: &ManagedKeyActor{DisplayName: "Current member", Username: "member"},
					Workspace: &ManagedKeyWorkspace{Kind: "project", Code: "proj-climate", Label: "Climate study"}}})
		}
		if strings.HasPrefix(mode, "unknown") {
			for _, item := range items {
				item["managed_subject_ref"] = ""
				item["attribution"] = ManagedKeyAttribution{State: "unknown"}
			}
			if mode == "unknown-creator" {
				items[0]["attribution"] = ManagedKeyAttribution{State: "unknown", Actor: &ManagedKeyActor{DisplayName: "Creator", Username: "creator"}}
			}
			if mode == "unknown-subject" {
				items[0]["managed_subject_ref"] = subject
			}
		}
		if mode == "mismatch" {
			items[0]["billing_context_ref"] = "55555555-5555-4555-8555-555555555555"
		}
		if mode == "wrong-token" {
			items[0]["native_token_id"] = 8
		}
		if mode == "wrong-subject" {
			items[0]["managed_subject_ref"] = "55555555-5555-4555-8555-555555555555"
		}
		if mode == "duplicate" {
			items[1] = items[0]
		}
		version := 2
		if mode == "v1" {
			version = 1
		}
		data, err := common.Marshal(map[string]any{"schema_version": version, "gateway_instance_ref": "fixture-gateway", "native_owner_id": 41, "items": items})
		require.NoError(t, err)
		_, _ = w.Write(data)
	}))
	defer server.Close()
	t.Setenv("MODEL_MANAGEMENT_AUTHORIZATION_URL", server.URL+"/v1/internal/models/authorize-management")
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/api/token/", nil)
	c.Set("managed_account", &ManagedAccount{OwnerID: 41, Kind: "org", ResourceScope: ManagedResourceGrant{Kind: "subject", SubjectRef: subject}, ManagementRequest: ManagementRequest{
		SchemaVersion: 2, Instance: "fixture-gateway", ActorID: 7, SessionID: "authenticated-session", WorkspaceKey: "org:fixture", Operation: "model.usage.read"}})
	rows, err := ReadManagedContextAttributions(c, references)
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	require.Len(t, rows, 3)
	require.Equal(t, "Current member", rows[references[0].ContextRef].Actor.DisplayName)
	require.Equal(t, "Climate study", rows[references[1].ContextRef].Workspace.Label)
	require.NotNil(t, rows[references[2].ContextRef], "two token0 contexts remain distinct")
	mode = "unknown"
	_, err = ReadManagedContextAttributions(c, references)
	require.ErrorIs(t, err, ErrManagedAccountDenied, "unknown assignment cannot authorize a member")
	ManagementAccount(c).ResourceScope = ManagedResourceGrant{Kind: "all"}
	rows, err = ReadManagedContextAttributions(c, references)
	require.NoError(t, err)
	for _, row := range rows {
		require.Equal(t, "unknown", row.State)
		require.Nil(t, row.Actor, "a legacy creator is not an assignee")
		require.Nil(t, row.Workspace)
	}
	for _, invalid := range []string{"unknown-creator", "unknown-subject"} {
		mode = invalid
		_, err = ReadManagedContextAttributions(c, references)
		require.ErrorIs(t, err, ErrManagedAccountDenied)
	}
	mode = "unknown"
	selected, _ := gin.CreateTestContext(httptest.NewRecorder())
	selected.Request = httptest.NewRequest("GET", "/api/token/?subject_ref="+subject, nil)
	selected.Set("managed_account", ManagementAccount(c))
	_, err = ReadManagedContextAttributions(selected, references)
	require.ErrorIs(t, err, ErrManagedAccountDenied, "a member selector cannot include an unknown assignment")
	ManagementAccount(c).ResourceScope = ManagedResourceGrant{Kind: "subject", SubjectRef: subject}
	for _, invalid := range []string{"mismatch", "wrong-token", "wrong-subject", "duplicate", "v1"} {
		t.Run(invalid, func(t *testing.T) {
			mode = invalid
			rows, err = ReadManagedContextAttributions(c, references)
			require.Error(t, err)
			require.Nil(t, rows)
		})
	}
	mode = "denied"
	_, err = ReadManagedContextAttributions(c, references)
	require.ErrorIs(t, err, ErrManagedAccountDenied)
	before := calls
	_, err = ReadManagedContextAttributions(c, []ManagedContextReference{references[0], references[0]})
	require.ErrorIs(t, err, ErrManagedAccountDenied)
	_, err = ReadManagedContextAttributions(c, nil)
	require.NoError(t, err)
	require.Equal(t, before, calls)
}

func TestManagedMemberCandidatesAcceptsFilteredScanCursor(t *testing.T) {
	credential := t.TempDir() + "/credential"
	require.NoError(t, os.WriteFile(credential, []byte(strings.Repeat("x", 48)), 0600))
	t.Setenv("MODEL_BILLING_ADMISSION_KEY_FILE", credential)
	t.Setenv("MODEL_BILLING_INSTANCE_REF", "fixture-gateway")
	after := "11111111-1111-4111-8111-111111111111"
	visible := ManagedMemberCandidate{SubjectRef: "22222222-2222-4222-8222-222222222222", DisplayName: "Member", Username: "member"}
	filteredCursor := "33333333-3333-4333-8333-333333333333"
	response := ManagedMemberCandidates{SchemaVersion: 2, Instance: "fixture-gateway", OwnerID: 41}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/internal/models/member-candidates", r.URL.Path)
		var request map[string]any
		require.NoError(t, common.DecodeJson(r.Body, &request))
		require.EqualValues(t, 2, request["schema_version"])
		require.Equal(t, after, request["after"])
		data, err := common.Marshal(response)
		require.NoError(t, err)
		_, _ = w.Write(data)
	}))
	defer server.Close()
	t.Setenv("MODEL_MANAGEMENT_AUTHORIZATION_URL", server.URL+"/v1/internal/models/authorize-management")
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/api/token/member-candidates", nil)
	c.Set("managed_account", &ManagedAccount{OwnerID: 41, ResourceScope: ManagedResourceGrant{Kind: "all"},
		AllowedActions: []string{"model.members.read"}, ManagementRequest: ManagementRequest{SchemaVersion: 2,
			Instance: "fixture-gateway", ActorID: 7, SessionID: "fixture-session", WorkspaceKey: "org:fixture", Operation: "model.members.read"}})
	for _, test := range []struct {
		name   string
		items  []ManagedMemberCandidate
		cursor string
		valid  bool
	}{
		{"filtered last principal", []ManagedMemberCandidate{visible}, filteredCursor, true},
		{"filtered entire page", []ManagedMemberCandidate{}, filteredCursor, true},
		{"end of directory", []ManagedMemberCandidate{}, "", true},
		{"unchanged cursor", []ManagedMemberCandidate{visible}, after, false},
		{"backward cursor", []ManagedMemberCandidate{visible}, "00000000-0000-4000-8000-000000000000", false},
		{"invalid cursor", []ManagedMemberCandidate{visible}, "not-a-principal", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			response.Items, response.NextCursor = test.items, test.cursor
			page, err := ReadManagedMemberCandidates(c, "", after, 50)
			if test.valid {
				require.NoError(t, err)
				require.Equal(t, test.items, page.Items)
				require.Equal(t, test.cursor, page.NextCursor)
			} else {
				require.Error(t, err)
				require.Nil(t, page)
			}
		})
	}
}
