package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		require.Equal(t, "Bearer "+strings.Repeat("x", 48), r.Header.Get("Authorization"))
		var request ManagementRequest
		require.NoError(t, common.DecodeJson(r.Body, &request))
		require.Equal(t, 7, request.ActorID)
		require.Equal(t, "session-fixture", request.SessionID)
		digest := sha256.Sum256([]byte("PUT\n/api/token/?status_only=true&token=private-key\n{\"id\":42,\"status\":2}"))
		require.Equal(t, hex.EncodeToString(digest[:]), request.SHA256)
		if denied {
			w.WriteHeader(403)
			return
		}
		raw, _ := common.Marshal(request)
		require.Equal(t, "/api/token/", request.Path)
		require.NotContains(t, string(raw), "private-key")
		grant := map[string]any{}
		require.NoError(t, common.Unmarshal(raw, &grant))
		grant["actor_ref"], grant["native_owner_id"], grant["account_label"], grant["account_kind"] = "actor-fixture", 41, "Research lab", "org"
		now := time.Now().Unix()
		claims := jwt.MapClaims{"version": 1, "iss": "sai-portal", "aud": "sai-model-governance", "surface": "model-governance", "site": "fixture-site", "operations": []string{request.Operation}, "policy_epoch": 2, "jti": request.RequestID, "nbf": now, "exp": now + 15, "grant": grant}
		if mutate != nil {
			mutate(claims, grant)
		}
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
		token.Header["typ"], token.Header["kid"] = "SAI-CAPABILITY", "fixture"
		signed, err := token.SignedString(private)
		require.NoError(t, err)
		response, _ := common.Marshal(map[string]any{"schema_version": 1, "capability": signed})
		_, _ = w.Write(response)
	}))
	defer server.Close()
	t.Setenv("MODEL_MANAGEMENT_AUTHORIZATION_URL", server.URL)
	request := func() *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("PUT", "/api/token/?status_only=true&token=private-key", strings.NewReader(`{"id":42,"status":2}`))
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
	} {
		t.Run(test.name, func(t *testing.T) {
			mutate = test.change
			require.Error(t, AuthorizeManagedAccount(request(), "model.keys.update"))
		})
	}
	require.Equal(t, 13, calls)
	before := calls
	pat := request()
	pat.Set("use_access_token", true)
	require.Error(t, AuthorizeManagedAccount(pat, "model.keys.update"))
	require.Equal(t, before, calls)
}
