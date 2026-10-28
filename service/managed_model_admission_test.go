package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/i18n"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagedModelAdmissionRechecksAndBindsNativeIdentity(t *testing.T) {
	require.NoError(t, i18n.Init())
	keyFile := t.TempDir() + "/admission"
	key := strings.Repeat("a", 48)
	require.NoError(t, os.WriteFile(keyFile, []byte(key), 0600))
	t.Setenv("MODEL_BILLING_ADMISSION_KEY_FILE", keyFile)
	t.Setenv("MODEL_BILLING_INSTANCE_REF", "test-gateway")
	status, mismatch, calls := 200, false, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer "+key, r.Header.Get("Authorization"))
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.NotContains(t, body, "prompt")
		assert.Equal(t, float64(7), body["native_owner_id"])
		assert.Equal(t, float64(43), body["native_token_id"])
		assert.Equal(t, "test-model", body["model"])
		if status != 200 {
			w.WriteHeader(status)
			return
		}
		if mismatch {
			body["native_owner_id"] = 8
		}
		body["billing_context_ref"] = "11111111-1111-4111-8111-111111111111"
		body["product_model"] = body["model"]
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()
	t.Setenv("MODEL_BILLING_ADMISSION_URL", server.URL+"/admit")
	request := func() *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("POST", "/v1/responses", strings.NewReader(`{"prompt":"private"}`))
		c.Set("id", 7)
		c.Set("token_id", 43)
		return c
	}
	c := request()
	require.Nil(t, AdmitManagedModel(c, "test-model", "request"))
	assert.Equal(t, "11111111-1111-4111-8111-111111111111", c.GetString("model_billing_context_ref"))
	status = 403
	denied := AdmitManagedModel(request(), "test-model", "request")
	require.NotNil(t, denied)
	assert.Equal(t, 403, denied.StatusCode)
	status, mismatch = 200, true
	denied = AdmitManagedModel(request(), "test-model", "request")
	require.NotNil(t, denied)
	assert.Equal(t, 503, denied.StatusCode)
	status, mismatch = 503, false
	require.NotNil(t, AdmitManagedModel(request(), "test-model", "request"))
	assert.Equal(t, 4, calls)
}
