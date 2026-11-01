package service

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagedModelAdmissionUsesLocalProjectionAndFreezesRequestFacts(t *testing.T) {
	require.NoError(t, i18n.Init())
	t.Setenv("MODEL_BILLING_INSTANCE_REF", "test-gateway")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	t.Setenv("MODEL_MANAGEMENT_AUTHORIZATION_URL", server.URL+"/authorize")
	t.Setenv("MODEL_BILLING_ADMISSION_KEY_FILE", "/no-admission-credential-required")
	require.NoError(t, ValidateManagedModelConfig())
	started := time.Now().Add(-2 * time.Second)
	request := func() *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("POST", "/v1/responses", strings.NewReader(`{"prompt":"private"}`))
		c.Set("id", 7)
		c.Set("token_id", 43)
		c.Set("model_billing_context_ref", "11111111-1111-4111-8111-111111111111")
		c.Set("model_execution_revision", int64(1))
		c.Set("model_execution_until", time.Now().Add(time.Hour).Unix())
		c.Set("model_policy_epoch", "7")
		common.SetContextKey(c, constant.ContextKeyRequestStartTime, started)
		return c
	}
	c := request()
	require.Nil(t, AdmitManagedModel(c, "test-model", "request"))
	assert.Equal(t, "7", c.GetString("model_billing_policy_epoch"))
	assert.Equal(t, started.Unix(), c.GetInt64("model_billing_request_started_at"))
	c.Set("model_policy_epoch", "8")
	common.SetContextKey(c, constant.ContextKeyRequestStartTime, time.Now())
	require.Nil(t, AdmitManagedModel(c, "test-model", "request"))
	assert.Equal(t, "7", c.GetString("model_billing_policy_epoch"))
	assert.Equal(t, started.Unix(), c.GetInt64("model_billing_request_started_at"))

	expired := request()
	expired.Set("model_execution_until", time.Now().Add(-time.Second).Unix())
	denied := AdmitManagedModel(expired, "test-model", "request")
	require.NotNil(t, denied)
	assert.Equal(t, http.StatusForbidden, denied.StatusCode)
	missing := request()
	missing.Set("model_execution_revision", int64(0))
	require.Equal(t, http.StatusServiceUnavailable, AdmitManagedModel(missing, "test-model", "request").StatusCode)
	missing = request()
	missing.Set("model_billing_context_ref", "")
	require.Equal(t, http.StatusServiceUnavailable, AdmitManagedModel(missing, "test-model", "request").StatusCode)
	unsupported := request()
	unsupported.Request.URL.Path = "/v1/embeddings"
	denied = AdmitManagedModel(unsupported, "test-model", "request")
	require.NotNil(t, denied)
	assert.Equal(t, http.StatusBadRequest, denied.StatusCode)
	assert.True(t, types.IsSkipRetryError(denied))
	assert.Zero(t, calls.Load(), "admission and rejection must use no Portal or Native management RPC")
}

func TestManagedProtocolAndProductArePreparedLocally(t *testing.T) {
	require.NoError(t, i18n.Init())
	t.Setenv("MODEL_BILLING_INSTANCE_REF", "configured-instance")
	for _, test := range []struct{ path, kind, model, alias, product string }{
		{"/v1/chat/completions", "request", "chat-high", "chat", "chat"},
		{"/v1/responses", "request", "responses", "", "responses"},
		{"/v1/responses/compact", "request", "responses", "", "responses"},
		{"/v1/responses", "responses_ws", "responses", "", "responses"},
		{"/pg/chat/completions", "playground", "chat", "", "chat"},
		{"/v1/tools/search", "request", "deepseek-search", "", "deepseek-search"},
		{"/v1/tools/fetch", "request", "deepseek-fetch", "deepseek-fetch", "deepseek-fetch"},
		{"/v1/tools/search", "request", "other-model", "deepseek-search", ""},
		{"/v1/tools/fetch", "request", "deepseek-fetch", "other-model", ""},
		{"/v1/responses", "request", "deepseek-search", "other-model", ""},
		{"/v1/realtime", "realtime", "chat", "", ""},
		{"/v1/tasks", "task", "chat", "", ""},
	} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, test.path, nil)
		c.Set("model_billing_alias", test.alias)
		denied := PrepareManagedModelRequest(c, test.model, test.kind)
		if test.product == "" {
			require.NotNil(t, denied, "%+v", test)
			assert.True(t, types.IsSkipRetryError(denied))
		} else {
			require.Nil(t, denied, "%+v", test)
			assert.Equal(t, test.product, c.GetString("model_billing_product"))
		}
		assert.Empty(t, c.GetString("model_billing_context_ref"), "no remote billing receipt was needed")
	}
	for _, name := range []string{"MODEL_BILLING_INSTANCE_REF", "MODEL_BILLING_ADMISSION_KEY_FILE", "MANAGED_ACCOUNT_PROVISION_KEY_FILE", "OIDC_REQUIRE_PREPROVISIONED"} {
		t.Setenv(name, "")
	}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/embeddings", nil)
	require.Nil(t, PrepareManagedModelRequest(c, "embedding-model", "request"))
	require.Nil(t, ManagedResponsesBody(c, strings.NewReader(`{"background":true}`)))
	c.Set("managed_binding_ref", "11111111-1111-4111-8111-111111111111")
	require.NotNil(t, ManagedResponsesBody(c, strings.NewReader(`{"background":true}`)))
}
