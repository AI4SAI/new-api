package service

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var managedAdmissionClient = &http.Client{
	Timeout:       5 * time.Second,
	Transport:     &http.Transport{Proxy: nil, MaxIdleConns: 8, MaxIdleConnsPerHost: 8, IdleConnTimeout: 90 * time.Second},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func ValidateManagedModelAdmissionConfig() error {
	endpoint, keyFile, instance := os.Getenv("MODEL_BILLING_ADMISSION_URL"), os.Getenv("MODEL_BILLING_ADMISSION_KEY_FILE"), os.Getenv("MODEL_BILLING_INSTANCE_REF")
	provision := os.Getenv("MANAGED_ACCOUNT_PROVISION_KEY_FILE")
	if endpoint == "" && keyFile == "" && instance == "" && provision == "" && os.Getenv("OIDC_REQUIRE_PREPROVISIONED") != "true" {
		return nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || instance == "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()))) {
		return errors.New("managed model admission configuration is incomplete")
	}
	key, err := os.ReadFile(keyFile)
	if err != nil || len(strings.TrimSpace(string(key))) < 32 || keyFile == provision {
		return errors.New("managed model admission requires its own private credential")
	}
	return nil
}

// AdmitManagedModel asks the billing owner about this authenticated execution.
// No model key, prompt, browser-selected payer or cached funding decision is sent.
func AdmitManagedModel(c *gin.Context, modelName, kind string) *types.NewAPIError {
	endpoint := os.Getenv("MODEL_BILLING_ADMISSION_URL")
	if endpoint == "" {
		if os.Getenv("MANAGED_ACCOUNT_PROVISION_KEY_FILE") != "" || os.Getenv("MODEL_BILLING_INSTANCE_REF") != "" ||
			os.Getenv("OIDC_REQUIRE_PREPROVISIONED") == "true" || c.GetString("managed_binding_ref") != "" {
			return types.NewErrorWithStatusCode(errors.New(i18n.T(c, "model.admission_unavailable")), types.ErrorCodeInvalidRequest,
				http.StatusServiceUnavailable, types.ErrOptionWithSkipRetry())
		}
		return nil
	}
	failure := func(status int, message string) *types.NewAPIError {
		return types.NewErrorWithStatusCode(errors.New(message), types.ErrorCodeInvalidRequest, status, types.ErrOptionWithSkipRetry())
	}
	unavailable := func() *types.NewAPIError {
		return failure(http.StatusServiceUnavailable, i18n.T(c, "model.admission_unavailable"))
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()))) {
		return unavailable()
	}
	key, err := os.ReadFile(os.Getenv("MODEL_BILLING_ADMISSION_KEY_FILE"))
	secret := strings.TrimSpace(string(key))
	instance := os.Getenv("MODEL_BILLING_INSTANCE_REF")
	owner, token := c.GetInt("id"), c.GetInt("token_id")
	if err != nil || len(secret) < 32 || len(secret) > 512 || instance == "" || owner <= 0 || token < 0 || modelName == "" {
		return unavailable()
	}
	requestID := c.GetString(common.RequestIdKey)
	if requestID == "" {
		requestID = common.GetUUID()
		c.Set(common.RequestIdKey, requestID)
	}
	body, err := common.Marshal(map[string]any{"schema_version": 1, "gateway_instance_ref": instance,
		"native_owner_id": owner, "native_token_id": token, "managed_binding_ref": c.GetString("managed_binding_ref"),
		"model": modelName, "native_group": common.GetContextKeyString(c, constant.ContextKeyUsingGroup),
		"pricing_model": c.GetString("model_billing_alias"),
		"request_id":    requestID, "kind": kind, "request_path": c.Request.URL.Path})
	if err != nil {
		return unavailable()
	}
	request, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return unavailable()
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+secret)
	response, err := managedAdmissionClient.Do(request)
	if err != nil {
		return unavailable()
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden {
		return failure(http.StatusForbidden, i18n.T(c, "model.admission_denied"))
	}
	if response.StatusCode != http.StatusOK {
		return unavailable()
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(raw) > 4096 {
		return unavailable()
	}
	var result struct {
		SchemaVersion int    `json:"schema_version"`
		Instance      string `json:"gateway_instance_ref"`
		Owner         int    `json:"native_owner_id"`
		Token         int    `json:"native_token_id"`
		RequestID     string `json:"request_id"`
		Model         string `json:"model"`
		Product       string `json:"product_model"`
		Binding       string `json:"billing_context_ref"`
	}
	if common.Unmarshal(raw, &result) != nil || result.SchemaVersion != 1 || result.Instance != instance ||
		result.Owner != owner || result.Token != token || result.RequestID != requestID || result.Model != modelName ||
		result.Product == "" || (result.Product != modelName && result.Product != c.GetString("model_billing_alias")) {
		return unavailable()
	}
	ref, err := uuid.Parse(result.Binding)
	if err != nil || ref.String() != result.Binding {
		return unavailable()
	}
	c.Set("model_billing_context_ref", result.Binding)
	c.Set("model_billing_product", result.Product)
	return nil
}

// ManagedResponsesBody rejects a background execution whose final usage cannot
// be settled by the synchronous model product. Check the effective outbound body
// too: channel parameter overrides and passthrough must not bypass this boundary.
func ManagedResponsesBody(c *gin.Context, body io.Reader) *types.NewAPIError {
	if c.GetString("model_billing_context_ref") == "" {
		return nil
	}
	var request struct {
		Background bool `json:"background"`
	}
	if common.DecodeJson(body, &request) != nil || request.Background {
		return types.NewErrorWithStatusCode(errors.New(i18n.T(c, "model.background_unavailable")),
			types.ErrorCodeInvalidRequest, http.StatusBadRequest, types.ErrOptionWithSkipRetry())
	}
	return nil
}
