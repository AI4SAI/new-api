package service

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ManagedModelMode comes from the configured service or a persisted binding,
// never an HTTP admission response or a browser-selected payer.
func ManagedModelMode(c *gin.Context) bool {
	if c.GetBool("managed_model_mode") {
		return true
	}
	managed := os.Getenv("MODEL_BILLING_INSTANCE_REF") != "" || os.Getenv("MANAGED_ACCOUNT_PROVISION_KEY_FILE") != "" ||
		os.Getenv("OIDC_REQUIRE_PREPROVISIONED") == "true" || c.GetString("managed_binding_ref") != "" ||
		c.GetString("model_billing_context_ref") != ""
	c.Set("managed_model_mode", managed)
	return managed
}

// PrepareManagedModelRequest owns protocol/product limits locally.
// Native quota preconsumption remains the funding authority for execution.
func PrepareManagedModelRequest(c *gin.Context, modelName, kind string) *types.NewAPIError {
	if !ManagedModelMode(c) {
		return nil
	}
	allowed, webProduct := false, ""
	switch c.Request.URL.Path {
	case "/v1/chat/completions":
		allowed = kind == "request"
	case "/v1/responses":
		allowed = kind == "request" || kind == "responses_ws"
	case "/v1/responses/compact":
		allowed = kind == "request"
	case "/pg/chat/completions":
		allowed = kind == "playground"
	case "/v1/tools/search":
		allowed, webProduct = kind == "request", "deepseek-search"
	case "/v1/tools/fetch":
		allowed, webProduct = kind == "request", "deepseek-fetch"
	}
	product := c.GetString("model_billing_alias")
	if product == "" {
		product = modelName
	}
	if !allowed || modelName == "" || (webProduct != "" && (modelName != webProduct || product != webProduct)) ||
		(webProduct == "" && (product == "deepseek-search" || product == "deepseek-fetch" ||
			modelName == "deepseek-search" || modelName == "deepseek-fetch")) {
		return types.NewErrorWithStatusCode(errors.New(i18n.T(c, "model.protocol_unavailable")), types.ErrorCodeInvalidRequest,
			http.StatusBadRequest, types.ErrOptionWithSkipRetry())
	}
	c.Set("model_billing_product", product)
	return nil
}

func ValidateManagedModelConfig() error {
	if os.Getenv("MODEL_BILLING_INSTANCE_REF") == "" && (os.Getenv("MANAGED_ACCOUNT_PROVISION_KEY_FILE") != "" ||
		os.Getenv("OIDC_REQUIRE_PREPROVISIONED") == "true") {
		return errors.New("managed model instance reference is required")
	}
	return nil
}

// AdmitManagedModel reads the token and owner projection already checked by
// native authentication. It performs no network or database operation.
func AdmitManagedModel(c *gin.Context, modelName, kind string) *types.NewAPIError {
	if denied := PrepareManagedModelRequest(c, modelName, kind); denied != nil {
		return denied
	}
	if !ManagedModelMode(c) {
		return nil
	}
	if c.GetString("model_billing_policy_epoch") != "" {
		return nil // Retain the accepted facts through retries of this request.
	}
	ref := c.GetString("model_billing_context_ref")
	parsed, refErr := uuid.Parse(ref)
	epoch := c.GetString("model_policy_epoch")
	policy, epochErr := strconv.ParseInt(epoch, 10, 64)
	started := common.GetContextKeyTime(c, constant.ContextKeyRequestStartTime)
	if c.GetInt("id") <= 0 || refErr != nil || parsed.String() != ref || c.GetInt64("model_execution_revision") <= 0 ||
		epochErr != nil || policy <= 0 || strconv.FormatInt(policy, 10) != epoch || started.IsZero() {
		return types.NewErrorWithStatusCode(errors.New(i18n.T(c, "model.admission_unavailable")),
			types.ErrorCodeInvalidRequest, http.StatusServiceUnavailable, types.ErrOptionWithSkipRetry())
	}
	if c.GetInt64("model_execution_until") <= time.Now().Unix() {
		return types.NewErrorWithStatusCode(errors.New(i18n.T(c, "model.admission_denied")),
			types.ErrorCodeInvalidRequest, http.StatusForbidden, types.ErrOptionWithSkipRetry())
	}
	c.Set("model_billing_policy_epoch", epoch)
	c.Set("model_billing_request_started_at", started.Unix())
	return nil
}

// ManagedResponsesBody checks the final outbound request, including channel
// overrides and passthrough, independently of any external service response.
func ManagedResponsesBody(c *gin.Context, body io.Reader) *types.NewAPIError {
	if !ManagedModelMode(c) {
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
