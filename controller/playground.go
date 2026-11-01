package controller

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// PreparePlayground is an explicit control operation before entering the native
// playground. Inference itself never creates a billing binding or calls Portal.
func PreparePlayground(c *gin.Context) {
	if c.GetBool("use_access_token") || c.GetHeader(service.ManagedWorkspaceHeader) != "" || c.GetInt("id") <= 0 {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	if !service.ManagedModelMode(c) {
		common.ApiSuccess(c, gin.H{"ready": true})
		return
	}
	owner := c.GetInt("id")
	ref, err := model.GetPlaygroundBillingContext(owner)
	if err == nil && ref == nil {
		value := uuid.NewSHA1(uuid.NameSpaceOID, []byte(os.Getenv("MODEL_BILLING_INSTANCE_REF")+":"+strconv.Itoa(owner)+":playground")).String()
		ref = &value
	}
	if err == nil {
		err = service.RegisterModelKey(c, &model.Token{UserId: owner, BillingContextRef: ref})
	}
	if err == nil {
		err = model.BindPlaygroundBillingContext(owner, *ref)
	}
	if err != nil {
		common.ApiErrorStatus(c, http.StatusServiceUnavailable, common.NewMessage("Managed account access is unavailable"))
		return
	}
	current, err := model.GetUserCache(owner)
	if err != nil {
		common.ApiErrorStatus(c, http.StatusServiceUnavailable, common.NewMessage("Managed account access is unavailable"))
		return
	}
	common.ApiSuccess(c, gin.H{"ready": current.ModelExecutionRevision > 0 && current.ModelExecutionUntil > time.Now().Unix()})
}

func Playground(c *gin.Context) {
	var newAPIError *types.NewAPIError

	defer func() {
		if newAPIError != nil {
			c.JSON(newAPIError.StatusCode, gin.H{
				"error": newAPIError.ToOpenAIError(common.UpstreamAddresses(c)...),
			})
		}
	}()

	useAccessToken := c.GetBool("use_access_token")
	if useAccessToken {
		newAPIError = types.NewError(errors.New(i18n.T(c, i18n.MsgRelayAccessTokenUnsupported)), types.ErrorCodeAccessDenied, types.ErrOptionWithSkipRetry())
		return
	}

	relayInfo, err := relaycommon.GenRelayInfo(c, types.RelayFormatOpenAI, nil, nil)
	if err != nil {
		newAPIError = types.NewError(err, types.ErrorCodeInvalidRequest, types.ErrOptionWithSkipRetry())
		return
	}

	userId := c.GetInt("id")

	// Write user context to ensure acceptUnsetRatio is available
	userCache, err := model.GetUserCache(userId)
	if err != nil {
		newAPIError = types.NewError(err, types.ErrorCodeQueryDataError, types.ErrOptionWithSkipRetry())
		return
	}
	userCache.WriteContext(c)

	tempToken := &model.Token{
		UserId: userId,
		Name:   fmt.Sprintf("playground-%s", relayInfo.UsingGroup),
		Group:  relayInfo.UsingGroup,
	}
	if service.ManagedModelMode(c) {
		ref := c.GetString("playground_billing_context_ref")
		if ref == "" {
			newAPIError = types.NewErrorWithStatusCode(errors.New(i18n.T(c, "model.admission_unavailable")),
				types.ErrorCodeQueryDataError, http.StatusServiceUnavailable, types.ErrOptionWithSkipRetry())
			return
		}
		tempToken.BillingContextRef, tempToken.BillingContextConfirmed = &ref, true
	}
	_ = middleware.SetupContextForToken(c, tempToken)

	Relay(c, types.RelayFormatOpenAI)
}
