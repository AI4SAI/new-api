package relay

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"
	"github.com/QuantumNous/new-api/relay/helper"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// DeepSeekToolsHelper relays the DeepSeek Search and Fetch APIs like
// /v1/alpha/search: the raw body is forwarded, the response is returned
// unchanged, and the call is billed at the routing name's request price with
// no tokens.
func DeepSeekToolsHelper(c *gin.Context, info *relaycommon.RelayInfo) (newAPIError *types.NewAPIError) {
	info.InitChannelMeta(c)

	switch info.ChannelType {
	case constant.ChannelTypeDeepSeek,
		constant.ChannelTypeNewAPI,
		constant.ChannelTypeSub2API,
		constant.ChannelTypeAdvancedCustom:
	default:
		// Allow retry onto another channel that may support this endpoint.
		return types.NewError(
			fmt.Errorf("channel does not support %s", c.Request.URL.Path),
			types.ErrorCodeInvalidRequest,
		)
	}

	request, ok := info.Request.(*dto.DeepSeekToolsRequest)
	if !ok {
		return types.NewErrorWithStatusCode(
			fmt.Errorf("invalid request type, expected *dto.DeepSeekToolsRequest, got %T", info.Request),
			types.ErrorCodeInvalidRequest,
			http.StatusBadRequest,
			types.ErrOptionWithSkipRetry(),
		)
	}

	err := helper.ModelMappedHelper(c, info, request)
	if err != nil {
		return types.NewError(err, types.ErrorCodeChannelModelMappedError, types.ErrOptionWithSkipRetry())
	}

	jsonData, err := buildAlphaSearchRequestBody(request.RawBody, info.OriginModelName, info.UpstreamModelName)
	if err != nil {
		return types.NewError(err, types.ErrorCodeConvertRequestFailed, types.ErrOptionWithSkipRetry())
	}

	if len(info.ParamOverride) > 0 {
		jsonData, err = relaycommon.ApplyParamOverrideWithRelayInfo(jsonData, info)
		if err != nil {
			return newAPIErrorFromParamOverride(err)
		}
	}
	var fetchURL, displayFetchURL string
	var redactError func(string) string
	if info.RelayMode == relayconstant.RelayModeToolsFetch {
		fetchURL, displayFetchURL = deepSeekFetchTarget(jsonData)
		if fetchURL != "" && displayFetchURL != fetchURL {
			errorTarget := displayFetchURL
			if errorTarget == "" {
				errorTarget = "[redacted URL]"
			}
			raw, _ := common.Marshal(fetchURL)
			display, _ := common.Marshal(errorTarget)
			redactError = strings.NewReplacer(string(raw[1:len(raw)-1]), string(display[1:len(display)-1]),
				fetchURL, errorTarget).Replace
		}
	}

	body, closer, err := relaycommon.NewOutboundJSONBody(jsonData)
	if err != nil {
		return types.NewError(err, types.ErrorCodeConvertRequestFailed, types.ErrOptionWithSkipRetry())
	}
	defer closer.Close()

	adaptor := GetAdaptor(info.ApiType)
	if adaptor == nil {
		return types.NewError(fmt.Errorf("invalid api type: %d", info.ApiType), types.ErrorCodeInvalidApiType, types.ErrOptionWithSkipRetry())
	}
	adaptor.Init(info)

	resp, err := adaptor.DoRequest(c, info, body)
	if err != nil {
		return types.NewOpenAIError(err, types.ErrorCodeDoRequestFailed, http.StatusInternalServerError)
	}

	statusCodeMappingStr := c.GetString("status_code_mapping")
	httpResp, ok := resp.(*http.Response)
	if !ok || httpResp == nil {
		return types.NewOpenAIError(errors.New("invalid http response"), types.ErrorCodeDoRequestFailed, http.StatusInternalServerError)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		newAPIError = service.RelayErrorHandler(c.Request.Context(), httpResp, false, redactError)
		service.ResetStatusCode(newAPIError, statusCodeMappingStr)
		return newAPIError
	}

	responseBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return types.NewOpenAIError(err, types.ErrorCodeReadResponseBodyFailed, http.StatusInternalServerError, types.ErrOptionWithSkipRetry())
	}
	service.IOCopyBytesGracefully(c, httpResp, responseBody)

	// DeepSeek bills a successful request only when it returns something: a
	// non-empty results array for Search, page content for Fetch. A billable
	// call settles at the routing name's request price; any other response
	// releases the reservation.
	var billable bool
	content := gjson.GetBytes(responseBody, "content")
	if httpResp.StatusCode == http.StatusOK && utf8.Valid(responseBody) && gjson.ValidBytes(responseBody) {
		switch info.RelayMode {
		case relayconstant.RelayModeToolsFetch:
			billable = content.Type == gjson.String && utf8.ValidString(content.Str) && content.Str != ""
		default:
			results := gjson.GetBytes(responseBody, "results")
			billable = results.IsArray() && len(results.Array()) > 0
		}
	}
	if !billable {
		if info.Billing != nil {
			info.Billing.Refund(c)
		}
		return nil
	}

	if info.RelayMode == relayconstant.RelayModeToolsSearch {
		// Record the effective outbound values after channel overrides, never the
		// raw request or original question. Missing optional fields use API defaults.
		var requestFields struct {
			Query       string `json:"query"`
			Count       *int   `json:"count"`
			NeedContent bool   `json:"need_content"`
		}
		if utf8.Valid(jsonData) && common.Unmarshal(jsonData, &requestFields) == nil && utf8.ValidString(requestFields.Query) &&
			strings.TrimSpace(requestFields.Query) != "" && utf8.RuneCountInString(requestFields.Query) <= 128 {
			count := 10
			if requestFields.Count != nil {
				count = *requestFields.Count
			}
			if count >= 1 && count <= 50 {
				info.SearchRequest = &relaycommon.DirectSearchLog{Query: requestFields.Query, Count: count,
					NeedContent: requestFields.NeedContent,
					ResultCount: len(gjson.GetBytes(responseBody, "results").Array()), Outcome: "success"}
			}
		}
	}
	if info.OriginModelName == constant.DeepSeekFetchModel && displayFetchURL != "" {
		info.FetchRequest = &relaycommon.DirectFetchLog{URL: displayFetchURL, URLRedacted: displayFetchURL != fetchURL,
			ContentBytes: len(content.Str), Outcome: "success"}
	}
	service.PostTextConsumeQuota(c, info, &dto.Usage{}, nil)
	return nil
}

// deepSeekFetchTarget supplies the same safe URL to usage metadata and errors.
// It never changes the request sent to the provider.
func deepSeekFetchTarget(body []byte) (rawURL, displayURL string) {
	var fields struct {
		URL string `json:"url"`
	}
	if common.Unmarshal(body, &fields) != nil {
		return "", ""
	}
	if !utf8.Valid(body) || !utf8.ValidString(fields.URL) || utf8.RuneCountInString(fields.URL) > 8192 {
		return fields.URL, ""
	}
	target, err := url.Parse(fields.URL)
	if err != nil || target.Hostname() == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return fields.URL, ""
	}
	// Preserve Unicode and encoded separators in the original path.
	displayURL = fields.URL
	if end := strings.IndexAny(displayURL, "?#"); end >= 0 {
		displayURL = displayURL[:end]
	}
	if target.User != nil {
		start := strings.Index(displayURL, "://") + 3
		authority, _, _ := strings.Cut(displayURL[start:], "/")
		displayURL = displayURL[:start] + displayURL[start+strings.LastIndexByte(authority, '@')+1:]
	}
	return fields.URL, displayURL
}
