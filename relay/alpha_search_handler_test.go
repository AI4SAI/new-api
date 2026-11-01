package relay

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/pkg/billingexpr"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relay/helper"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/model_setting"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildAlphaSearchRequestBodyPreservesUnknownFields(t *testing.T) {
	raw := []byte(`{
		"id":"req_1",
		"model":"gpt-5.1",
		"input":[{"role":"user","content":"hi"}],
		"commands":{"search_query":[{"q":"weather","recency":1}]},
		"settings":{"locale":"en"},
		"future_field":{"nested":true}
	}`)

	out, err := buildAlphaSearchRequestBody(raw, "gpt-5.1", "gpt-5.1-mapped")
	require.NoError(t, err)

	var body map[string]any
	require.NoError(t, common.Unmarshal(out, &body))
	assert.Equal(t, "gpt-5.1-mapped", body["model"])
	assert.Equal(t, "req_1", body["id"])
	require.Contains(t, body, "commands")
	require.Contains(t, body, "settings")
	require.Contains(t, body, "future_field")
	require.Contains(t, body, "input")

	commands, ok := body["commands"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, commands, "search_query")

	future, ok := body["future_field"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, future["nested"])
}

func TestBuildAlphaSearchRequestBodyNoMappingKeepsRawBytes(t *testing.T) {
	raw := []byte(`{"model":"gpt-5.1","commands":{"search_query":[{"q":"x"}]},"future_field":1}`)
	out, err := buildAlphaSearchRequestBody(raw, "gpt-5.1", "gpt-5.1")
	require.NoError(t, err)
	assert.Equal(t, raw, out)
}

type recordedSettlement struct {
	settled  []int
	refunded bool
}

func (s *recordedSettlement) Settle(quota int) error {
	s.settled = append(s.settled, quota)
	return nil
}
func (s *recordedSettlement) Refund(*gin.Context)    { s.refunded = true }
func (*recordedSettlement) NeedsRefund() bool        { return false }
func (*recordedSettlement) GetPreConsumedQuota() int { return 0 }
func (*recordedSettlement) Reserve(int) error        { return nil }

// /v1/tools/search and /v1/tools/fetch follow /v1/alpha/search: the raw body
// reaches /v1/tools/* unchanged and the response returns unchanged. With only
// the built-in prices, a response DeepSeek bills (results, page content)
// settles one call at the routing name's request price and no tokens, an
// empty one releases the reservation, an upstream error keeps its status, and
// a channel that cannot relay the endpoint fails retryably without sending
// anything.
func TestDeepSeekToolsHelper(t *testing.T) {
	service.InitHttpClient()
	gin.SetMode(gin.TestMode)
	batch, logConsume := common.BatchUpdateEnabled, common.LogConsumeEnabled
	common.BatchUpdateEnabled, common.LogConsumeEnabled = true, false
	t.Cleanup(func() { common.BatchUpdateEnabled, common.LogConsumeEnabled = batch, logConsume })
	grok := model_setting.GetGrokSettings()
	previousGrok := *grok
	grok.ViolationDeductionEnabled, grok.ViolationDeductionAmount = true, 0.05
	t.Cleanup(func() { *grok = previousGrok })

	const search, fetch = "/v1/tools/search", "/v1/tools/fetch"
	const results = `{"results":[{"title":"DeepSeek","url":"https://deepseek.com/","rerank_score":2.1}]}`
	tests := []struct {
		name, path, body, response string
		channelType, status        int
		settled                    []int
		refunded                   bool
		searchLog                  *relaycommon.DirectSearchLog
		fetchLog                   *relaycommon.DirectFetchLog
		override                   map[string]any
		errorMessage               string
	}{
		{name: "search with results", path: search, body: `{"query":"deepseek site:example.com","count":2,"need_content":true,"ori_question":"private original prompt","headers":{"Authorization":"private credential"},"future_field":{"nested":true}}`,
			response: results, channelType: constant.ChannelTypeDeepSeek, status: http.StatusOK, settled: []int{375},
			searchLog: &relaycommon.DirectSearchLog{Query: "deepseek site:example.com", Count: 2, NeedContent: true, ResultCount: 1, Outcome: "success"}},
		{name: "search without results", path: search, body: `{"query":"site:none.invalid deepseek"}`,
			response: `{"results":[]}`, channelType: constant.ChannelTypeDeepSeek, status: http.StatusOK, refunded: true},
		{name: "fetch with page content", path: fetch, body: `{"url":"https://example.com/"}`,
			response: `{"title":"Example Domain","content":"# Example Domain"}`, channelType: constant.ChannelTypeDeepSeek, status: http.StatusOK, settled: []int{375},
			fetchLog: &relaycommon.DirectFetchLog{URL: "https://example.com/", ContentBytes: 16, Outcome: "success"}},
		{name: "fetch metadata follows effective redacted URL", path: fetch, body: `{"url":"https://example.com/original"}`,
			response: `{"title":"private title","content":"正文"}`, channelType: constant.ChannelTypeDeepSeek, status: http.StatusOK, settled: []int{375},
			override: map[string]any{"url": "https://user:private-password@example.com/article?signature=private-signature#private-fragment"},
			fetchLog: &relaycommon.DirectFetchLog{URL: "https://example.com/article", URLRedacted: true, ContentBytes: 6, Outcome: "success"}},
		{name: "fetch empty URL delimiters are redacted", path: fetch, body: `{"url":"https://example.com/article?#"}`,
			response: `{"title":"","content":"text"}`, channelType: constant.ChannelTypeDeepSeek, status: http.StatusOK, settled: []int{375},
			fetchLog: &relaycommon.DirectFetchLog{URL: "https://example.com/article", URLRedacted: true, ContentBytes: 4, Outcome: "success"}},
		{name: "fetch preserves Unicode and encoded path separators", path: fetch, body: `{"url":"https://example.com/文献/a%2Fb%3Fc?signature=private-signature"}`,
			response: `{"title":"","content":"正文"}`, channelType: constant.ChannelTypeDeepSeek, status: http.StatusOK, settled: []int{375},
			fetchLog: &relaycommon.DirectFetchLog{URL: "https://example.com/文献/a%2Fb%3Fc", URLRedacted: true, ContentBytes: 6, Outcome: "success"}},
		{name: "fetch invalid display URL does not change upstream charge", path: fetch, body: `{"url":"not a URL"}`,
			response: `{"title":"","content":"text"}`, channelType: constant.ChannelTypeDeepSeek, status: http.StatusOK, settled: []int{375}},
		{name: "fetch invalid UTF-8 URL is not repaired into metadata", path: fetch, body: "{\"url\":\"https://example.com/\xff\"}",
			response: `{"title":"","content":"text"}`, channelType: constant.ChannelTypeDeepSeek, status: http.StatusOK, settled: []int{375}},
		{name: "fetch without content", path: fetch, body: `{"url":"https://example.com/"}`,
			response: `{"title":"Example Domain","content":""}`, channelType: constant.ChannelTypeDeepSeek, status: http.StatusOK, refunded: true},
		{name: "fetch non-string content is not a billable page", path: fetch, body: `{"url":"https://example.com/"}`,
			response: `{"content":{"error":"unavailable"}}`, channelType: constant.ChannelTypeDeepSeek, status: http.StatusOK, refunded: true},
		{name: "fetch malformed response is not billable", path: fetch, body: `{"url":"https://example.com/"}`,
			response: `{"content":"unfinished"`, channelType: constant.ChannelTypeDeepSeek, status: http.StatusOK, refunded: true},
		{name: "fetch invalid UTF-8 response is not billable", path: fetch, body: `{"url":"https://example.com/"}`,
			response: "{\"content\":\"\xff\"}", channelType: constant.ChannelTypeDeepSeek, status: http.StatusOK, refunded: true},
		{name: "fetch non-200 success is not billable", path: fetch, body: `{"url":"https://example.com/"}`,
			response: `{"content":"page"}`, channelType: constant.ChannelTypeDeepSeek, status: http.StatusCreated, refunded: true},
		{name: "search non-200 success is not billable", path: search, body: `{"query":"deepseek"}`,
			response: results, channelType: constant.ChannelTypeDeepSeek, status: http.StatusCreated, refunded: true},
		{name: "fetch failure keeps its status", path: fetch, body: `{"url":"https://example.com/missing"}`,
			response:    `{"error":{"message":"failed to fetch URL","type":"not_found_error","param":null,"code":"invalid_request_error"}}`,
			channelType: constant.ChannelTypeDeepSeek, status: http.StatusNotFound, refunded: true},
		{name: "fetch safety refusal never incurs Grok fee", path: fetch, body: `{"url":"https://example.com/"}`,
			response:    `{"error":{"message":"Content violates usage guidelines","type":"invalid_request_error","code":"invalid_request_error"}}`,
			channelType: constant.ChannelTypeDeepSeek, status: http.StatusForbidden, refunded: true},
		{name: "search safety refusal never incurs Grok fee", path: search, body: `{"query":"deepseek"}`,
			response:    `{"error":{"message":"Failed check: SAFETY_CHECK_TYPE","type":"invalid_request_error","code":"invalid_request_error"}}`,
			channelType: constant.ChannelTypeDeepSeek, status: http.StatusForbidden, refunded: true},
		{name: "fetch rate limit refunds", path: fetch, body: `{"url":"https://example.com/"}`,
			response:    `{"error":{"message":"rate limited","type":"rate_limit_error"}}`,
			channelType: constant.ChannelTypeDeepSeek, status: http.StatusTooManyRequests, refunded: true},
		{name: "fetch timeout refunds", path: fetch, body: `{"url":"https://example.com/"}`,
			response:    `{"error":{"message":"timed out","type":"timeout_error"}}`,
			channelType: constant.ChannelTypeDeepSeek, status: http.StatusGatewayTimeout, refunded: true},
		{name: "fetch redacts JSON escaped target in error message", path: fetch,
			body:        `{"url":"https://example.com/private?q=\"private-signature\"#private-fragment"}`,
			response:    `{"error":{"message":"failed https:\/\/example.com\/private?q=\"private-signature\"#private-fragment","type":"invalid_request_error"}}`,
			channelType: constant.ChannelTypeDeepSeek, status: http.StatusNotFound, refunded: true, errorMessage: "failed https://example.com/private"},
		{name: "fetch redacts target before invalid JSON debug log", path: fetch,
			body:        `{"url":"https://user:private-password@example.com/private?signature=private-signature#private-fragment"}`,
			response:    `invalid upstream body for https://user:private-password@example.com/private?signature=private-signature#private-fragment`,
			channelType: constant.ChannelTypeDeepSeek, status: http.StatusBadGateway, refunded: true, errorMessage: "bad response status code 502"},
		{name: "fetch malformed escaped target stays out of debug logs", path: fetch,
			body:        `{"url":"https://example.com/private?signature=private-signature"}`,
			response:    `broken https:\/\/example.com\/private\u003fsignature=private-signature`,
			channelType: constant.ChannelTypeDeepSeek, status: http.StatusBadGateway, refunded: true, errorMessage: "bad response status code 502"},
		{name: "fetch invalid target is still private on error", path: fetch,
			body:        `{"url":"https://example.com/%ZZ?signature=private-signature"}`,
			response:    `{"error":{"message":"invalid URL https://example.com/%ZZ?signature=private-signature","type":"invalid_request_error"}}`,
			channelType: constant.ChannelTypeDeepSeek, status: http.StatusBadRequest, refunded: true, errorMessage: "invalid URL [redacted URL]"},
		{name: "search through a New API channel", path: search, body: `{"query":"deepseek"}`,
			response: results, channelType: constant.ChannelTypeNewAPI, status: http.StatusOK, settled: []int{375},
			searchLog: &relaycommon.DirectSearchLog{Query: "deepseek", Count: 10, ResultCount: 1, Outcome: "success"}},
		{name: "search metadata follows effective override", path: search, body: `{"query":"original","count":2,"need_content":true}`,
			response: results, channelType: constant.ChannelTypeDeepSeek, status: http.StatusOK, settled: []int{375},
			override:  map[string]any{"query": "资料 after:2026-01-01", "count": 4, "need_content": false},
			searchLog: &relaycommon.DirectSearchLog{Query: "资料 after:2026-01-01", Count: 4, ResultCount: 1, Outcome: "success"}},
		{name: "invalid metadata does not change upstream billing", path: search, body: `{"query":"deepseek","count":51}`,
			response: results, channelType: constant.ChannelTypeDeepSeek, status: http.StatusOK, settled: []int{375}},
		{name: "channel without the endpoint", path: search, body: `{"query":"deepseek"}`, channelType: constant.ChannelTypeOpenAI},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			common.LogWriterMu.Lock()
			previousWriter, previousDebug := gin.DefaultErrorWriter, common.DebugEnabled
			gin.DefaultErrorWriter, common.DebugEnabled = &logs, true
			common.LogWriterMu.Unlock()
			t.Cleanup(func() {
				common.LogWriterMu.Lock()
				gin.DefaultErrorWriter, common.DebugEnabled = previousWriter, previousDebug
				common.LogWriterMu.Unlock()
			})
			var gotPath string
			var gotBody []byte
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotBody, _ = io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.response)
			}))
			t.Cleanup(upstream.Close)
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			c.Request.Header.Set("Content-Type", "application/json")
			routingName := map[string]string{search: constant.DeepSeekSearchModel, fetch: constant.DeepSeekFetchModel}[tc.path]
			common.SetContextKey(c, constant.ContextKeyOriginalModel, routingName)
			common.SetContextKey(c, constant.ContextKeyUsingGroup, "default")
			common.SetContextKey(c, constant.ContextKeyUserGroup, "default")
			common.SetContextKey(c, constant.ContextKeyChannelType, tc.channelType)
			common.SetContextKey(c, constant.ContextKeyChannelBaseUrl, upstream.URL)
			common.SetContextKey(c, constant.ContextKeyChannelKey, "sk-test")
			common.SetContextKey(c, constant.ContextKeyChannelParamOverride, tc.override)

			request, err := helper.GetAndValidateRequest(c, types.RelayFormatDeepSeekTools)
			require.NoError(t, err)
			info, err := relaycommon.GenRelayInfo(c, types.RelayFormatDeepSeekTools, request, nil)
			require.NoError(t, err)
			info.BillingRequestInput = &billingexpr.RequestInput{Body: []byte(tc.body)}
			_, err = helper.ModelPriceHelper(c, info, 0, request.GetTokenCountMeta())
			require.NoError(t, err, "the routing name is priced out of the box")
			settlement := &recordedSettlement{}
			info.Billing = settlement
			info.SearchRequest = &relaycommon.DirectSearchLog{Query: "previous attempt", Outcome: "success"}
			info.FetchRequest = &relaycommon.DirectFetchLog{URL: "https://example.com/previous", ContentBytes: 99, Outcome: "success"}

			apiErr := DeepSeekToolsHelper(c, info)
			if tc.status == 0 {
				require.NotNil(t, apiErr)
				assert.False(t, types.IsSkipRetryError(apiErr))
				assert.Empty(t, gotPath)
				return
			}
			apiErr = RefundFailedRequestBilling(c, info, apiErr)
			for _, excluded := range []string{"private-password", "private-signature", "private-fragment"} {
				assert.NotContains(t, logs.String(), excluded)
				if apiErr != nil {
					assert.NotContains(t, apiErr.Error(), excluded)
					assert.NotContains(t, apiErr.MaskSensitiveErrorWithStatusCode(), excluded)
				}
			}
			if tc.errorMessage != "" {
				require.NotNil(t, apiErr)
				assert.Equal(t, tc.errorMessage, apiErr.Error())
			}
			assert.Equal(t, tc.path, gotPath)
			if tc.override == nil {
				assert.Equal(t, tc.body, string(gotBody))
			} else {
				expected, err := common.Marshal(tc.override)
				require.NoError(t, err)
				assert.JSONEq(t, string(expected), string(gotBody))
			}
			assert.Equal(t, tc.settled, settlement.settled)
			assert.Equal(t, tc.refunded, settlement.refunded)
			assert.Equal(t, tc.searchLog, info.SearchRequest)
			assert.Equal(t, tc.fetchLog, info.FetchRequest)
			other := service.GenerateTextOtherInfo(c, info, 0, 1, 0, 0, 0, 0, 1).Snapshot()
			assert.NotContains(t, other, "po", "debug overrides must not bypass tool metadata redaction")
			public, err := common.Marshal(other)
			require.NoError(t, err)
			for _, excluded := range []string{"private-password", "private-signature", "private-fragment"} {
				assert.NotContains(t, string(public), excluded)
			}
			if tc.fetchLog == nil {
				assert.NotContains(t, other, "fetch_request")
			} else {
				assert.Equal(t, *tc.fetchLog, other["fetch_request"])
				assert.NotContains(t, other, "web_search")
				assert.NotContains(t, other, "search_request")
				encoded, err := common.Marshal(other["fetch_request"])
				require.NoError(t, err)
				for _, excluded := range []string{"private-password", "private-signature", "private-fragment", "private title", "正文"} {
					assert.NotContains(t, string(encoded), excluded)
				}
			}
			if tc.searchLog == nil {
				assert.NotContains(t, other, "search_request")
			} else {
				assert.Equal(t, *tc.searchLog, other["search_request"])
				assert.NotContains(t, other, "web_search")
				encoded, err := common.Marshal(other["search_request"])
				require.NoError(t, err)
				for _, excluded := range []string{"private original prompt", "private credential", "headers", "ori_question", "future_field"} {
					assert.NotContains(t, string(encoded), excluded)
				}
			}
			if tc.status >= http.StatusBadRequest {
				require.NotNil(t, apiErr)
				assert.Equal(t, tc.status, apiErr.StatusCode)
				return
			}
			require.Nil(t, apiErr)
			assert.Equal(t, tc.status, recorder.Code)
			assert.Equal(t, tc.response, recorder.Body.String())
		})
	}
}
