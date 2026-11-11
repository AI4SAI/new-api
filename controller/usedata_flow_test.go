package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type flowQuotaResponse struct {
	Success bool                  `json:"success"`
	Message string                `json:"message"`
	Data    []model.FlowQuotaData `json:"data"`
}

func setupFlowControllerTestDB(t *testing.T) {
	t.Helper()
	db := setupModelListControllerTestDB(t)
	require.NoError(t, db.AutoMigrate(&model.Token{}, &model.QuotaData{}))
	require.NoError(t, model.DB.Create(&model.Channel{Id: 1, Name: "east"}).Error)
	require.NoError(t, model.DB.Create(&model.Token{Id: 11, UserId: 1, Key: "sk-primary", Name: "primary"}).Error)
	require.NoError(t, model.DB.Create(&model.Token{Id: 22, UserId: 2, Key: "sk-backup", Name: "backup"}).Error)
	require.NoError(t, model.DB.Create(&model.QuotaData{
		UserID:    1,
		Username:  "alice",
		NodeName:  "node-a",
		TokenID:   11,
		UseGroup:  "default",
		ChannelID: 1,
		ModelName: "gpt-a",
		CreatedAt: 1100,
		Count:     2,
		Quota:     100,
		TokenUsed: 40,
	}).Error)
	require.NoError(t, model.DB.Create(&model.QuotaData{
		UserID:    2,
		Username:  "bob",
		NodeName:  "node-b",
		TokenID:   22,
		UseGroup:  "vip",
		ChannelID: 1,
		ModelName: "gpt-b",
		CreatedAt: 1200,
		Count:     1,
		Quota:     70,
		TokenUsed: 30,
	}).Error)
}

func decodeFlowQuotaResponse(t *testing.T, recorder *httptest.ResponseRecorder) flowQuotaResponse {
	t.Helper()
	require.Equal(t, http.StatusOK, recorder.Code)
	var payload flowQuotaResponse
	require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &payload))
	require.True(t, payload.Success, payload.Message)
	return payload
}

func TestGetAllFlowQuotaDatesUsesAdminDimensions(t *testing.T) {
	setupFlowControllerTestDB(t)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Set("role", common.RoleAdminUser)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/data/flow?start_timestamp=1000&end_timestamp=2000&username=bob", nil)

	GetAllFlowQuotaDates(ctx)

	payload := decodeFlowQuotaResponse(t, recorder)
	require.Len(t, payload.Data, 1)
	require.Equal(t, "bob", payload.Data[0].Username)
	require.Equal(t, "vip", payload.Data[0].UseGroup)
	require.Equal(t, "east", payload.Data[0].ChannelName)
	require.Empty(t, payload.Data[0].TokenName)
	require.Empty(t, payload.Data[0].NodeName)
}

func TestGetAllFlowQuotaDatesUsesRootDimensions(t *testing.T) {
	setupFlowControllerTestDB(t)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Set("role", common.RoleRootUser)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/data/flow?start_timestamp=1000&end_timestamp=2000&username=alice", nil)

	GetAllFlowQuotaDates(ctx)

	payload := decodeFlowQuotaResponse(t, recorder)
	require.Len(t, payload.Data, 1)
	require.Equal(t, "alice", payload.Data[0].Username)
	require.Equal(t, "node-a", payload.Data[0].NodeName)
	require.Equal(t, "primary", payload.Data[0].TokenName)
	require.Equal(t, "default", payload.Data[0].UseGroup)
	require.Equal(t, "east", payload.Data[0].ChannelName)
}

func TestGetUserFlowQuotaDatesRestrictsToAuthenticatedUser(t *testing.T) {
	setupFlowControllerTestDB(t)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Set("id", 1)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/data/flow/self?start_timestamp=1000&end_timestamp=2000", nil)

	GetUserFlowQuotaDates(ctx)

	payload := decodeFlowQuotaResponse(t, recorder)
	require.Len(t, payload.Data, 1)
	require.Empty(t, payload.Data[0].Username)
	require.Equal(t, "primary", payload.Data[0].TokenName)
	require.Equal(t, "default", payload.Data[0].UseGroup)
	require.Empty(t, payload.Data[0].ChannelName)
}

func TestGetUserFlowQuotaDatesRejectsInvalidTimeRange(t *testing.T) {
	setupFlowControllerTestDB(t)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Set("id", 1)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/data/flow/self?start_timestamp=bad&end_timestamp=2000", nil)

	GetUserFlowQuotaDates(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	var payload flowQuotaResponse
	require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &payload))
	require.False(t, payload.Success)
	require.Equal(t, "invalid start_timestamp", payload.Message)
}

func TestManagedDashboardQuotaScopesDatabaseMatrix(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			dsn := os.Getenv("TEST_" + strings.ToUpper(dialect) + "_DSN")
			if dialect != "sqlite" && dsn == "" {
				t.Skip("test database DSN is not configured")
			}
			mainDB, _ := newAuditTestDatabase(t, dialect, dsn)
			logDB, _ := newAuditTestDatabase(t, dialect, dsn)
			kind := common.DatabaseType(dialect)
			useLogExportDatabases(t, mainDB, logDB, kind, kind)
			require.NoError(t, mainDB.AutoMigrate(&model.Token{}, &model.QuotaData{}))
			require.NoError(t, logDB.AutoMigrate(&model.Log{}))
			start := time.Now().Unix()/3600*3600 - 3*3600
			end := start + 2*3600 - 1
			tokens := []model.Token{
				{Id: 101, UserId: 41, Key: "dashboard-active", Name: "A active", ManagedSubjectRef: managedMemberA, Status: common.TokenStatusEnabled},
				{Id: 102, UserId: 41, Key: "dashboard-disabled", Name: "A disabled", ManagedSubjectRef: managedMemberA, Status: common.TokenStatusDisabled},
				{Id: 103, UserId: 41, Key: "dashboard-retired", Name: "A retired", ManagedSubjectRef: managedMemberA, DeletedAt: gorm.DeletedAt{Time: time.Unix(start-1, 0), Valid: true}},
				{Id: 104, UserId: 41, Key: "dashboard-reassigned", Name: "Other member current name", ManagedSubjectRef: managedMemberB},
				{Id: 201, UserId: 41, Key: "dashboard-other-member", Name: "B active", ManagedSubjectRef: managedMemberB},
			}
			require.NoError(t, mainDB.Create(&tokens).Error)
			entries := []model.Log{
				{UserId: 41, ManagedSubjectRef: managedMemberA, TokenId: 101, CreatedAt: start + 60, Quota: 11, PromptTokens: 10, CompletionTokens: 2, MeteredCacheReadTokens: common.GetPointer(int64(2))},
				{UserId: 41, ManagedSubjectRef: managedMemberA, TokenId: 102, CreatedAt: start + 70, Quota: 13, PromptTokens: 20, CompletionTokens: 3, MeteredCacheReadTokens: common.GetPointer(int64(3))},
				{UserId: 41, ManagedSubjectRef: managedMemberA, TokenId: 103, CreatedAt: start + 80, Quota: 17, PromptTokens: 30, CompletionTokens: 4},
				{UserId: 41, ManagedSubjectRef: managedMemberA, TokenId: 0, CreatedAt: start + 3610, Quota: 19, PromptTokens: 40, CompletionTokens: 5, MeteredCacheReadTokens: common.GetPointer(int64(4))},
				{UserId: 41, ManagedSubjectRef: managedMemberA, TokenId: 999, CreatedAt: start + 3620, Quota: 23, PromptTokens: 50, CompletionTokens: 6, MeteredCacheReadTokens: common.GetPointer(int64(5))},
				{UserId: 41, ManagedSubjectRef: managedMemberA, TokenId: 104, CreatedAt: start + 3630, Quota: 29, PromptTokens: 60, CompletionTokens: 7, MeteredCacheReadTokens: common.GetPointer(int64(6))},
				{UserId: 41, ManagedSubjectRef: managedMemberB, TokenId: 201, CreatedAt: start + 60, Quota: 31, PromptTokens: 70, CompletionTokens: 8, MeteredCacheReadTokens: common.GetPointer(int64(7))},
				{UserId: 41, ManagedSubjectRef: managedMemberB, TokenId: 0, CreatedAt: start + 3610, Quota: 37, PromptTokens: 80, CompletionTokens: 9, MeteredCacheReadTokens: common.GetPointer(int64(8))},
				{UserId: 41, TokenId: 0, CreatedAt: start + 90, Quota: 41, PromptTokens: 90, CompletionTokens: 10},
				{UserId: 41, ManagedSubjectRef: strings.ToUpper(managedMemberA), CreatedAt: start + 90, Quota: 43, PromptTokens: 1, CompletionTokens: 1},
				{UserId: 42, ManagedSubjectRef: managedMemberA, CreatedAt: start + 90, Quota: 1000, PromptTokens: 1000},
				{UserId: 7, CreatedAt: start + 90, Quota: 888, PromptTokens: 888},
				{UserId: 41, ManagedSubjectRef: managedMemberA, CreatedAt: start - 1, Quota: 500},
				{UserId: 41, ManagedSubjectRef: managedMemberA, CreatedAt: end + 1, Quota: 500},
			}
			for i := range entries {
				entries[i].Type, entries[i].ModelName, entries[i].Group = model.LogTypeConsume, "model-a", "default"
				entries[i].Username, entries[i].Content, entries[i].Ip = "private owner", "private request", "192.0.2.5"
				entries[i].Other = `{"cache_write_tokens":99,"private":"metadata"}`
			}
			entries = append(entries,
				model.Log{UserId: 41, ManagedSubjectRef: managedMemberA, CreatedAt: start + 100, Type: model.LogTypeRefund, Quota: 500},
				model.Log{UserId: 41, ManagedSubjectRef: managedMemberA, CreatedAt: start + 100, Type: model.LogTypeError, Quota: 500})
			require.NoError(t, logDB.Create(&entries).Error)
			// Personal dashboards keep the existing derived data, independent of logs.
			require.NoError(t, mainDB.Create(&model.QuotaData{UserID: 7, ModelName: "personal-model", CreatedAt: start,
				UseGroup: "personal-group", Count: 2, Quota: 11, TokenUsed: 22, CacheReadTokens: 3, CacheCreationTokens: 4}).Error)
			account := managedControllerAccount(managedMemberA)
			startManagedControllerAuthority(t, account, func(_ http.ResponseWriter, r *http.Request) {
				t.Errorf("dashboard must not resolve individual keys or contexts through Core: %s", r.URL.Path)
			})
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set("id", 7)
				c.Set("role", common.RoleCommonUser)
				c.Set("session_id", "fixture-session")
				c.Next()
				require.Equal(t, 7, c.GetInt("id"), "organization scope must not replace the authenticated actor")
				require.Equal(t, common.RoleCommonUser, c.GetInt("role"))
			})
			router.GET("/api/data/self", middleware.ManagedAccountAuthorization("model.usage.read"), GetUserQuotaDates)
			router.GET("/api/data/flow/self", middleware.ManagedAccountAuthorization("model.usage.read"), GetUserFlowQuotaDates)
			router.GET("/api/log/self", middleware.ManagedAccountAuthorization("model.usage.read"), func(c *gin.Context) {
				value, present := c.Get("management_token_visibility")
				require.True(t, present, "usage log routes must retain their disclosure map")
				visibility := value.(map[int]model.TokenLogVisibility)
				require.Contains(t, visibility, 101)
				require.Contains(t, visibility, 103, "retired key provenance remains available to the log formatter")
				require.NotContains(t, visibility, 201)
				c.Status(http.StatusNoContent)
			})
			tokenQueries := 0
			const tokenQueryCallback = "test:dashboard_token_queries"
			require.NoError(t, mainDB.Callback().Query().After("gorm:query").Register(tokenQueryCallback, func(tx *gorm.DB) {
				if tx.Statement.Table == "tokens" {
					tokenQueries++
				}
			}))
			t.Cleanup(func() { require.NoError(t, mainDB.Callback().Query().Remove(tokenQueryCallback)) })
			request := func(path, query string, managed bool) *httptest.ResponseRecorder {
				recorder := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, path+"?"+query, nil)
				if managed {
					req.Header.Set(service.ManagedWorkspaceHeader, "org:fixture")
				}
				router.ServeHTTP(recorder, req)
				return recorder
			}
			query := fmt.Sprintf("start_timestamp=%d&end_timestamp=%d", start, end)
			for _, endpoint := range []string{"/api/data/self", "/api/data/flow/self"} {
				for _, tc := range []struct {
					name, subject, selector string
					managed                 bool
					count, quota, tokens    float64
				}{
					{"personal", "", "", false, 2, 11, 22},
					{"member", managedMemberA, "", true, 6, 112, 237},
					{"member cannot select another owner", managedMemberA, "&user_id=42&username=other&role=100", true, 6, 112, 237},
					{"organization administrator", "", "", true, 10, 264, 506},
					{"administrator selects member", "", "&subject_ref=" + managedMemberB, true, 2, 68, 167},
				} {
					t.Run(endpoint+"/"+tc.name, func(t *testing.T) {
						*account = *managedControllerAccount(tc.subject)
						tokenQueries = 0
						response := request(endpoint, query+tc.selector, tc.managed)
						require.Equal(t, http.StatusOK, response.Code)
						var payload struct {
							Success bool             `json:"success"`
							Data    []map[string]any `json:"data"`
						}
						require.NoError(t, common.Unmarshal(response.Body.Bytes(), &payload))
						require.True(t, payload.Success, response.Body.String())
						var count, quota, tokens float64
						for _, row := range payload.Data {
							count += row["count"].(float64)
							quota += row["quota"].(float64)
							tokens += row["token_used"].(float64)
							if tc.managed {
								for _, field := range []string{"user_id", "username", "node_name", "channel_id", "channel_name", "content", "other", "billing_context_ref", "managed_subject_ref", "cache_creation_tokens"} {
									require.NotContains(t, row, field)
								}
							}
						}
						require.Equal(t, tc.count, count)
						require.Equal(t, tc.quota, quota)
						require.Equal(t, tc.tokens, tokens)
						wantTokenQueries := 0
						if tc.managed && endpoint == "/api/data/flow/self" {
							wantTokenQueries = 1
						}
						require.Equal(t, wantTokenQueries, tokenQueries, "aggregate routes must not preload every key; flow resolves only result labels once")
						if tc.name == "member" && endpoint == "/api/data/self" {
							require.Len(t, payload.Data, 2)
							require.EqualValues(t, start, payload.Data[0]["created_at"])
							require.NotContains(t, payload.Data[0], "cache_read_tokens", "an unknown counter must not become zero")
							require.EqualValues(t, 15, payload.Data[1]["cache_read_tokens"])
						}
						if tc.name == "member" && endpoint == "/api/data/flow/self" {
							require.Len(t, payload.Data, 6)
							require.Contains(t, response.Body.String(), "A disabled")
							require.NotContains(t, response.Body.String(), "Other member current name")
						}
					})
				}
				*account = *managedControllerAccount(managedMemberA)
				require.Equal(t, http.StatusForbidden, request(endpoint, query+"&subject_ref="+managedMemberB, true).Code)
				account.AllowedActions = nil
				require.Equal(t, http.StatusForbidden, request(endpoint, query, true).Code, "denied organization access cannot fall back to personal data")
				*account = *managedControllerAccount(managedMemberA)
				tooOld := end - operation_setting.GetLogSetting().MaxRangeSeconds() - 1
				response := request(endpoint, fmt.Sprintf("start_timestamp=%d&end_timestamp=%d", tooOld, end), true)
				require.Contains(t, response.Body.String(), `"success":false`)
			}
			tokenQueries = 0
			require.Equal(t, http.StatusNoContent, request("/api/log/self", query, true).Code)
			require.Equal(t, 1, tokenQueries)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := (model.ManagedResourceScope{OwnerID: 41, SubjectRef: managedMemberA, Restricted: true}).GetQuotaData(ctx, start, end)
			require.Error(t, err, "canceled dashboard requests must stop the log query")
			ctx, cancel = context.WithCancel(context.Background())
			defer cancel()
			labelsStarted := false
			const cancelLabelsCallback = "test:cancel_dashboard_labels"
			require.NoError(t, mainDB.Callback().Query().Before("gorm:query").Register(cancelLabelsCallback, func(tx *gorm.DB) {
				if tx.Statement.Table == "tokens" {
					labelsStarted = true
					cancel()
				}
			}))
			t.Cleanup(func() { require.NoError(t, mainDB.Callback().Query().Remove(cancelLabelsCallback)) })
			_, err = (model.ManagedResourceScope{OwnerID: 41, SubjectRef: managedMemberA, Restricted: true}).GetFlowQuotaData(ctx, start, end)
			require.True(t, labelsStarted, "cancellation must occur after the log aggregation")
			require.ErrorIs(t, err, context.Canceled, "the label query must inherit the canceled request")
		})
	}
}
