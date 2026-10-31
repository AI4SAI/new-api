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
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/operation_setting"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// callLogHandler runs a log handler as the given user and returns the JSON
// lines of the response.
func callLogHandler(t *testing.T, handler gin.HandlerFunc, userId int, role int, query string, managedOwner ...int) []map[string]any {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/log?"+query, nil)
	ctx.Set("id", userId)
	ctx.Set("role", role)
	if len(managedOwner) == 1 {
		visibility, err := model.UserTokenLogVisibility(managedOwner[0])
		require.NoError(t, err)
		ctx.Set("managed_account", &service.ManagedAccount{OwnerID: managedOwner[0]})
		ctx.Set("management_token_visibility", visibility)
	}
	handler(ctx)
	var lines []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(recorder.Body.String()), "\n") {
		var value map[string]any
		require.NoError(t, common.UnmarshalJsonStr(line, &value))
		lines = append(lines, value)
	}
	return lines
}

func TestManagedLogsKeepUsageHistoryWithoutPrivateDetails(t *testing.T) {
	for _, database := range []struct {
		name, env string
		kind      common.DatabaseType
	}{
		{"sqlite", "", common.DatabaseTypeSQLite}, {"mysql", "AUDIT_MYSQL_DSN", common.DatabaseTypeMySQL}, {"postgres", "AUDIT_POSTGRES_DSN", common.DatabaseTypePostgreSQL},
	} {
		t.Run(database.name, func(t *testing.T) {
			dsn := os.Getenv(database.env)
			if database.env != "" && dsn == "" {
				t.Skip(database.env + " is not configured")
			}
			mainDB, _ := newAuditTestDatabase(t, database.name, dsn)
			logDB, _ := newAuditTestDatabase(t, database.name, dsn)
			useLogExportDatabases(t, mainDB, logDB, database.kind, database.kind)
			require.NoError(t, mainDB.AutoMigrate(&model.Token{}, &model.User{}))
			require.NoError(t, logDB.AutoMigrate(&model.Log{}))
			require.NoError(t, mainDB.Create(&model.User{Id: 41, Username: "org-owner", Group: "default", AffCode: "logs-owner"}).Error)
			external := seedToken(t, mainDB, 41, "device", "external-log-key")
			internal := seedToken(t, mainDB, 41, "pilot-private-name", "internal-log-key")
			legacy := seedToken(t, mainDB, 41, "unknown-old-source", "legacy-log-key")
			require.NoError(t, mainDB.Model(external).Update("management_creator_id", 7).Error)
			require.NoError(t, mainDB.Model(internal).Update("managed_binding_ref", "11111111-1111-4111-8111-111111111111").Error)
			for _, search := range []struct {
				name  string
				human bool
				count int
			}{{"Pilot", true, 1}, {internal.Name, true, 0}, {internal.Name, false, 1}, {"Pilot", false, 0}} {
				rows, total, err := model.SearchUserTokens(41, search.name, "", 0, 10, search.human)
				require.NoError(t, err)
				require.EqualValues(t, search.count, total)
				require.Len(t, rows, search.count)
			}
			now := time.Now().Unix()
			for _, entry := range []model.Log{
				{UserId: 41, TokenId: external.Id, RequestId: "external-history", Quota: 5, TokenName: "device"},
				{UserId: 41, TokenId: internal.Id, RequestId: "pilot-private", Quota: 100, TokenName: internal.Name},
				{UserId: 41, TokenId: legacy.Id, RequestId: "legacy-private", Quota: 20, TokenName: legacy.Name},
				{UserId: 41, TokenId: 9999, RequestId: "missing-key-private", Quota: 10},
				{UserId: 41, TokenId: 0, RequestId: "playground-private", Quota: 7},
				{UserId: 41, TokenId: external.Id, TokenName: "Pilot", RequestId: "external-same-display", Quota: 3},
				{UserId: 42, TokenId: external.Id, RequestId: "another-owner", Quota: 1000},
			} {
				entry.Type = model.LogTypeConsume
				entry.CreatedAt = now
				entry.Username = "former-org-name"
				entry.ModelName = "fixture-model"
				entry.BillingProduct = "charged-model"
				entry.Group = "charged-group"
				entry.PromptTokens = 120
				entry.CompletionTokens = 30
				entry.Content = "private research prompt"
				entry.Ip = "192.0.2.3"
				entry.ChannelId = 17
				entry.UpstreamRequestId = "upstream-private"
				entry.BillingContextRef = "private-context"
				entry.Other = `{"search_request":{"query":"private search query"},"content_parts":[{"message":"private details"}],"input_tokens_total":120,"cache_tokens":40,"model_price":0.002,"billing_unit":"request","billing_mode":"tiered_expr","fixed_price":0.00075,"expr_b64":"private-expression","admin_info":{"credential":"private"}}`
				require.NoError(t, logDB.Create(&entry).Error)
			}
			require.NoError(t, logDB.Create(&model.Log{UserId: 41, TokenId: 0, Type: model.LogTypeTopup, Quota: 10000, CreatedAt: now, Content: "unrelated owner payment"}).Error)
			require.NoError(t, external.Delete())
			require.NoError(t, legacy.Delete())
			listed := callLogHandler(t, GetUserLogs, 7, common.RoleCommonUser, "", 41)[0]
			require.EqualValues(t, 6, listed["data"].(map[string]any)["total"])
			rows := listed["data"].(map[string]any)["items"].([]any)
			for _, item := range rows {
				row := item.(map[string]any)
				if int(row["token_id"].(float64)) == external.Id {
					require.Equal(t, "private research prompt", row["content"])
					continue
				}
				for _, field := range []string{"content", "ip", "username"} {
					require.Empty(t, row[field])
				}
				require.EqualValues(t, 0, row["channel"])
				for _, field := range []string{"request_id", "upstream_request_id", "billing_context_ref"} {
					require.NotContains(t, row, field)
				}
				require.Equal(t, "fixture-model", row["model_name"])
				require.Equal(t, "charged-model", row["billing_product"])
				require.Equal(t, "charged-group", row["group"])
				require.NotContains(t, row["other"], "private")
				require.NotContains(t, row["other"], "search_request")
				var billing map[string]any
				require.NoError(t, common.UnmarshalJsonStr(row["other"].(string), &billing))
				require.Equal(t, "request", billing["billing_unit"])
				require.Equal(t, "tiered_expr", billing["billing_mode"])
				require.Equal(t, 0.00075, billing["fixed_price"])
				require.EqualValues(t, 40, row["metering"].(map[string]any)["cache_read_tokens"])
				if int(row["token_id"].(float64)) == internal.Id {
					require.Equal(t, "Pilot", row["token_name"])
				} else {
					if int(row["token_id"].(float64)) == legacy.Id {
						require.Equal(t, legacy.Name, row["token_name"])
					} else if int(row["token_id"].(float64)) > 0 {
						require.Equal(t, "Key #9999", row["token_name"])
					} else {
						require.Empty(t, row["token_name"])
					}
				}
			}
			stat := callLogHandler(t, GetLogsSelfStat, 7, common.RoleCommonUser, "", 41)[0]
			require.EqualValues(t, 145, stat["data"].(map[string]any)["quota"])
			exported := callLogHandler(t, ExportUserLogs, 7, common.RoleAdminUser, "", 41)
			require.Len(t, exported, 7)
			for _, row := range exported[:6] {
				if int(row["token_id"].(float64)) != external.Id {
					require.NotContains(t, fmt.Sprint(row), "private")
				}
			}
			byAlias := callLogHandler(t, GetUserLogs, 7, common.RoleCommonUser, "token_name=Pilot", 41)[0]
			require.EqualValues(t, 2, byAlias["data"].(map[string]any)["total"])
			aliasStat := callLogHandler(t, GetLogsSelfStat, 7, common.RoleCommonUser, "token_name=Pilot", 41)[0]
			require.EqualValues(t, 103, aliasStat["data"].(map[string]any)["quota"])
			hiddenName := callLogHandler(t, GetUserLogs, 7, common.RoleCommonUser, "token_name="+internal.Name, 41)[0]
			require.EqualValues(t, 0, hiddenName["data"].(map[string]any)["total"])
			query := fmt.Sprintf("token_id=%d", internal.Id)
			own := callLogHandler(t, GetUserLogs, 41, common.RoleCommonUser, query)[0]
			require.Contains(t, fmt.Sprint(own), "private research prompt")
			require.NoError(t, internal.Delete())
			historical := callLogHandler(t, GetUserLogs, 7, common.RoleCommonUser, query, 41)[0]
			require.EqualValues(t, 1, historical["data"].(map[string]any)["total"])
			require.NotContains(t, fmt.Sprint(historical), "private")

		})
	}
}

func exportedRequestIds(lines []map[string]any) []any {
	ids := make([]any, 0, len(lines))
	for _, line := range lines[:len(lines)-1] {
		ids = append(ids, line["request_id"])
	}
	return ids
}

// seedExportLogs stores logs of two users: three in the last hour and one
// from 400 days ago.
func seedExportLogs(t *testing.T, mainDB *gorm.DB, logDB *gorm.DB, now int64) {
	t.Helper()
	require.NoError(t, mainDB.Create(&model.Channel{Id: 9, Name: "primary"}).Error)
	logs := []model.Log{
		{UserId: 1, Username: "alice", CreatedAt: now - 3600, Type: model.LogTypeConsume, ModelName: "gpt-a", ChannelId: 9, Quota: 10, RequestId: "a-1", Other: `{"admin_info":{"use_channel":["9"]}}`},
		{UserId: 2, Username: "bob", CreatedAt: now - 1800, Type: model.LogTypeConsume, ModelName: "gpt-b", ChannelId: 9, Quota: 20, RequestId: "b-1"},
		{UserId: 1, Username: "alice", CreatedAt: now - 60, Type: model.LogTypeError, ModelName: "gpt-a", RequestId: "a-2"},
		{UserId: 1, Username: "alice", CreatedAt: now - 400*24*3600, Type: model.LogTypeConsume, ModelName: "gpt-a", RequestId: "a-old"},
	}
	for i := range logs {
		require.NoError(t, logDB.Create(&logs[i]).Error)
	}
}

func useLogExportDatabases(t *testing.T, mainDB *gorm.DB, logDB *gorm.DB, mainType common.DatabaseType, logType common.DatabaseType) {
	t.Helper()
	previousDB, previousLogDB := model.DB, model.LOG_DB
	previousMain, previousLog := common.MainDatabaseType(), common.LogDatabaseType()
	previousRedis, previousMemory := common.RedisEnabled, common.MemoryCacheEnabled
	model.DB, model.LOG_DB = mainDB, logDB
	common.SetDatabaseTypes(mainType, logType)
	common.RedisEnabled, common.MemoryCacheEnabled = false, false
	t.Cleanup(func() {
		model.DB, model.LOG_DB = previousDB, previousLogDB
		common.SetDatabaseTypes(previousMain, previousLog)
		common.RedisEnabled, common.MemoryCacheEnabled = previousRedis, previousMemory
	})
}

func TestLogExportDatabaseMatrix(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousMaster := common.IsMasterNode
	common.IsMasterNode = true
	t.Cleanup(func() { common.IsMasterNode = previousMaster })
	for _, tc := range []struct {
		kind, env string
		typ       common.DatabaseType
	}{
		{"sqlite", "", common.DatabaseTypeSQLite},
		{"mysql", "AUDIT_MYSQL_DSN", common.DatabaseTypeMySQL},
		{"postgres", "AUDIT_POSTGRES_DSN", common.DatabaseTypePostgreSQL},
		{"clickhouse", "AUDIT_CLICKHOUSE_DSN", common.DatabaseTypeClickHouse},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			dsn := os.Getenv(tc.env)
			if tc.env != "" && dsn == "" {
				t.Skip(tc.env + " is not configured")
			}
			db, isolatedDSN := newAuditTestDatabase(t, tc.kind, dsn)
			mainDB, mainType := db, tc.typ
			if tc.kind == "clickhouse" {
				mainDB, _ = newAuditTestDatabase(t, "sqlite", "")
				mainType = common.DatabaseTypeSQLite
			}
			useLogExportDatabases(t, mainDB, db, mainType, tc.typ)
			require.NoError(t, mainDB.AutoMigrate(&model.Channel{}))
			if tc.kind == "clickhouse" {
				t.Setenv("LOG_SQL_DSN", isolatedDSN)
				require.NoError(t, model.InitLogDB())
			} else {
				require.NoError(t, db.AutoMigrate(&model.Log{}))
			}
			versionSQL := "SELECT version()"
			if tc.kind == "sqlite" {
				versionSQL = "SELECT sqlite_version()"
			}
			var version string
			require.NoError(t, model.LOG_DB.Raw(versionSQL).Scan(&version).Error)
			t.Logf("log database: %s %s", tc.kind, version)
			now := time.Now().Unix()
			seedExportLogs(t, mainDB, model.LOG_DB, now)
			query := fmt.Sprintf("start_timestamp=%d&end_timestamp=%d", now-2*24*3600, now+3600)

			listed := callLogHandler(t, GetUserLogs, 1, common.RoleCommonUser, query)[0]
			require.Equal(t, true, listed["success"])
			assert.EqualValues(t, 2, listed["data"].(map[string]any)["total"])
			listed = callLogHandler(t, GetAllLogs, 3, common.RoleAdminUser, query+"&username=alice")[0]
			require.Equal(t, true, listed["success"])
			assert.EqualValues(t, 2, listed["data"].(map[string]any)["total"])

			own := callLogHandler(t, ExportUserLogs, 1, common.RoleCommonUser, query)
			require.Len(t, own, 3)
			assert.Equal(t, []any{"a-2", "a-1"}, exportedRequestIds(own))
			assert.Equal(t, map[string]any{"success": true, "message": "", "data": map[string]any{"count": float64(2)}}, own[2])
			assert.Equal(t, float64(1), own[0]["id"], "user exports carry list positions, not row ids")
			assert.Empty(t, own[1]["channel_name"])
			assert.NotContains(t, own[1]["other"], "admin_info")

			all := callLogHandler(t, ExportAllLogs, 3, common.RoleAdminUser, query+"&model_name=gpt-%25")
			require.Len(t, all, 4)
			assert.Equal(t, []any{"a-2", "b-1", "a-1"}, exportedRequestIds(all))
			assert.Equal(t, "primary", all[2]["channel_name"])
			assert.Contains(t, all[2]["other"], "admin_info")
			assert.Equal(t, true, all[3]["success"])
		})
	}
}

func TestLogExportRules(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _ := newAuditTestDatabase(t, "sqlite", "")
	useLogExportDatabases(t, db, db, common.DatabaseTypeSQLite, common.DatabaseTypeSQLite)
	require.NoError(t, db.AutoMigrate(&model.Channel{}, &model.Log{}, &model.QuotaData{}))
	now := time.Now().Unix()
	seedExportLogs(t, db, db, now)
	logSetting := operation_setting.GetLogSetting()
	previousSetting := *logSetting
	t.Cleanup(func() { *logSetting = previousSetting })
	recent := fmt.Sprintf("start_timestamp=%d&end_timestamp=%d", now-2*24*3600, now)
	tooLong := fmt.Sprintf("start_timestamp=%d&end_timestamp=%d", now-366*24*3600, now)

	t.Run("time range", func(t *testing.T) {
		rejected := callLogHandler(t, ExportAllLogs, 3, common.RoleAdminUser, tooLong)
		require.Len(t, rejected, 1)
		assert.Equal(t, false, rejected[0]["success"])
		assert.Equal(t, "The time range cannot exceed {{days}} days", rejected[0]["message_key"])
		assert.Equal(t, map[string]any{"days": float64(365)}, rejected[0]["message_params"])

		assert.Equal(t, false, callLogHandler(t, GetUserLogs, 1, common.RoleCommonUser, tooLong)[0]["success"])
		assert.Equal(t, false, callLogHandler(t, GetLogsSelfStat, 1, common.RoleCommonUser, tooLong)[0]["success"])
		assert.Equal(t, true, callLogHandler(t, GetUserLogs, 3, common.RoleAdminUser, tooLong)[0]["success"], "administrators search their own logs without a limit")

		// The dashboard follows the same range instead of its old one-month limit.
		fortyDays := fmt.Sprintf("start_timestamp=%d&end_timestamp=%d", now-40*24*3600, now)
		for _, handler := range []gin.HandlerFunc{GetUserQuotaDates, GetUserFlowQuotaDates} {
			assert.Equal(t, "The time range cannot exceed {{days}} days", callLogHandler(t, handler, 1, common.RoleCommonUser, tooLong)[0]["message_key"])
			assert.Equal(t, true, callLogHandler(t, handler, 1, common.RoleCommonUser, fortyDays)[0]["success"])
		}

		// Without a start, a user's search reaches back the whole range.
		listed := callLogHandler(t, GetUserLogs, 1, common.RoleCommonUser, "")[0]
		assert.Equal(t, true, listed["success"])
		assert.EqualValues(t, 2, listed["data"].(map[string]any)["total"])

		logSetting.MaxRangeDays = 400
		assert.Equal(t, true, callLogHandler(t, GetUserLogs, 1, common.RoleCommonUser, tooLong)[0]["success"])
		logSetting.MaxRangeDays = previousSetting.MaxRangeDays
	})

	t.Run("user export switch", func(t *testing.T) {
		logSetting.UserExportEnabled = false
		t.Cleanup(func() { logSetting.UserExportEnabled = previousSetting.UserExportEnabled })
		disabled := callLogHandler(t, ExportUserLogs, 1, common.RoleCommonUser, recent)
		require.Len(t, disabled, 1)
		assert.Equal(t, "Log export is disabled", disabled[0]["message_key"])
		assert.Equal(t, true, callLogHandler(t, ExportUserLogs, 3, common.RoleAdminUser, recent)[0]["success"], "administrators export their own logs even when users cannot")
	})

	t.Run("one export per user", func(t *testing.T) {
		release, ok, err := service.AcquireLogExportLock(1)
		require.NoError(t, err)
		require.True(t, ok)
		busy := callLogHandler(t, ExportUserLogs, 1, common.RoleCommonUser, recent)
		require.Len(t, busy, 1)
		assert.Equal(t, "Another log export is running. Try again after it finishes.", busy[0]["message_key"])
		other := callLogHandler(t, ExportUserLogs, 2, common.RoleCommonUser, recent)
		assert.Equal(t, true, other[len(other)-1]["success"], "other users are not blocked")
		release()
		assert.Len(t, callLogHandler(t, ExportUserLogs, 1, common.RoleCommonUser, recent), 3)
	})
}

func TestAcquireLogExportLock(t *testing.T) {
	for _, useRedis := range []bool{false, true} {
		t.Run(fmt.Sprintf("redis=%v", useRedis), func(t *testing.T) {
			previousRedis, previousClient := common.RedisEnabled, common.RDB
			common.RedisEnabled = useRedis
			if useRedis {
				server := miniredis.RunT(t)
				common.RDB = redis.NewClient(&redis.Options{Addr: server.Addr()})
				require.NoError(t, common.RDB.Ping(context.Background()).Err())
			}
			t.Cleanup(func() { common.RedisEnabled, common.RDB = previousRedis, previousClient })

			release, ok, err := service.AcquireLogExportLock(1)
			require.NoError(t, err)
			require.True(t, ok)
			_, ok, err = service.AcquireLogExportLock(1)
			require.NoError(t, err)
			assert.False(t, ok, "a second export of the same user must wait")
			releaseOther, ok, err := service.AcquireLogExportLock(2)
			require.NoError(t, err)
			assert.True(t, ok)
			releaseOther()
			release()
			releaseAgain, ok, err := service.AcquireLogExportLock(1)
			require.NoError(t, err)
			assert.True(t, ok, "a finished export frees the user")
			releaseAgain()
		})
	}
}
