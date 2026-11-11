package model

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func managedScopeTestDatabase(t *testing.T, dialect, purpose string) (*gorm.DB, common.DatabaseType) {
	t.Helper()
	var driver gorm.Dialector
	kind := common.DatabaseType(dialect)
	if dialect == "sqlite" {
		driver = sqlite.Open(filepath.Join(t.TempDir(), "scope.db"))
	} else {
		key := "TEST_" + strings.ToUpper(dialect)
		if purpose != "" {
			key += "_" + purpose
		}
		key += "_DSN"
		dsn := os.Getenv(key)
		if dsn == "" {
			t.Skip(key + " is not configured")
		}
		if dialect == "mysql" {
			driver = mysql.Open(dsn)
		} else {
			driver = postgres.Open(dsn)
		}
	}
	db, err := gorm.Open(driver, &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	return db, kind
}

func TestManagedResourceScopeQueriesAndMutations(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			db, databaseType := managedScopeTestDatabase(t, dialect, "")
			oldDB, oldDatabaseType := DB, common.MainDatabaseType()
			DB = db
			common.SetDatabaseTypes(databaseType, common.LogDatabaseType())
			initCol()
			t.Cleanup(func() {
				DB = oldDB
				common.SetDatabaseTypes(oldDatabaseType, common.LogDatabaseType())
				initCol()
			})
			for range 2 {
				require.NoError(t, DB.AutoMigrate(&Token{}))
			}
			owner := 170000001
			tokens := []Token{
				{UserId: owner, ManagedSubjectRef: "member-a"},
				{UserId: owner, ManagedSubjectRef: "member-a"},
				{UserId: owner, ManagedSubjectRef: "member-b"},
				{UserId: owner, ManagedSubjectRef: "MEMBER-A"},
				{UserId: owner},
				{UserId: owner + 1, ManagedSubjectRef: "member-a"},
			}
			ids := make([]int, 0, len(tokens))
			t.Cleanup(func() { require.NoError(t, DB.Unscoped().Where("id IN ?", ids).Delete(&Token{}).Error) })
			for i := range tokens {
				tokens[i].Key = "scope-test-" + common.GetUUID()
				tokens[i].Name, tokens[i].ExpiredTime, tokens[i].RemainQuota = "original", -1, 100
				require.NoError(t, DB.Create(&tokens[i]).Error)
				ids = append(ids, tokens[i].Id)
			}
			scope := ManagedResourceScope{OwnerID: owner, SubjectRef: "member-a", Restricted: true}
			page, err := scope.GetAllTokens(0, 1)
			require.NoError(t, err)
			require.Len(t, page, 1)
			assert.Equal(t, tokens[1].Id, page[0].Id)
			page, total, err := scope.SearchTokens("original", "", 1, 1, true)
			require.NoError(t, err)
			require.Len(t, page, 1)
			assert.EqualValues(t, 2, total)
			assert.Equal(t, tokens[0].Id, page[0].Id)
			count, err := scope.CountTokens()
			require.NoError(t, err)
			assert.EqualValues(t, 2, count)
			visibility, err := scope.UserTokenLogVisibility()
			require.NoError(t, err)
			assert.Len(t, visibility, 2)
			assert.Contains(t, visibility, tokens[0].Id)
			assert.Contains(t, visibility, tokens[1].Id)
			count, err = CountUserTokens(owner)
			require.NoError(t, err)
			assert.EqualValues(t, 5, count)
			for _, denied := range []int{tokens[2].Id, tokens[3].Id, tokens[4].Id, tokens[5].Id} {
				_, err = scope.GetToken(denied)
				require.ErrorIs(t, err, ErrManagedResourceScopeDenied)
			}
			_, err = (ManagedResourceScope{OwnerID: owner, Restricted: true}).CountTokens()
			require.ErrorIs(t, err, ErrManagedResourceScopeDenied)

			member, err := scope.GetToken(tokens[0].Id)
			require.NoError(t, err)
			admin, err := GetTokenByIds(member.Id, owner)
			require.NoError(t, err)
			admin.Group, admin.ModelLimits, admin.ModelLimitsEnabled = "updated", "model-limited", true
			require.NoError(t, admin.Update(TokenQuotaAdjustment{Delta: 40, ExpectedRevision: admin.QuotaRevision}))
			require.NoError(t, member.UpdateManagedName("member name"))
			reloaded, err := GetTokenByIds(member.Id, owner)
			require.NoError(t, err)
			assert.Equal(t, "member name", reloaded.Name)
			assert.Equal(t, "updated", reloaded.Group)
			assert.Equal(t, "model-limited", reloaded.ModelLimits)
			assert.Equal(t, 140, reloaded.RemainQuota)
			require.ErrorIs(t, member.Update(), ErrManagedResourceScopeDenied)
			member.Status = common.TokenStatusEnabled
			require.ErrorIs(t, member.SelectUpdate(), ErrManagedResourceScopeDenied)
			member.Status = common.TokenStatusDisabled
			require.NoError(t, member.SelectUpdate())
			member.Id = tokens[2].Id
			require.ErrorIs(t, member.UpdateManagedName("forbidden"), ErrManagedResourceScopeDenied)
			require.ErrorIs(t, member.Delete(), ErrTokenDeletionNotAllowed)

			for _, batch := range [][]int{{tokens[0].Id, tokens[2].Id}, {tokens[0].Id, -1}} {
				_, err = scope.GetTokenKeys(batch)
				require.ErrorIs(t, err, ErrManagedResourceScopeDenied)
				_, err = scope.BatchDeleteTokens(batch)
				require.ErrorIs(t, err, ErrTokenDeletionNotAllowed)
				_, err = scope.GetToken(tokens[0].Id)
				require.NoError(t, err, "a denied batch must not delete the authorized item")
			}
			keys, err := scope.GetTokenKeys([]int{tokens[0].Id, tokens[1].Id})
			require.NoError(t, err)
			require.Len(t, keys, 2)
			managerScope := ManagedResourceScope{OwnerID: owner, StrictBatch: true}
			keys, err = managerScope.GetTokenKeys([]int{tokens[0].Id, tokens[2].Id})
			require.NoError(t, err)
			require.Len(t, keys, 2, "account administrators can include different subjects in their account")
			for _, batch := range [][]int{{tokens[0].Id, tokens[5].Id}, {tokens[0].Id, -1}} {
				_, err = managerScope.GetTokenKeys(batch)
				require.ErrorIs(t, err, ErrManagedResourceScopeDenied)
				_, err = managerScope.BatchDeleteTokens(batch)
				require.ErrorIs(t, err, ErrTokenDeletionNotAllowed)
				_, err = managerScope.GetToken(tokens[0].Id)
				require.NoError(t, err, "a denied administrator batch must not partially mutate the account")
			}
			for _, selected := range []ManagedResourceScope{scope, managerScope, {OwnerID: owner}} {
				countDeleted, err := selected.BatchDeleteTokens([]int{tokens[0].Id, tokens[0].Id})
				require.ErrorIs(t, err, ErrTokenDeletionNotAllowed)
				assert.Zero(t, countDeleted)
				retained, err := selected.GetToken(tokens[0].Id)
				require.NoError(t, err)
				require.ErrorIs(t, retained.Delete(), ErrTokenDeletionNotAllowed)
				assert.False(t, retained.DeletedAt.Valid)
				assert.Equal(t, common.TokenStatusDisabled, retained.Status)
			}
			countDeleted, err := BatchDeleteTokens([]int{tokens[4].Id, tokens[5].Id}, owner)
			require.ErrorIs(t, err, ErrTokenDeletionNotAllowed)
			assert.Zero(t, countDeleted)
			require.ErrorIs(t, DeleteTokenById(tokens[0].Id, owner), ErrTokenDeletionNotAllowed)
			// Seed a pre-policy deleted row directly, preserving historical read coverage.
			require.NoError(t, DB.Delete(&tokens[0]).Error)
			visibility, err = scope.UserTokenLogVisibility()
			require.NoError(t, err)
			assert.Contains(t, visibility, tokens[0].Id)
			keys, err = scope.GetTokenKeys([]int{tokens[0].Id, tokens[1].Id})
			require.NoError(t, err)
			require.Len(t, keys, 1)
			assert.Equal(t, tokens[1].Id, keys[0].Id)
			keys, err = managerScope.GetTokenKeys([]int{tokens[0].Id, tokens[1].Id})
			require.NoError(t, err)
			require.Len(t, keys, 1)
			assert.Equal(t, tokens[1].Id, keys[0].Id)
		})
	}
}

func TestManagedSubjectConfirmationAndCache(t *testing.T) {
	truncateTables(t)
	server := useUserCacheMiniRedis(t)
	ref := "11111111-1111-4111-8111-111111111111"
	token := Token{UserId: 7, Key: "subject-confirm-key", Name: "confirmed", BillingContextRef: &ref,
		CreationRequestSHA: strings.Repeat("a", 64), ExpiredTime: -1, RemainQuota: 100}
	require.NoError(t, token.InsertPendingBillingToken())
	require.Equal(t, common.TokenStatusDisabled, token.Status)
	require.NoError(t, cacheSetTokenForTest(token))
	require.NoError(t, token.ConfirmBillingContext("member-a"))
	assert.Equal(t, "member-a", token.ManagedSubjectRef)
	assert.True(t, token.BillingContextConfirmed)
	require.NoError(t, token.ConfirmBillingContext("member-a"))
	require.ErrorIs(t, token.ConfirmBillingContext("member-b"), ErrBillingContextConflict)
	require.NoError(t, cacheSetTokenForTest(token))
	server.HSet(getTokenCacheKey(token.Key), "CacheSchemaVersion", "4", "RemainQuota", "80")
	server.HDel(getTokenCacheKey(token.Key), "ManagedSubjectRef")
	_, err := cacheGetTokenByKey(token.Key)
	require.Error(t, err)
	require.NoError(t, cacheSetTokenForTest(token))
	cached, err := cacheGetTokenByKey(token.Key)
	require.NoError(t, err)
	assert.Equal(t, "member-a", cached.ManagedSubjectRef)
	assert.Equal(t, 80, cached.RemainQuota, "metadata hydration must retain outstanding native reservations")

	legacyRef := "22222222-2222-4222-8222-222222222222"
	legacy := Token{UserId: 7, Key: "legacy-subject-key", BillingContextRef: &legacyRef,
		CreationRequestSHA: strings.Repeat("b", 64), BillingContextConfirmed: true}
	require.NoError(t, DB.Create(&legacy).Error)
	require.ErrorIs(t, legacy.ConfirmBillingContext("member-a"), ErrBillingContextConflict)
	legacy.ManagedSubjectRef = "member-a"
	require.ErrorIs(t, legacy.Update(), ErrManagedResourceScopeDenied)
	var stored Token
	require.NoError(t, DB.First(&stored, legacy.Id).Error)
	assert.Empty(t, stored.ManagedSubjectRef)
}

func TestManagedResourceScopeSeparateLogsAndWriters(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			mainDB, kind := managedScopeTestDatabase(t, dialect, "")
			logDB, _ := managedScopeTestDatabase(t, dialect, "LOG")
			oldDB, oldLogDB, oldExport, oldMemory := DB, LOG_DB, common.DataExportEnabled, common.MemoryCacheEnabled
			oldMainType, oldLogType := common.MainDatabaseType(), common.LogDatabaseType()
			DB, LOG_DB, common.DataExportEnabled, common.MemoryCacheEnabled = mainDB, logDB, false, false
			common.SetDatabaseTypes(kind, kind)
			initCol()
			t.Cleanup(func() {
				DB, LOG_DB, common.DataExportEnabled, common.MemoryCacheEnabled = oldDB, oldLogDB, oldExport, oldMemory
				common.SetDatabaseTypes(oldMainType, oldLogType)
				initCol()
			})
			require.NoError(t, DB.AutoMigrate(&Token{}, &User{}))
			require.NoError(t, LOG_DB.AutoMigrate(&Log{}))
			assert.False(t, LOG_DB.Migrator().HasTable(&Token{}), "log reads must not join the main token database")
			owner := User{Username: "subject-log-owner", Status: common.UserStatusEnabled}
			require.NoError(t, DB.Create(&owner).Error)
			t.Cleanup(func() {
				require.NoError(t, mainDB.Unscoped().Where("user_id = ?", owner.Id).Delete(&Token{}).Error)
				require.NoError(t, mainDB.Unscoped().Delete(&owner).Error)
				require.NoError(t, logDB.Where("user_id = ?", owner.Id).Delete(&Log{}).Error)
			})
			for _, entry := range []struct {
				subject string
				quota   int
			}{{"member-a", 7}, {"member-b", 13}, {"", 19}} {
				ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
				ctx.Set("username", owner.Username)
				ctx.Set("managed_subject_ref", entry.subject)
				ctx.Set("model_billing_context_ref", "context-"+entry.subject)
				RecordConsumeLog(ctx, owner.Id, RecordConsumeLogParams{TokenId: 0, ModelName: "model-a", Quota: entry.quota,
					PromptTokens: 3, CompletionTokens: 2, Other: NewLogOther()})
				RecordErrorLog(ctx, owner.Id, 0, "model-a", "", "failure", 0, 0, false, "", NewLogOther())
			}
			scope := ManagedResourceScope{OwnerID: owner.Id, SubjectRef: "member-a", Restricted: true}
			filter := LogFilter{ResourceScope: &scope, Type: LogTypeConsume, TokenVisibility: map[int]TokenLogVisibility{}}
			logs, total, err := GetUserLogs(owner.Id, filter, 0, 100)
			require.NoError(t, err)
			require.Len(t, logs, 1)
			assert.EqualValues(t, 1, total)
			assert.Zero(t, logs[0].TokenId)
			assert.Equal(t, 7, logs[0].Quota)
			assert.Equal(t, "member-a", logs[0].ManagementSubjectRef)
			assert.Equal(t, "context-member-a", logs[0].ManagementBillingContextRef)
			assert.Empty(t, logs[0].ManagedSubjectRef)
			assert.Empty(t, logs[0].BillingContextRef)
			stat, err := SumUsedQuota(LogTypeConsume, 0, 0, "", "", "", 0, "", filter)
			require.NoError(t, err)
			assert.Equal(t, 7, stat.Quota)
			var exported []Log
			require.NoError(t, StreamUserLogs(context.Background(), owner.Id, filter, func(log *Log) error {
				exported = append(exported, *log)
				return nil
			}))
			require.Len(t, exported, 1)
			body, err := common.Marshal(exported)
			require.NoError(t, err)
			assert.NotContains(t, string(body), "managed_subject_ref")
			assert.NotContains(t, string(body), "ManagementBillingContextRef")
			filter.Type = LogTypeError
			logs, total, err = GetAllLogs(filter, 0, 100)
			require.NoError(t, err)
			assert.EqualValues(t, 1, total)
			require.Len(t, logs, 1)
			assert.Equal(t, "member-a", logs[0].ManagedSubjectRef)
			assert.Equal(t, "context-member-a", logs[0].BillingContextRef)
			taskContext := "33333333-3333-4333-8333-333333333333"
			retired := Token{UserId: owner.Id, Key: "retired-task-subject", Name: "task key", ManagedSubjectRef: "member-a",
				BillingContextRef: &taskContext, BillingContextConfirmed: true}
			require.NoError(t, DB.Create(&retired).Error)
			require.NoError(t, DB.Delete(&retired).Error) // pre-policy historical fixture
			RecordTaskBillingLog(RecordTaskBillingLogParams{UserId: owner.Id, TokenId: retired.Id,
				LogType: LogTypeConsume, ModelName: "model-a", Quota: 5, Other: NewLogOther()})
			filter.Type, filter.TokenID = LogTypeConsume, &retired.Id
			logs, total, err = GetAllLogs(filter, 0, 100)
			require.NoError(t, err)
			require.Len(t, logs, 1)
			assert.EqualValues(t, 1, total)
			assert.Equal(t, "member-a", logs[0].ManagedSubjectRef, "late task settlement retains immutable attribution after key deletion")
			assert.Equal(t, taskContext, logs[0].BillingContextRef)
			logs, _, err = GetUserLogs(owner.Id, filter, 0, 100)
			require.NoError(t, err)
			require.Len(t, logs, 1)
			assert.Equal(t, taskContext, logs[0].ManagementBillingContextRef)
			assert.Empty(t, logs[0].BillingContextRef)
			filter.ResourceScope = &ManagedResourceScope{OwnerID: owner.Id, Restricted: true}
			_, _, err = GetAllLogs(filter, 0, 100)
			require.ErrorIs(t, err, ErrManagedResourceScopeDenied)
		})
	}
}

func TestManagedUserLogOrderingMatchesExport(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			logDB, kind := managedScopeTestDatabase(t, dialect, "LOG")
			oldLogDB, oldLogType := LOG_DB, common.LogDatabaseType()
			LOG_DB = logDB
			common.SetLogDatabaseType(kind)
			initCol()
			t.Cleanup(func() {
				LOG_DB = oldLogDB
				common.SetLogDatabaseType(oldLogType)
				initCol()
			})
			require.NoError(t, logDB.AutoMigrate(&Log{}))
			owner := 170000009
			entries := []Log{
				{UserId: owner, ManagedSubjectRef: "member-a", CreatedAt: 400, TokenName: "newest"},
				{UserId: owner, ManagedSubjectRef: "member-a", CreatedAt: 300, TokenName: "same-second-first"},
				{UserId: owner, ManagedSubjectRef: "member-a", CreatedAt: 200, TokenName: "middle"},
				{UserId: owner, ManagedSubjectRef: "member-a", CreatedAt: 300, TokenName: "same-second-second"},
				{UserId: owner, ManagedSubjectRef: "member-b", CreatedAt: 500, TokenName: "other-member"},
				{UserId: owner + 1, ManagedSubjectRef: "member-a", CreatedAt: 600, TokenName: "other-owner"},
				{UserId: owner, ManagedSubjectRef: "member-a", CreatedAt: 100, TokenName: "backfilled-history"},
			}
			ids := make([]int, 0, len(entries))
			t.Cleanup(func() { require.NoError(t, logDB.Where("id IN ?", ids).Delete(&Log{}).Error) })
			for i := range entries {
				entries[i].Type = LogTypeConsume
				require.NoError(t, logDB.Create(&entries[i]).Error)
				ids = append(ids, entries[i].Id)
			}
			scope := ManagedResourceScope{OwnerID: owner, SubjectRef: "member-a", Restricted: true}
			for _, test := range []struct {
				name     string
				filter   LogFilter
				expected []string
			}{
				{"personal", LogFilter{}, []string{"other-member", "newest", "same-second-second", "same-second-first", "middle", "backfilled-history"}},
				{"member", LogFilter{ResourceScope: &scope, TokenVisibility: map[int]TokenLogVisibility{}}, []string{"newest", "same-second-second", "same-second-first", "middle", "backfilled-history"}},
			} {
				t.Run(test.name, func(t *testing.T) {
					var listed []string
					for offset := 0; offset < len(test.expected); offset += 2 {
						page, total, err := GetUserLogs(owner, test.filter, offset, 2)
						require.NoError(t, err)
						require.EqualValues(t, len(test.expected), total)
						require.Len(t, page, min(2, len(test.expected)-offset))
						for i, row := range page {
							assert.Equal(t, offset+i+1, row.Id, "list IDs retain their display positions")
							listed = append(listed, row.TokenName)
						}
					}
					assert.Equal(t, test.expected, listed, "later insertion must not move older usage ahead of newer usage")
					var exported []string
					require.NoError(t, StreamUserLogs(context.Background(), owner, test.filter, func(row *Log) error {
						assert.Equal(t, len(exported)+1, row.Id)
						exported = append(exported, row.TokenName)
						return nil
					}))
					// The CSV consumer appends stream rows in their received order.
					assert.Equal(t, test.expected, exported)
					assert.Equal(t, listed, exported, "all list pages and the CSV source must have identical order")
				})
			}
		})
	}
}

func TestManagedSubjectSchemaUpgrade(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			mainDB, kind := managedScopeTestDatabase(t, dialect, "UPGRADE")
			logDB, _ := managedScopeTestDatabase(t, dialect, "UPGRADE_LOG")
			oldDB, oldLogDB := DB, LOG_DB
			oldMainType, oldLogType := common.MainDatabaseType(), common.LogDatabaseType()
			DB, LOG_DB = mainDB, logDB
			common.SetDatabaseTypes(kind, kind)
			initCol()
			t.Cleanup(func() {
				DB, LOG_DB = oldDB, oldLogDB
				common.SetDatabaseTypes(oldMainType, oldLogType)
				initCol()
			})
			require.NoError(t, mainDB.AutoMigrate(&Token{}))
			require.NoError(t, logDB.AutoMigrate(&Log{}))
			// Reconstruct the released Token/Log shape by removing only this
			// release's subject columns and their indexes before inserting history.
			require.NoError(t, mainDB.Migrator().DropIndex(&Token{}, "idx_token_managed_subject"))
			require.NoError(t, logDB.Migrator().DropIndex(&Log{}, "idx_log_managed_subject"))
			require.NoError(t, logDB.Migrator().DropIndex(&Log{}, "idx_log_managed_subject_time"))
			require.NoError(t, mainDB.Migrator().DropColumn(&Token{}, "ManagedSubjectRef"))
			require.NoError(t, logDB.Migrator().DropColumn(&Log{}, "ManagedSubjectRef"))
			type storedTable struct {
				db      *gorm.DB
				name    string
				columns []clause.Column
				before  []map[string]any
			}
			tables := []storedTable{{db: mainDB, name: "tokens"}, {db: logDB, name: "logs"}}
			owner := 170000011
			key := "schema-retained-" + common.GetUUID()
			for i, context := range []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
				require.NoError(t, mainDB.Table("tokens").Create(map[string]any{
					"id": i + 1, "user_id": owner, "key": key + string(rune('a'+i)), "name": "preserved",
					"created_time": 1700000000, "status": common.TokenStatusDisabled, "remain_quota": 123,
					"used_quota": 27, "quota_revision": 3, "metadata_revision": 9,
					"billing_context_ref": context, "billing_context_confirmed": true,
					"creation_request_sha": strings.Repeat("a", 64),
				}).Error)
				require.NoError(t, logDB.Table("logs").Create(map[string]any{
					"id": i + 1, "user_id": owner, "token_id": i, "created_at": 1700000000 + i,
					"type": LogTypeConsume, "model_name": "model-a", "quota": 27 + i,
					"prompt_tokens": 5, "completion_tokens": 3, "request_id": context,
					"billing_context_ref": context, "other": `{"cache_tokens":2}`,
				}).Error)
			}
			require.NoError(t, mainDB.Table("tokens").Where("id = ?", 2).Update("deleted_at", gorm.Expr("CURRENT_TIMESTAMP")).Error)
			for i := range tables {
				columns, err := tables[i].db.Migrator().ColumnTypes(tables[i].name)
				require.NoError(t, err)
				for _, column := range columns {
					tables[i].columns = append(tables[i].columns, clause.Column{Name: column.Name()})
				}
				require.NoError(t, tables[i].db.Table(tables[i].name).Clauses(clause.Select{Columns: tables[i].columns}).Order("id").Find(&tables[i].before).Error)
				require.Len(t, tables[i].before, 2)
			}
			for round := range 2 {
				require.NoError(t, mainDB.AutoMigrate(&Token{}))
				require.NoError(t, logDB.AutoMigrate(&Log{}))
				for _, table := range tables {
					var after []map[string]any
					require.NoError(t, table.db.Table(table.name).Clauses(clause.Select{Columns: table.columns}).Order("id").Find(&after).Error)
					assert.Equal(t, table.before, after, "all original columns survive migration %d for %s", round+1, table.name)
					var assigned int64
					require.NoError(t, table.db.Table(table.name).Where("managed_subject_ref IS NOT NULL AND managed_subject_ref <> ''").Count(&assigned).Error)
					assert.Zero(t, assigned, "schema upgrades must not invent an assignee")
				}
			}
			assert.True(t, mainDB.Migrator().HasIndex(&Token{}, "idx_token_managed_subject"))
			assert.True(t, logDB.Migrator().HasIndex(&Log{}, "idx_log_managed_subject"))
			assert.True(t, logDB.Migrator().HasIndex(&Log{}, "idx_log_managed_subject_time"))
			require.Error(t, mainDB.Table("tokens").Create(map[string]any{"id": 3, "user_id": owner, "key": key + "a"}).Error,
				"the existing credential uniqueness must survive both upgrades")
			count, err := (ManagedResourceScope{OwnerID: owner, SubjectRef: "member-a", Restricted: true}).CountTokens()
			require.NoError(t, err)
			assert.Zero(t, count)
		})
	}
}
