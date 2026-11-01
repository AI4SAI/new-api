package model

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type quotaReplyLossHook struct {
	scriptMatch string
	fired       bool
	before      bool
}

func (hook *quotaReplyLossHook) BeforeProcess(ctx context.Context, cmd redis.Cmder) (context.Context, error) {
	if hook.before && !hook.fired && cmd.Name() == "eval" {
		script, _ := cmd.Args()[1].(string)
		if strings.Contains(script, hook.scriptMatch) {
			hook.fired = true
			return ctx, errors.New("injected Redis publication failure")
		}
	}
	return ctx, nil
}
func (hook *quotaReplyLossHook) AfterProcess(_ context.Context, cmd redis.Cmder) error {
	if hook.fired || cmd.Name() != "eval" || cmd.Err() != nil {
		return nil
	}
	script, _ := cmd.Args()[1].(string)
	if strings.Contains(script, hook.scriptMatch) {
		hook.fired = true
		return errors.New("injected Redis acknowledgement lost")
	}
	return nil
}
func (hook *quotaReplyLossHook) BeforeProcessPipeline(ctx context.Context, _ []redis.Cmder) (context.Context, error) {
	return ctx, nil
}
func (hook *quotaReplyLossHook) AfterProcessPipeline(context.Context, []redis.Cmder) error {
	return nil
}

func TestTokenQuotaRedisAcknowledgementLossIsUnknown(t *testing.T) {
	for _, stage := range []string{"adjustment", "confirmation"} {
		t.Run(stage, func(t *testing.T) {
			truncateTables(t)
			resetBatchUpdateTestState(t)
			useTokenAdjustmentRedis(t)
			token := createReserveTestToken(t, 100)
			require.NoError(t, cacheSetTokenForTest(token))
			match := "'QuotaRevision', tonumber(ARGV[4]) + 1, 'CacheSchemaVersion', -1"
			if stage == "confirmation" {
				match = "if tonumber(redis.call('HGET', KEYS[1], 'QuotaRevision') or '0') ~= tonumber(ARGV[2])"
			}
			hook := &quotaReplyLossHook{scriptMatch: match}
			common.RDB.AddHook(hook)
			err := token.Update(TokenQuotaAdjustment{Delta: 25, ExpectedRevision: 0})
			require.True(t, hook.fired)
			require.ErrorIs(t, err, ErrTokenQuotaUpdateUnknown)
			stored := getTokenFromDB(t, token.Id)
			if stage == "adjustment" {
				require.Equal(t, 100, stored.RemainQuota)
				require.Zero(t, stored.QuotaRevision)
				_, err = GetTokenByKey(token.Key, false)
				require.ErrorIs(t, err, ErrTokenQuotaUpdateUnknown)
				ok, err := TryReserveTokenQuota(token.Id, token.Key, 1, false)
				require.False(t, ok)
				require.ErrorIs(t, err, ErrTokenQuotaUpdateUnknown)
			} else {
				require.Equal(t, 125, stored.RemainQuota)
				require.EqualValues(t, 1, stored.QuotaRevision)
				require.ErrorIs(t, token.Update(TokenQuotaAdjustment{Delta: 25, ExpectedRevision: 0}), ErrTokenQuotaRevisionConflict)
			}
		})
	}
}

type quotaCommitFaultPool struct {
	gorm.ConnPool
	commitApplied bool
	readbackFails bool
	begins        int
}

func (pool *quotaCommitFaultPool) BeginTx(ctx context.Context, options *sql.TxOptions) (gorm.ConnPool, error) {
	pool.begins++
	if pool.begins > 1 && pool.readbackFails {
		return nil, errors.New("injected readback unavailable")
	}
	var tx gorm.ConnPool
	var err error
	switch connection := pool.ConnPool.(type) {
	case gorm.TxBeginner:
		tx, err = connection.BeginTx(ctx, options)
	case gorm.ConnPoolBeginner:
		tx, err = connection.BeginTx(ctx, options)
	default:
		return nil, errors.New("unsupported transaction fixture")
	}
	if err != nil || pool.begins > 1 {
		return tx, err
	}
	return &quotaCommitFaultTx{ConnPool: tx, commitApplied: pool.commitApplied}, nil
}

type quotaCommitFaultTx struct {
	gorm.ConnPool
	commitApplied bool
}

func (tx *quotaCommitFaultTx) Commit() error {
	var err error
	if tx.commitApplied {
		err = tx.ConnPool.(gorm.TxCommitter).Commit()
	} else {
		err = tx.ConnPool.(gorm.TxCommitter).Rollback()
	}
	if err != nil {
		return err
	}
	return errors.New("injected commit acknowledgement lost")
}
func (tx *quotaCommitFaultTx) Rollback() error { return tx.ConnPool.(gorm.TxCommitter).Rollback() }

func TestTokenQuotaCommitOutcomeUsesExactMutation(t *testing.T) {
	for _, test := range []struct {
		name                         string
		commitApplied, readbackFails bool
		remaining, delta             int
	}{{"committed", true, false, 125, 25}, {"withdrawal-committed", true, false, 75, -25}, {"rolled-back", false, false, 100, 25}, {"withdrawal-rolled-back", false, false, 100, -25}, {"unknown", false, true, 100, 25}} {
		t.Run(test.name, func(t *testing.T) {
			truncateTables(t)
			resetBatchUpdateTestState(t)
			useTokenAdjustmentRedis(t)
			token := createReserveTestToken(t, 100)
			require.NoError(t, cacheSetTokenForTest(token))
			original := DB
			faulted := DB.Session(&gorm.Session{NewDB: true, Context: context.Background()})
			faulted.Statement.ConnPool = &quotaCommitFaultPool{ConnPool: original.Statement.ConnPool, commitApplied: test.commitApplied, readbackFails: test.readbackFails}
			DB = faulted
			err := token.Update(TokenQuotaAdjustment{Delta: test.delta, ExpectedRevision: 0})
			DB = original
			switch {
			case test.readbackFails:
				require.ErrorIs(t, err, ErrTokenQuotaUpdateUnknown)
			case test.commitApplied:
				require.NoError(t, err)
			default:
				require.ErrorContains(t, err, "acknowledgement lost")
			}
			stored := getTokenFromDB(t, token.Id)
			require.Equal(t, test.remaining, stored.RemainQuota)
			if test.commitApplied {
				require.EqualValues(t, 1, stored.QuotaRevision)
				require.NotEmpty(t, stored.QuotaMutationRef)
			} else {
				require.Zero(t, stored.QuotaRevision)
			}
			if test.readbackFails {
				token.Name = "renamed after unknown"
				require.NoError(t, token.Update())
				token.Status = common.TokenStatusDisabled
				require.NoError(t, token.SelectUpdate())
				token.Status = common.TokenStatusEnabled
				require.NoError(t, token.SelectUpdate())
				_, err = GetTokenByKey(token.Key, false)
				require.ErrorIs(t, err, ErrTokenQuotaUpdateUnknown)
				ok, err := TryReserveTokenQuota(token.Id, token.Key, 1, false)
				require.False(t, ok)
				require.ErrorIs(t, err, ErrTokenQuotaUpdateUnknown)
				ok, err = TryReserveTokenQuota(token.Id, token.Key, 1, true)
				require.False(t, ok)
				require.ErrorIs(t, err, ErrTokenQuotaUpdateUnknown)
				require.Equal(t, "125", common.RDB.HGet(context.Background(), getTokenCacheKey(token.Key), "RemainQuota").Val())
			} else {
				require.Equal(t, strconv.Itoa(test.remaining), common.RDB.HGet(context.Background(), getTokenCacheKey(token.Key), "RemainQuota").Val())
			}
		})
	}
}

func useTokenAdjustmentRedis(t *testing.T) {
	t.Helper()
	if dsn := os.Getenv("TEST_QUOTA_DB_DSN"); dsn != "" {
		previousDB, previousType := DB, common.MainDatabaseType()
		var dialector gorm.Dialector
		switch os.Getenv("TEST_QUOTA_DB_DIALECT") {
		case "mysql":
			dialector = mysql.Open(dsn)
			common.SetDatabaseTypes(common.DatabaseTypeMySQL, common.LogDatabaseType())
		case "postgres":
			dialector = postgres.Open(dsn)
			common.SetDatabaseTypes(common.DatabaseTypePostgreSQL, common.LogDatabaseType())
		default:
			t.Fatal("unsupported TEST_QUOTA_DB_DIALECT")
		}
		db, err := gorm.Open(dialector, &gorm.Config{})
		require.NoError(t, err)
		DB = db
		initCol()
		require.NoError(t, db.AutoMigrate(&Token{}))
		t.Cleanup(func() {
			sqlDB, err := db.DB()
			require.NoError(t, err)
			require.NoError(t, sqlDB.Close())
			DB = previousDB
			common.SetDatabaseTypes(previousType, common.LogDatabaseType())
			initCol()
		})
	}
	useUserCacheMiniRedis(t)
	if address := os.Getenv("TEST_REDIS_ADDR"); address != "" {
		previous := common.RDB
		client := redis.NewClient(&redis.Options{Addr: address})
		require.NoError(t, client.Ping(context.Background()).Err())
		common.RDB = client
		t.Cleanup(func() { require.NoError(t, client.Close()); common.RDB = previous })
	}
}

func TestTokenQuotaUpdatesPreserveDeductionsAndRejectRetry(t *testing.T) {
	for _, batch := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "batch"}[batch], func(t *testing.T) {
			truncateTables(t)
			resetBatchUpdateTestState(t)
			useTokenAdjustmentRedis(t)
			common.BatchUpdateEnabled = batch
			token := createReserveTestToken(t, 100)
			require.NoError(t, cacheSetTokenForTest(token))
			reserved, err := TryReserveTokenQuota(token.Id, token.Key, 30, false)
			require.NoError(t, err)
			require.True(t, reserved)
			token.Name = "updated metadata"
			require.NoError(t, token.Update())
			require.Equal(t, "70", common.RDB.HGet(context.Background(), getTokenCacheKey(token.Key), "RemainQuota").Val())
			require.NoError(t, token.Update(TokenQuotaAdjustment{Delta: 25, ExpectedRevision: 0}))
			require.ErrorIs(t, token.Update(TokenQuotaAdjustment{Delta: 25, ExpectedRevision: 0}), ErrTokenQuotaRevisionConflict)
			require.Error(t, token.Update(TokenQuotaAdjustment{Delta: -96, ExpectedRevision: 1}))
			token.Status = common.TokenStatusDisabled
			require.NoError(t, token.SelectUpdate())
			if batch {
				batchUpdate()
			}
			stored := getTokenFromDB(t, token.Id)
			require.Equal(t, 95, stored.RemainQuota)
			require.Equal(t, 30, stored.UsedQuota)
			require.EqualValues(t, 1, stored.QuotaRevision)
			require.Equal(t, "95", common.RDB.HGet(context.Background(), getTokenCacheKey(token.Key), "RemainQuota").Val())
		})
	}
}

func TestTokenQuotaAdjustmentFailurePreservesConcurrentConsumption(t *testing.T) {
	truncateTables(t)
	resetBatchUpdateTestState(t)
	useTokenAdjustmentRedis(t)
	token := createReserveTestToken(t, 0)
	require.NoError(t, cacheSetTokenForTest(token))
	const callback = "test:failed_quota_configuration"
	require.NoError(t, DB.Callback().Update().Before("gorm:update").Register(callback, func(tx *gorm.DB) {
		if changes, ok := tx.Statement.Dest.(map[string]any); ok && changes["quota_revision"] != nil {
			result, err := cacheTryReserveTokenQuota(token.Id, token.Key, 1)
			require.NoError(t, err)
			require.Equal(t, cacheQuotaUnknown, result, "uncommitted adjustment must not authorize a new request")
			// An already accepted request may still settle real consumption.
			result, err = cacheApplyTokenQuotaDelta(token.Id, token.Key, -50)
			require.NoError(t, err)
			require.Equal(t, cacheQuotaOK, result)
			addNewRecord(BatchUpdateTypeTokenQuota, token.Id, -50)
			tx.AddError(errors.New("injected database write failure"))
		}
	}))
	err := token.Update(TokenQuotaAdjustment{Delta: 100, ExpectedRevision: 0})
	require.ErrorContains(t, err, "injected database write failure")
	require.NoError(t, DB.Callback().Update().Remove(callback))
	batchUpdate()
	stored := getTokenFromDB(t, token.Id)
	require.Equal(t, -50, stored.RemainQuota)
	require.Equal(t, 50, stored.UsedQuota)
	require.Zero(t, stored.QuotaRevision)
	require.Equal(t, "-50", common.RDB.HGet(context.Background(), getTokenCacheKey(token.Key), "RemainQuota").Val())
	reserved, err := TryReserveTokenQuota(token.Id, token.Key, 1, false)
	require.NoError(t, err)
	require.False(t, reserved)
}

func TestTokenDisableFailsWhenCacheCannotBeInvalidated(t *testing.T) {
	truncateTables(t)
	server := useUserCacheMiniRedis(t)
	token := createReserveTestToken(t, 100)
	require.NoError(t, cacheSetTokenForTest(token))
	token.Status = common.TokenStatusDisabled
	server.SetError("injected cache failure")
	require.Error(t, token.SelectUpdate())
	server.SetError("")
	require.Equal(t, common.TokenStatusEnabled, getTokenFromDB(t, token.Id).Status)
	require.NoError(t, token.SelectUpdate())
	require.Equal(t, common.TokenStatusDisabled, getTokenFromDB(t, token.Id).Status)
	_, err := ValidateUserToken(token.Key)
	require.Error(t, err)
}

func TestTokenMetadataUnknownResultCannotRestoreEnabledCache(t *testing.T) {
	for _, stage := range []string{"commit_response", "commit_unknown", "rollback", "cache_publication"} {
		t.Run(stage, func(t *testing.T) {
			truncateTables(t)
			resetBatchUpdateTestState(t)
			useTokenAdjustmentRedis(t)
			token := createReserveTestToken(t, 100)
			old := token
			require.NoError(t, cacheSetTokenForTest(token))
			original := DB
			if stage != "cache_publication" {
				faulted := DB.Session(&gorm.Session{NewDB: true, Context: context.Background()})
				faulted.Statement.ConnPool = &quotaCommitFaultPool{ConnPool: original.Statement.ConnPool,
					commitApplied: stage != "rollback", readbackFails: stage == "commit_unknown"}
				DB = faulted
			} else {
				common.RDB.AddHook(&quotaReplyLossHook{scriptMatch: "local revision = tonumber", before: true})
			}
			token.Status = common.TokenStatusDisabled
			err := token.SelectUpdate()
			DB = original
			require.Error(t, err)
			if stage == "rollback" {
				_, err = ValidateUserToken(token.Key)
				require.NoError(t, err, "a confirmed rollback must recover without manual cache repair")
				return
			}
			require.Equal(t, common.TokenStatusDisabled, getTokenFromDB(t, token.Id).Status)
			// Account invalidation must not replace an unresolved version fence.
			if stage == "commit_unknown" {
				require.NoError(t, invalidateTokenCacheForMutation(token.Key))
				require.Equal(t, time.Duration(-1), common.RDB.TTL(context.Background(), getTokenCacheFenceKey(token.Key)).Val())
			}
			_, err = cacheInitToken(old)
			require.ErrorIs(t, err, ErrTokenMetadataStale)
			_, err = ValidateUserToken(token.Key)
			require.ErrorIs(t, err, ErrTokenInvalid)
			require.NoError(t, token.SelectUpdate(), "retry must recover the committed disable")
			// A delayed resolver from the first mutation cannot remove a newer fence.
			require.NoError(t, setTokenMetadataFence(token.Key, token.MetadataRevision+1))
			operationErr := errors.New("old result")
			token.resolveMetadataOutcome(&operationErr, old.MetadataRevision+1)
			_, err = cacheInitToken(token)
			require.ErrorIs(t, err, ErrTokenMetadataStale)
		})
	}
}

func createReserveTestUser(t *testing.T, quota int) User {
	t.Helper()
	user := User{
		Username:    "reserve-user-" + common.GetRandomString(6),
		Password:    "unused-password-hash",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AuthVersion: 1,
		Quota:       quota,
		AffCode:     "reserve-aff-" + common.GetRandomString(8),
	}
	require.NoError(t, DB.Create(&user).Error)
	return user
}

func createReserveTestToken(t *testing.T, remainQuota int) Token {
	t.Helper()
	token := Token{
		UserId:      1,
		Key:         "reserve-token-" + common.GetRandomString(8),
		Name:        "reserve-test",
		Status:      common.TokenStatusEnabled,
		ExpiredTime: -1,
		RemainQuota: remainQuota,
	}
	require.NoError(t, token.Insert())
	return token
}

func getUserQuotaFromDB(t *testing.T, id int) int {
	t.Helper()
	var user User
	require.NoError(t, DB.Select("quota").First(&user, id).Error)
	return user.Quota
}

func getTokenFromDB(t *testing.T, id int) Token {
	t.Helper()
	var token Token
	require.NoError(t, DB.First(&token, id).Error)
	return token
}

func resetBatchUpdateTestState(t *testing.T) {
	t.Helper()
	oldBatchEnabled := common.BatchUpdateEnabled
	common.BatchUpdateEnabled = false
	for i := range BatchUpdateTypeCount {
		batchUpdateLocks[i].Lock()
		batchUpdateStores[i] = make(map[int]int)
		batchUpdateLocks[i].Unlock()
	}
	t.Cleanup(func() {
		common.BatchUpdateEnabled = oldBatchEnabled
		for i := range BatchUpdateTypeCount {
			batchUpdateLocks[i].Lock()
			batchUpdateStores[i] = make(map[int]int)
			batchUpdateLocks[i].Unlock()
		}
	})
}

func TestTryReserveQuotaWithoutRedis(t *testing.T) {
	truncateTables(t)
	resetBatchUpdateTestState(t)

	user := createReserveTestUser(t, 100)
	reserved, err := TryReserveUserQuota(user.Id, 60)
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, 40, getUserQuotaFromDB(t, user.Id))

	reserved, err = TryReserveUserQuota(user.Id, 41)
	require.NoError(t, err)
	assert.False(t, reserved)
	assert.Equal(t, 40, getUserQuotaFromDB(t, user.Id))

	token := createReserveTestToken(t, 80)
	reserved, err = TryReserveTokenQuota(token.Id, token.Key, 25, false)
	require.NoError(t, err)
	assert.True(t, reserved)
	reloaded := getTokenFromDB(t, token.Id)
	assert.Equal(t, 55, reloaded.RemainQuota)
	assert.Equal(t, 25, reloaded.UsedQuota)

	reserved, err = TryReserveTokenQuota(token.Id, token.Key, 56, false)
	require.NoError(t, err)
	assert.False(t, reserved)
	assert.Equal(t, 55, getTokenFromDB(t, token.Id).RemainQuota)
}

func TestRedisBatchReserveNeverFallsBackToStaleDatabaseBalance(t *testing.T) {
	truncateTables(t)
	resetBatchUpdateTestState(t)
	useUserCacheMiniRedis(t)
	common.BatchUpdateEnabled = true

	user := createReserveTestUser(t, 10)
	reserved, err := TryReserveUserQuota(user.Id, 8)
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, 10, getUserQuotaFromDB(t, user.Id), "batch delta is not flushed yet")

	reserved, err = TryReserveUserQuota(user.Id, 3)
	require.NoError(t, err)
	assert.False(t, reserved, "stale DB balance must not authorize a second spend")
	cachedUser, err := GetUserCache(user.Id)
	require.NoError(t, err)
	assert.Equal(t, 2, cachedUser.Quota)

	token := createReserveTestToken(t, 9)
	reserved, err = TryReserveTokenQuota(token.Id, token.Key, 7, false)
	require.NoError(t, err)
	assert.True(t, reserved)
	reserved, err = TryReserveTokenQuota(token.Id, token.Key, 3, false)
	require.NoError(t, err)
	assert.False(t, reserved)
	assert.Equal(t, 9, getTokenFromDB(t, token.Id).RemainQuota)

	batchUpdate()
	assert.Equal(t, 2, getUserQuotaFromDB(t, user.Id))
	reloadedToken := getTokenFromDB(t, token.Id)
	assert.Equal(t, 2, reloadedToken.RemainQuota)
	assert.Equal(t, 7, reloadedToken.UsedQuota)
}

func TestBatchUpdateAccumulatesTwoMaximumRequestCharges(t *testing.T) {
	truncateTables(t)
	resetBatchUpdateTestState(t)
	common.BatchUpdateEnabled = true

	user := createReserveTestUser(t, common.MaxQuota*2+100)
	require.NoError(t, DecreaseUserQuota(user.Id, common.MaxQuota, false))
	require.NoError(t, DecreaseUserQuota(user.Id, common.MaxQuota, false))

	batchUpdate()
	assert.Equal(t, 100, getUserQuotaFromDB(t, user.Id))
}

func TestBatchUpdateAccumulatorSaturatesOverflow(t *testing.T) {
	resetBatchUpdateTestState(t)

	addNewRecord(BatchUpdateTypeUserQuota, 1, math.MaxInt)
	addNewRecord(BatchUpdateTypeUserQuota, 1, 1)
	batchUpdateLocks[BatchUpdateTypeUserQuota].Lock()
	assert.Equal(t, math.MaxInt, batchUpdateStores[BatchUpdateTypeUserQuota][1])
	batchUpdateLocks[BatchUpdateTypeUserQuota].Unlock()

	batchUpdateLocks[BatchUpdateTypeUserQuota].Lock()
	batchUpdateStores[BatchUpdateTypeUserQuota] = make(map[int]int)
	batchUpdateLocks[BatchUpdateTypeUserQuota].Unlock()
	addNewRecord(BatchUpdateTypeUserQuota, 1, math.MinInt)
	addNewRecord(BatchUpdateTypeUserQuota, 1, -1)
	batchUpdateLocks[BatchUpdateTypeUserQuota].Lock()
	assert.Equal(t, math.MinInt, batchUpdateStores[BatchUpdateTypeUserQuota][1])
	batchUpdateLocks[BatchUpdateTypeUserQuota].Unlock()
}

func TestReserveFallsBackToDatabaseWhenRedisIsUnavailable(t *testing.T) {
	truncateTables(t)
	resetBatchUpdateTestState(t)
	server := useUserCacheMiniRedis(t)

	user := createReserveTestUser(t, 20)
	require.NoError(t, populateUserCache(user))
	server.Close()

	// Redis 故障时降级为数据库条件更新：服务保持可用且不会超扣。
	reserved, err := TryReserveUserQuota(user.Id, 5)
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, 15, getUserQuotaFromDB(t, user.Id))

	reserved, err = TryReserveUserQuota(user.Id, 16)
	require.NoError(t, err)
	assert.False(t, reserved)
	assert.Equal(t, 15, getUserQuotaFromDB(t, user.Id))
}

func TestSynchronousReserveCompensatesCacheWhenPersistenceFails(t *testing.T) {
	truncateTables(t)
	resetBatchUpdateTestState(t)
	useUserCacheMiniRedis(t)

	user := createReserveTestUser(t, 10)
	require.NoError(t, populateUserCache(user))
	require.NoError(t, DB.Delete(&user).Error)

	reserved, err := TryReserveUserQuota(user.Id, 6)
	assert.False(t, reserved)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	cached, cacheErr := cacheGetUserBase(user.Id)
	require.NoError(t, cacheErr)
	assert.Equal(t, 10, cached.Quota)

	token := createReserveTestToken(t, 12)
	_, err = GetTokenByKey(token.Key, true)
	require.NoError(t, err)
	require.NoError(t, DB.Delete(&token).Error)
	reserved, err = TryReserveTokenQuota(token.Id, token.Key, 7, false)
	assert.False(t, reserved)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	cachedToken, cacheErr := cacheGetTokenByKey(token.Key)
	require.NoError(t, cacheErr)
	assert.Equal(t, 12, cachedToken.RemainQuota)
	assert.Zero(t, cachedToken.UsedQuota)
}

func TestTokenCacheInitPreservesLiveQuotaAndFenceBlocksStaleSnapshot(t *testing.T) {
	truncateTables(t)
	resetBatchUpdateTestState(t)
	server := useUserCacheMiniRedis(t)
	common.SyncFrequency = 60

	token := createReserveTestToken(t, 100)
	loaded, err := GetTokenByKey(token.Key, true)
	require.NoError(t, err)
	stale := *loaded

	result, err := cacheApplyTokenQuotaDelta(token.Id, token.Key, -70)
	require.NoError(t, err)
	require.Equal(t, cacheQuotaOK, result)

	// 已存在的哈希只刷新 TTL：数据库快照不得覆盖已被原子预扣的余额。
	code, err := cacheInitToken(stale)
	require.NoError(t, err)
	assert.Equal(t, 2, code)
	cached, err := cacheGetTokenByKey(token.Key)
	require.NoError(t, err)
	assert.Equal(t, 30, cached.RemainQuota)

	// Fence retires metadata while retaining quota that includes outstanding deductions.
	require.NoError(t, invalidateTokenCacheForMutation(token.Key))
	code, err = cacheInitToken(stale)
	require.NoError(t, err)
	assert.Zero(t, code, "the pre-mutation snapshot must not be published while fenced")
	_, err = cacheGetTokenByKey(token.Key)
	assert.Error(t, err)

	// fence 过期后可重新从数据库水合。
	server.FastForward(time.Duration(tokenCacheFenceSeconds+1) * time.Second)
	fresh, err := GetTokenByKey(token.Key, false)
	require.NoError(t, err)
	assert.Equal(t, 100, fresh.RemainQuota)
	cached, err = cacheGetTokenByKey(token.Key)
	require.NoError(t, err)
	assert.Equal(t, 30, cached.RemainQuota, "metadata refresh must preserve outstanding reservations")
}
