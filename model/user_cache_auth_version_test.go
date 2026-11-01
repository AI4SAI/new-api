package model

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func useUserCacheMiniRedis(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	server := miniredis.RunT(t)
	oldRedisEnabled := common.RedisEnabled
	oldRDB := common.RDB
	oldSyncFrequency := common.SyncFrequency
	common.RedisEnabled = true
	common.SyncFrequency = 2
	common.RDB = redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = common.RDB.Close()
		common.RedisEnabled = oldRedisEnabled
		common.RDB = oldRDB
		common.SyncFrequency = oldSyncFrequency
	})
	return server
}

func TestManagedExecutionProjectionPreservesQuotaAndFencesStaleCache(t *testing.T) {
	truncateTables(t)
	server := useUserCacheMiniRedis(t)
	ref := "personal:11111111-1111-4111-8111-111111111111"
	playground := "22222222-2222-4222-8222-222222222222"
	user := User{Username: "execution-owner", Role: common.RoleCommonUser, Status: common.UserStatusEnabled,
		Quota: 100, UsedQuota: 5, RequestCount: 3, AuthVersion: 1, PlaygroundBillingContextRef: &playground}
	require.NoError(t, DB.Create(&user).Error)
	require.NoError(t, ClaimExternalIdentityWithTx(DB, "managed-account", ref, user.Id))
	require.NoError(t, populateUserCache(user))
	require.NoError(t, cacheDecrUserQuota(user.Id, 30))
	req := ManagedExecutionUpdate{UserID: user.Id, AccountRef: ref, Revision: 1, ValidUntil: common.GetTimestamp() + 600, PolicyEpoch: "3"}
	first, err := UpdateManagedExecution(req)
	require.NoError(t, err)
	replayed, err := UpdateManagedExecution(req)
	require.NoError(t, err)
	assert.Equal(t, first, replayed)
	cached, err := GetUserCache(user.Id)
	require.NoError(t, err)
	assert.Equal(t, 70, cached.Quota, "metadata must retain pending native quota deltas")
	assert.EqualValues(t, 1, cached.AuthVersion)
	assert.EqualValues(t, 1, cached.ModelExecutionRevision)
	assert.Equal(t, "3", cached.ModelPolicyEpoch)
	assert.Equal(t, playground, cached.PlaygroundBillingContextRef)
	context, _ := gin.CreateTestContext(nil)
	cached.WriteContext(context)
	assert.Equal(t, req.ValidUntil, context.GetInt64("model_execution_until"))
	assert.Equal(t, "3", context.GetString("model_policy_epoch"))
	assert.Equal(t, playground, context.GetString("playground_billing_context_ref"))
	stale := *cached
	req.ExpectedRevision, req.Revision, req.ValidUntil, req.PolicyEpoch = 1, 2, 0, "4"
	_, err = UpdateManagedExecution(req)
	require.NoError(t, err)
	require.ErrorIs(t, writeUserCache(&stale, true), ErrModelExecutionCachePending)
	var queries atomic.Int64
	callback := "test:execution_cache_no_sql"
	require.NoError(t, DB.Callback().Query().Before("gorm:query").Register(callback, func(*gorm.DB) { queries.Add(1) }))
	cached, err = GetUserCache(user.Id)
	require.NoError(t, err)
	require.NoError(t, DB.Callback().Query().Remove(callback))
	assert.Zero(t, queries.Load())
	assert.Zero(t, cached.ModelExecutionUntil)
	assert.Equal(t, 70, cached.Quota)
	// A delayed fill cannot revive an expired/revoked projection after hash TTL.
	server.FastForward(time.Duration(userAuthFenceTTLSeconds()+1) * time.Second)
	require.ErrorIs(t, writeUserCache(&stale, true), ErrModelExecutionCachePending)
	cached, err = GetUserCache(user.Id)
	require.NoError(t, err)
	assert.EqualValues(t, 2, cached.ModelExecutionRevision)
	assert.Zero(t, cached.ModelExecutionUntil)
	require.NoError(t, setUserCacheVersionFence(getModelExecutionFenceKey(user.Id), 3))
	queries.Store(0)
	require.NoError(t, DB.Callback().Query().Before("gorm:query").Register(callback, func(*gorm.DB) { queries.Add(1) }))
	cached, err = GetUserCache(user.Id)
	require.NoError(t, err)
	require.NoError(t, DB.Callback().Query().Remove(callback))
	assert.Zero(t, queries.Load(), "pending model projection must not force warm identity reads into SQL")
	assert.Equal(t, common.UserStatusEnabled, cached.Status)
	assert.Zero(t, cached.ModelExecutionUntil)
	_, err = ReadManagedExecution(user.Id, ref)
	require.ErrorIs(t, err, ErrModelExecutionCachePending, "control read must not acknowledge an unconfirmed projection")
	require.NoError(t, SetUserAuthVersionFence(user.Id, 2))
	_, err = GetUserCache(user.Id)
	require.ErrorIs(t, err, ErrUserAuthCachePending, "independent authentication revocation remains enforced")
	server.FastForward(time.Duration(userAuthFenceTTLSeconds()+1) * time.Second)
	cached, err = GetUserCache(user.Id)
	require.NoError(t, err)
	assert.EqualValues(t, 2, cached.ModelExecutionRevision)
	// Ordinary profile writes cannot bypass the dedicated projection CAS.
	user.ModelExecutionRevision, user.ModelExecutionUntil, user.ModelPolicyEpoch = 99, common.GetTimestamp()+1000, "99"
	require.NoError(t, user.Update(false))
	assert.EqualValues(t, 2, user.ModelExecutionRevision)
	assert.Zero(t, user.ModelExecutionUntil)
	assert.Equal(t, "4", user.ModelPolicyEpoch)
	assert.Equal(t, 100, user.Quota)
	assert.Equal(t, 5, user.UsedQuota)
	assert.Equal(t, 3, user.RequestCount)
	assert.EqualValues(t, 1, user.AuthVersion)
	// A lost Redis publication acknowledgement does not poison human identity.
	hook := &quotaReplyLossHook{scriptMatch: "ModelExecutionRevision"}
	common.RDB.AddHook(hook)
	req.ExpectedRevision, req.Revision = 2, 3
	_, err = UpdateManagedExecution(req)
	require.True(t, hook.fired)
	require.ErrorContains(t, err, "acknowledgement lost")
	cached, err = GetUserCache(user.Id)
	require.NoError(t, err)
	assert.Equal(t, common.UserStatusEnabled, cached.Status)
	assert.EqualValues(t, 1, cached.AuthVersion)
	assert.Zero(t, cached.ModelExecutionUntil)
	_, err = ReadManagedExecution(user.Id, ref)
	require.NoError(t, err)
	req.ExpectedRevision, req.Revision, req.ValidUntil = 3, 4, common.GetTimestamp()+600
	_, err = UpdateManagedExecution(req)
	require.NoError(t, err)
	cached, err = GetUserCache(user.Id)
	require.NoError(t, err)
	assert.Equal(t, req.ValidUntil, cached.ModelExecutionUntil)
}

func TestUserAuthFenceRollbackExpiresAndRecovers(t *testing.T) {
	truncateTables(t)
	server := useUserCacheMiniRedis(t)

	user := User{
		Username:    "auth-fence-rollback",
		Password:    "password",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AuthVersion: 1,
	}
	require.NoError(t, DB.Create(&user).Error)
	require.NoError(t, populateUserCache(user))

	tx := DB.Begin()
	require.NoError(t, tx.Error)
	next, err := IncrementUserAuthVersionWithTx(tx, user.Id)
	require.NoError(t, err)
	assert.EqualValues(t, 2, next)

	_, err = cacheGetUserBase(user.Id)
	assert.ErrorIs(t, err, ErrUserAuthCachePending)
	cacheTTL, err := common.RDB.TTL(t.Context(), getUserCacheKey(user.Id)).Result()
	require.NoError(t, err)
	fenceTTL, err := common.RDB.TTL(t.Context(), getUserAuthFenceKey(user.Id)).Result()
	require.NoError(t, err)
	assert.Greater(t, fenceTTL, cacheTTL)
	require.NoError(t, tx.Rollback().Error)

	server.FastForward(time.Duration(userAuthFenceTTLSeconds()+1) * time.Second)
	assert.False(t, server.Exists(getUserAuthFenceKey(user.Id)))
	committed, err := common.RDB.Get(t.Context(), getUserAuthVersionKey(user.Id)).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", committed)

	cached, err := GetUserCache(user.Id)
	require.NoError(t, err)
	assert.EqualValues(t, 1, cached.AuthVersion)
}

func TestPendingUserAuthFenceRejectsStaleCacheWrite(t *testing.T) {
	server := useUserCacheMiniRedis(t)
	const userID = 4201
	require.NoError(t, SetUserAuthVersionFence(userID, 2))

	err := writeUserCache(&UserBase{
		Id: userID, Group: "default", Username: "stale", AuthVersion: 1,
	}, true)

	assert.ErrorIs(t, err, ErrUserAuthCachePending)
	assert.False(t, server.Exists(getUserCacheKey(userID)))
}

func TestUserAuthFieldUpdateRejectsVersionMismatch(t *testing.T) {
	useUserCacheMiniRedis(t)
	const userID = 4202
	require.NoError(t, writeUserCache(&UserBase{
		Id: userID, Group: "current", Username: "cached", AuthVersion: 3,
	}, true))

	err := updateUserCacheFieldAtVersion(userID, "Group", "stale", 2)

	assert.ErrorIs(t, err, ErrUserAuthCachePending)
	group, err := common.RDB.HGet(t.Context(), getUserCacheKey(userID), "Group").Result()
	require.NoError(t, err)
	assert.Equal(t, "current", group)
}

func TestRefreshUserGroupCacheRepairsDelayedSameVersionWrite(t *testing.T) {
	truncateTables(t)
	useUserCacheMiniRedis(t)

	user := User{
		Username:    "delayed-group-refresh",
		Password:    "password",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AuthVersion: 1,
	}
	require.NoError(t, DB.Create(&user).Error)
	require.NoError(t, populateUserCache(user))

	firstSnapshotRead := make(chan struct{})
	releaseDelayedRefresh := make(chan struct{})
	var intercepted atomic.Bool
	const callbackName = "test:block_delayed_group_refresh"
	require.NoError(t, DB.Callback().Query().After("gorm:query").Register(callbackName, func(*gorm.DB) {
		if intercepted.CompareAndSwap(false, true) {
			close(firstSnapshotRead)
			<-releaseDelayedRefresh
		}
	}))
	t.Cleanup(func() {
		_ = DB.Callback().Query().Remove(callbackName)
	})

	delayedResult := make(chan error, 1)
	go func() {
		delayedResult <- RefreshUserGroupCache(user.Id)
	}()
	<-firstSnapshotRead

	require.NoError(t, DB.Model(&User{}).Where("id = ?", user.Id).Update("group", "pro").Error)
	require.NoError(t, RefreshUserGroupCache(user.Id))
	cached, err := cacheGetUserBase(user.Id)
	require.NoError(t, err)
	assert.Equal(t, "pro", cached.Group)
	assert.EqualValues(t, 1, cached.AuthVersion)

	close(releaseDelayedRefresh)
	require.NoError(t, <-delayedResult)
	cached, err = cacheGetUserBase(user.Id)
	require.NoError(t, err)
	assert.Equal(t, "pro", cached.Group)
	assert.EqualValues(t, 1, cached.AuthVersion)
}

func TestCommittedUserAuthVersionPermanentlyRejectsDelayedCacheFill(t *testing.T) {
	truncateTables(t)
	server := useUserCacheMiniRedis(t)

	user := User{
		Username:    "auth-fence-commit",
		Password:    "password",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AuthVersion: 1,
	}
	require.NoError(t, DB.Create(&user).Error)
	require.NoError(t, populateUserCache(user))
	stale := *user.ToBaseUser()

	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		_, err := IncrementUserAuthVersionWithTx(tx, user.Id)
		return err
	}))
	require.NoError(t, PublishUserAuthCache(user.Id))
	assert.False(t, server.Exists(getUserAuthFenceKey(user.Id)))
	committed, err := common.RDB.Get(t.Context(), getUserAuthVersionKey(user.Id)).Result()
	require.NoError(t, err)
	assert.Equal(t, "2", committed)

	server.FastForward(time.Duration(userAuthFenceTTLSeconds()+1) * time.Second)
	require.NoError(t, common.RedisDelKey(getUserCacheKey(user.Id)))
	err = writeUserCache(&stale, true)
	assert.True(t, errors.Is(err, ErrUserAuthCachePending))
	committed, err = common.RDB.Get(t.Context(), getUserAuthVersionKey(user.Id)).Result()
	require.NoError(t, err)
	assert.Equal(t, "2", committed)
}

func TestUserAuthVersionFenceAndCommittedFloorAreMonotonic(t *testing.T) {
	truncateTables(t)
	server := useUserCacheMiniRedis(t)

	const userID = 4101
	require.NoError(t, SetUserAuthVersionFence(userID, 5))
	require.NoError(t, SetUserAuthVersionFence(userID, 3))
	pending, err := common.RDB.Get(t.Context(), getUserAuthFenceKey(userID)).Result()
	require.NoError(t, err)
	assert.Equal(t, "5", pending)
	floor, _, err := getUserCacheVersionFloors(userID)
	require.NoError(t, err)
	assert.EqualValues(t, 5, floor)

	// Committing an older transaction must neither clear a newer pending fence
	// nor lower the effective deny floor.
	require.NoError(t, publishCommittedUserAuthVersion(userID, 3))
	pending, err = common.RDB.Get(t.Context(), getUserAuthFenceKey(userID)).Result()
	require.NoError(t, err)
	assert.Equal(t, "5", pending)
	floor, _, err = getUserCacheVersionFloors(userID)
	require.NoError(t, err)
	assert.EqualValues(t, 5, floor)

	require.NoError(t, publishCommittedUserAuthVersion(userID, 5))
	assert.False(t, server.Exists(getUserAuthFenceKey(userID)))
	committed, err := common.RDB.Get(t.Context(), getUserAuthVersionKey(userID)).Result()
	require.NoError(t, err)
	assert.Equal(t, "5", committed)

	require.NoError(t, publishCommittedUserAuthVersion(userID, 4))
	committed, err = common.RDB.Get(t.Context(), getUserAuthVersionKey(userID)).Result()
	require.NoError(t, err)
	assert.Equal(t, "5", committed)
}
