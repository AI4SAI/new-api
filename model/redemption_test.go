package model

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func managedReclaimFixture(t *testing.T, used bool) (User, Redemption, ManagedReclaimRequest) {
	t.Helper()
	truncateTables(t)
	resetBatchUpdateTestState(t)
	useTokenAdjustmentRedis(t)
	require.NoError(t, DB.AutoMigrate(&User{}, &Redemption{}, &ExternalIdentityClaim{}))
	user := createReserveTestUser(t, 100)
	user.UsedQuota, user.RequestCount, user.ModelExecutionRevision = 17, 4, 2
	require.NoError(t, DB.Model(&user).Updates(map[string]any{"used_quota": 17, "request_count": 4, "model_execution_revision": 2}).Error)
	require.NoError(t, ClaimExternalIdentityWithTx(DB, "managed-account", fmt.Sprintf("account-%d", user.Id), user.Id))
	ref, revision := uuid.NewString(), int64(1)
	grant := Redemption{UserId: 999, Key: common.GetUUID(), Name: "reclaim-original", Quota: 100, ManagedGrantRef: &ref,
		ManagedOwnerID: user.Id, ManagedExecutionRevision: &revision, Status: common.RedemptionCodeStatusEnabled}
	amount := 100
	if used {
		grant.Status, grant.UsedUserId, amount = common.RedemptionCodeStatusUsed, user.Id, 80
	}
	require.NoError(t, DB.Create(&grant).Error)
	t.Cleanup(func() { DB.Unscoped().Delete(&grant) })
	require.NoError(t, populateUserCache(user))
	return user, grant, ManagedReclaimRequest{GrantRef: ref, UserID: user.Id, Quota: &amount, ExpectedExecutionRevision: &user.ModelExecutionRevision}
}

func TestManagedReclaimPreservesInflightDeltasAndResolvesUnknownResults(t *testing.T) {
	for _, stage := range []string{"normal", "redis_reply_lost", "redis_before_eval", "db_commit_reply_lost", "db_commit_unknown", "db_rollback"} {
		t.Run(stage, func(t *testing.T) {
			user, grant, request := managedReclaimFixture(t, true)
			key := Token{UserId: user.Id, Key: common.GetUUID(), Status: common.TokenStatusEnabled, RemainQuota: 87, UsedQuota: 13}
			require.NoError(t, DB.Create(&key).Error)
			// The cache includes a real in-flight deduction absent from the DB.
			common.BatchUpdateEnabled = true
			reserved, reserveErr := TryReserveUserQuota(user.Id, 70)
			require.NoError(t, reserveErr)
			require.True(t, reserved)
			assert.Equal(t, 100, getUserQuotaFromDB(t, user.Id))
			original := DB
			if stage == "redis_reply_lost" || stage == "redis_before_eval" {
				common.RDB.AddHook(&quotaReplyLossHook{scriptMatch: "local reclaimed = tonumber(ARGV[17])", before: stage == "redis_before_eval"})
			} else if stage == "db_commit_reply_lost" || stage == "db_commit_unknown" || stage == "db_rollback" {
				faulted := DB.Session(&gorm.Session{NewDB: true, Context: context.Background()})
				faulted.Statement.ConnPool = &quotaCommitFaultPool{ConnPool: original.Statement.ConnPool,
					commitApplied: stage != "db_rollback", readbackFails: stage == "db_commit_unknown"}
				DB = faulted
			}
			receipt, err := ReclaimManagedRedemption(request)
			DB = original
			if stage == "normal" || stage == "db_commit_reply_lost" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			if stage == "db_rollback" {
				assert.Equal(t, 100, getUserQuotaFromDB(t, user.Id))
				cached, cacheErr := cacheGetUserBase(user.Id)
				require.NoError(t, cacheErr)
				assert.Equal(t, 30, cached.Quota)
			}
			receipt, err = ReclaimManagedRedemption(request)
			require.NoError(t, err)
			assert.True(t, receipt.Completed)
			assert.Equal(t, "reclaimed", receipt.Outcome)
			assert.Equal(t, 100, receipt.QuotaBefore)
			assert.Equal(t, 20, receipt.QuotaAfter)
			assert.Equal(t, 80, receipt.ReclaimedQuota)
			repeated, err := ReadManagedRedemptionReclaim(request.GrantRef, user.Id)
			require.NoError(t, err)
			assert.Equal(t, receipt, repeated)
			cached, err := cacheGetUserBase(user.Id)
			require.NoError(t, err)
			assert.Equal(t, -50, cached.Quota)
			require.NoError(t, cacheIncrUserQuota(user.Id, 20)) // Original request refund remains independent.
			addNewRecord(BatchUpdateTypeUserQuota, user.Id, 20)
			batchUpdate()
			repeated, err = ReclaimManagedRedemption(request)
			require.NoError(t, err)
			assert.Equal(t, receipt, repeated)
			cached, err = cacheGetUserBase(user.Id)
			require.NoError(t, err)
			assert.Equal(t, -30, cached.Quota)
			stored, err := GetUserById(user.Id, false)
			require.NoError(t, err)
			assert.Equal(t, -30, stored.Quota)
			assert.Equal(t, user.UsedQuota, stored.UsedQuota)
			assert.Equal(t, user.RequestCount, stored.RequestCount)
			assert.Equal(t, user.Status, stored.Status)
			var preserved Token
			require.NoError(t, DB.First(&preserved, key.Id).Error)
			assert.Equal(t, key.Key, preserved.Key)
			assert.Equal(t, key.Status, preserved.Status)
			assert.Equal(t, key.RemainQuota, preserved.RemainQuota)
			assert.Equal(t, key.UsedQuota, preserved.UsedQuota)
			conflicting := request
			other := 79
			conflicting.Quota = &other
			_, err = ReclaimManagedRedemption(conflicting)
			require.ErrorIs(t, err, ErrManagedReclaimConflict)
			_, err = Redeem(grant.Key, user.Id)
			require.Error(t, err)
		})
	}
}

func TestManagedReclaimRejectsDelayedPopulationAndSurvivesColdCache(t *testing.T) {
	user, _, request := managedReclaimFixture(t, true)
	receipt, err := ReclaimManagedRedemption(request)
	require.NoError(t, err)
	// Simulate natural hash expiry. The committed total floor is not expiring.
	require.NoError(t, common.RDB.Expire(t.Context(), getUserCacheKey(user.Id), time.Nanosecond).Err())
	require.NoError(t, common.RDB.Del(t.Context(), getUserCacheKey(user.Id)).Err())
	require.ErrorIs(t, populateUserCache(user), ErrUserQuotaReclaimPending)
	cached, err := GetUserCache(user.Id)
	require.NoError(t, err)
	assert.Equal(t, 20, cached.Quota)
	repeated, err := ReclaimManagedRedemption(request)
	require.NoError(t, err)
	assert.Equal(t, receipt, repeated)
	cached, err = cacheGetUserBase(user.Id)
	require.NoError(t, err)
	assert.Equal(t, 20, cached.Quota)
	// A pending reclaim blocks reservation but does not block in-flight refunds.
	require.NoError(t, setUserQuotaReclaimFence(user.Id, 90))
	identity, identityErr := GetUserCache(user.Id)
	require.NoError(t, identityErr)
	assert.Equal(t, user.Username, identity.Username)
	assert.Zero(t, identity.ModelExecutionUntil)
	reserved, err := TryReserveUserQuota(user.Id, 1)
	require.ErrorIs(t, err, ErrUserQuotaReclaimPending)
	assert.False(t, reserved)
	require.NoError(t, cacheIncrUserQuota(user.Id, 3))
	require.NoError(t, resolveUserQuotaReclaimFence(user.Id, 80, 80))
	assert.Equal(t, "90", common.RDB.Get(t.Context(), getUserQuotaReclaimFenceKey(user.Id)).Val())
}

func TestManagedReclaimCancellationAndZeroCloseDoNotReopenGrant(t *testing.T) {
	for _, used := range []bool{false, true} {
		t.Run(fmt.Sprint(used), func(t *testing.T) {
			user, grant, request := managedReclaimFixture(t, used)
			if used {
				zero := 0
				request.Quota = &zero
			}
			value, err := ReclaimManagedRedemption(request)
			require.NoError(t, err)
			assert.True(t, value.Completed)
			assert.Equal(t, 100, value.QuotaBefore)
			assert.Equal(t, 100, value.QuotaAfter)
			if used {
				assert.Equal(t, "reclaimed", value.Outcome)
			} else {
				assert.Equal(t, "cancelled", value.Outcome)
			}
			repeat, err := ReclaimManagedRedemption(request)
			require.NoError(t, err)
			assert.Equal(t, value, repeat)
			_, err = Redeem(grant.Key, user.Id)
			require.Error(t, err)
			assert.Equal(t, 100, getUserQuotaFromDB(t, user.Id))
		})
	}
}

func TestManagedGrantRenewalPreservesDeliveryAndOffFencesOriginalAttempt(t *testing.T) {
	user, grant, request := managedReclaimFixture(t, false)
	// Grant at revision1 survives a normal positive execution renewal to2.
	require.NoError(t, DB.Model(&User{}).Where("id = ?", user.Id).Update("model_execution_until", common.GetTimestamp()+60).Error)
	_, err := Redeem(grant.Key, user.Id)
	require.NoError(t, err)
	ref := uuid.NewString()
	missing, err := ReadManagedRedemptionReclaim(ref, user.Id)
	require.NoError(t, err)
	assert.False(t, missing.Exists)
	request.GrantRef = ref
	_, err = ReclaimManagedRedemption(request)
	require.ErrorIs(t, err, ErrManagedReclaimConflict)
	require.NoError(t, DB.Model(&User{}).Where("id = ?", user.Id).Updates(map[string]any{
		"model_execution_until": 0, "model_execution_revoked_revision": 2}).Error)
	closed, err := ReclaimManagedRedemption(request)
	require.NoError(t, err)
	assert.Equal(t, "cancelled", closed.Outcome)
	assert.Equal(t, 200, closed.QuotaAfter)
	repeat, err := ReclaimManagedRedemption(request)
	require.NoError(t, err)
	assert.Equal(t, closed, repeat)
	assert.Equal(t, 200, getUserQuotaFromDB(t, user.Id))
}

func TestSearchRedemptionsFiltersAndPaginates(t *testing.T) {
	require.NoError(t, DB.AutoMigrate(&Redemption{}))
	require.NoError(t, DB.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(&Redemption{}).Error)
	t.Cleanup(func() {
		require.NoError(t, DB.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(&Redemption{}).Error)
	})

	now := common.GetTimestamp()
	redemptions := []Redemption{
		{Id: 1, Name: "alpha-active", Key: "00000000000000000000000000000001", Status: common.RedemptionCodeStatusEnabled, ExpiredTime: 0},
		{Id: 2, Name: "alpha-future", Key: "00000000000000000000000000000002", Status: common.RedemptionCodeStatusEnabled, ExpiredTime: now + 3600},
		{Id: 3, Name: "alpha-expired", Key: "00000000000000000000000000000003", Status: common.RedemptionCodeStatusEnabled, ExpiredTime: now - 10},
		{Id: 4, Name: "beta-disabled", Key: "00000000000000000000000000000004", Status: common.RedemptionCodeStatusDisabled, ExpiredTime: 0},
		{Id: 5, Name: "beta-used", Key: "00000000000000000000000000000005", Status: common.RedemptionCodeStatusUsed, ExpiredTime: 0},
	}
	require.NoError(t, DB.Create(&redemptions).Error)

	tests := []struct {
		name      string
		keyword   string
		status    string
		startIdx  int
		num       int
		wantTotal int64
		wantIds   []int
	}{
		{
			name:      "no filters returns all rows",
			num:       10,
			wantTotal: 5,
			wantIds:   []int{5, 4, 3, 2, 1},
		},
		{
			name:      "keyword filters by name prefix",
			keyword:   "alpha",
			num:       10,
			wantTotal: 3,
			wantIds:   []int{3, 2, 1},
		},
		{
			name:      "enabled status excludes expired rows",
			status:    "1",
			num:       10,
			wantTotal: 2,
			wantIds:   []int{2, 1},
		},
		{
			name:      "expired status returns enabled expired rows",
			status:    "expired",
			num:       10,
			wantTotal: 1,
			wantIds:   []int{3},
		},
		{
			name:      "disabled status",
			status:    "2",
			num:       10,
			wantTotal: 1,
			wantIds:   []int{4},
		},
		{
			name:      "used status",
			status:    "3",
			num:       10,
			wantTotal: 1,
			wantIds:   []int{5},
		},
		{
			name:      "pagination keeps unpaged total",
			startIdx:  1,
			num:       2,
			wantTotal: 5,
			wantIds:   []int{4, 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows, total, err := SearchRedemptions(tt.keyword, tt.status, tt.startIdx, tt.num)
			require.NoError(t, err)
			assert.Equal(t, tt.wantTotal, total)
			gotIds := make([]int, 0, len(rows))
			for _, row := range rows {
				gotIds = append(gotIds, row.Id)
			}
			assert.Equal(t, tt.wantIds, gotIds)
		})
	}
}

func setupRedeemFixture(t *testing.T, quota int) (userId int, key string) {
	t.Helper()
	require.NoError(t, DB.AutoMigrate(&Redemption{}))
	require.NoError(t, DB.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(&Redemption{}).Error)
	t.Cleanup(func() {
		require.NoError(t, DB.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(&Redemption{}).Error)
		DB.Exec("DELETE FROM users")
		DB.Exec("DELETE FROM logs")
	})

	user := &User{Username: "redeem-user", Password: "password", Status: common.UserStatusEnabled, Quota: 0}
	require.NoError(t, DB.Create(user).Error)

	key = "10000000000000000000000000000001"
	redemption := &Redemption{
		Name:        "redeem-test",
		Key:         key,
		Status:      common.RedemptionCodeStatusEnabled,
		Quota:       quota,
		CreatedTime: common.GetTimestamp(),
	}
	require.NoError(t, DB.Create(redemption).Error)
	return user.Id, key
}

func TestRedeemCreditsQuotaExactlyOnce(t *testing.T) {
	userId, key := setupRedeemFixture(t, 500)

	quota, err := Redeem(key, userId)
	require.NoError(t, err)
	assert.Equal(t, 500, quota)

	var user User
	require.NoError(t, DB.First(&user, "id = ?", userId).Error)
	assert.Equal(t, 500, user.Quota)

	var redemption Redemption
	require.NoError(t, DB.First(&redemption, "name = ?", "redeem-test").Error)
	assert.Equal(t, common.RedemptionCodeStatusUsed, redemption.Status)
	assert.Equal(t, userId, redemption.UsedUserId)

	// Redeeming the same code again must fail and must not credit quota.
	_, err = Redeem(key, userId)
	require.Error(t, err)
	require.NoError(t, DB.First(&user, "id = ?", userId).Error)
	assert.Equal(t, 500, user.Quota)
}

func TestRedeemRejectsWalletOverflow(t *testing.T) {
	userId, key := setupRedeemFixture(t, 11)
	require.NoError(t, DB.Model(&User{}).Where("id = ?", userId).Update("quota", common.MaxWalletQuota-10).Error)

	_, err := Redeem(key, userId)
	require.ErrorIs(t, err, ErrRedeemFailed)

	var user User
	require.NoError(t, DB.First(&user, "id = ?", userId).Error)
	assert.Equal(t, common.MaxWalletQuota-10, user.Quota)

	var redemption Redemption
	require.NoError(t, DB.First(&redemption, "key = ?", key).Error)
	assert.Equal(t, common.RedemptionCodeStatusEnabled, redemption.Status)
}

func TestRedemptionQuotaRejectsWalletOverflow(t *testing.T) {
	setupRedeemFixture(t, 500)

	redemption := &Redemption{
		Name:        "overflow-redemption",
		Key:         "10000000000000000000000000000002",
		Status:      common.RedemptionCodeStatusEnabled,
		Quota:       common.MaxWalletQuota + 1,
		CreatedTime: common.GetTimestamp(),
	}
	require.Error(t, redemption.Insert())
}

// Exactly one of several concurrent redeems of the same code may win, and
// quota must be credited exactly once.
func TestRedeemConcurrentSingleSuccess(t *testing.T) {
	userId, key := setupRedeemFixture(t, 300)

	const goroutines = 5
	successes := make([]bool, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			if _, err := Redeem(key, userId); err == nil {
				successes[idx] = true
			}
		}(i)
	}
	wg.Wait()

	successCount := 0
	for _, ok := range successes {
		if ok {
			successCount++
		}
	}
	assert.Equal(t, 1, successCount, "exactly one concurrent redeem should succeed")

	var user User
	require.NoError(t, DB.First(&user, "id = ?", userId).Error)
	assert.Equal(t, 300, user.Quota, "quota must be credited exactly once")
}
