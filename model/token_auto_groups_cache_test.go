package model

import (
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenAutoGroupsRoundTripThroughRedisHashCache(t *testing.T) {
	useUserCacheMiniRedis(t)
	ref := "22222222-2222-4222-8222-222222222222"
	token := Token{
		Id:                      42,
		UserId:                  7,
		Key:                     "token-auto-groups-cache-key",
		Name:                    "auto-cache",
		Group:                   "auto",
		AutoGroups:              `["vip","default"]`,
		ManagedBindingRef:       "11111111-1111-4111-8111-111111111111",
		ManagementCreatorID:     7,
		QuotaRevision:           2,
		BillingContextRef:       &ref,
		BillingContextConfirmed: true,
	}

	require.NoError(t, cacheSetTokenForTest(token))
	cached, err := cacheGetTokenByKey(token.Key)
	require.NoError(t, err)
	assert.Equal(t, token.AutoGroups, cached.AutoGroups)
	assert.Equal(t, token.ManagedBindingRef, cached.ManagedBindingRef)
	assert.Equal(t, token.ManagementCreatorID, cached.ManagementCreatorID)
	assert.Equal(t, token.QuotaRevision, cached.QuotaRevision)
	require.Equal(t, token.BillingContextRef, cached.BillingContextRef)
	assert.True(t, cached.BillingContextConfirmed)
	groups, err := cached.GetAutoGroups()
	require.NoError(t, err)
	assert.Equal(t, []string{"vip", "default"}, groups)
}

func TestTokenAllowUserQuotaQueryRoundTripsThroughRedisHashCache(t *testing.T) {
	server := useUserCacheMiniRedis(t)
	token := Token{Id: 43, UserId: 7, Key: "token-user-quota-cache-key", Name: "user-quota-cache", AllowUserQuotaQuery: true}

	initialized, err := cacheInitToken(token)
	require.NoError(t, err)
	require.Equal(t, 1, initialized)
	cached, err := cacheGetTokenByKey(token.Key)
	require.NoError(t, err)
	assert.True(t, cached.AllowUserQuotaQuery)
	assert.Positive(t, server.TTL(getTokenCacheKey(token.Key)))
}

func TestTokenUpdateSynchronouslyNarrowsPreheatedAutoGroupsCache(t *testing.T) {
	truncateTables(t)
	server := useUserCacheMiniRedis(t)
	token := Token{
		UserId:          7,
		Key:             "token-auto-groups-update-cache-key",
		Name:            "auto-cache-update",
		Status:          common.TokenStatusEnabled,
		ExpiredTime:     -1,
		UnlimitedQuota:  true,
		Group:           "auto",
		CrossGroupRetry: true,
		AutoGroups:      `["default","vip"]`,
	}
	require.NoError(t, token.Insert())
	require.NoError(t, cacheSetTokenForTest(token))

	preheated, err := cacheGetTokenByKey(token.Key)
	require.NoError(t, err)
	assert.JSONEq(t, `["default","vip"]`, preheated.AutoGroups)

	require.NoError(t, token.SetAutoGroups([]string{"vip"}))
	require.NoError(t, token.Update())
	// Metadata is invalidated without dropping outstanding quota reservations;
	// the next authenticated read must observe the narrowed groups.
	_, cacheErr := cacheGetTokenByKey(token.Key)
	require.Error(t, cacheErr, "the pre-update cache entry must be invalidated")
	reloaded, err := GetTokenByKey(token.Key, false)
	require.NoError(t, err)
	assert.JSONEq(t, `["vip"]`, reloaded.AutoGroups)
	require.NoError(t, cacheSetTokenForTest(*reloaded))
	old := *reloaded
	reloaded.Status = common.TokenStatusDisabled
	require.NoError(t, reloaded.SelectUpdate())
	server.FastForward(5 * time.Minute)
	_, err = cacheInitToken(old)
	require.ErrorIs(t, err, ErrTokenMetadataStale)
	_, err = ValidateUserToken(token.Key)
	require.ErrorIs(t, err, ErrTokenInvalid)

}

// cacheSetTokenForTest 以测试身份写入完整 token 缓存（含额度字段），
// 模拟“已水合”的缓存状态。
func cacheSetTokenForTest(token Token) error {
	_, err := cacheInitToken(token)
	return err
}
