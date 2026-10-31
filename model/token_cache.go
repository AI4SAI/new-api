package model

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/QuantumNous/new-api/common"
)

func getTokenCacheKey(key string) string {
	return fmt.Sprintf("token:%s", common.GenerateHMAC(key))
}

func getTokenCacheFenceKey(key string) string {
	return fmt.Sprintf("token:fence:%s", common.GenerateHMAC(key))
}

func tokenCacheTTLSeconds() int {
	ttl := common.RedisKeyCacheSeconds()
	if ttl <= 0 {
		return 60
	}
	return ttl
}

// tokenCacheFenceSeconds must outlive a token mutation's database write plus
// any in-flight reader's DB-read-to-cache-init gap. The fence is not deleted
// after commit; it expires naturally so a reader holding a pre-mutation
// snapshot cannot publish it right after the mutation cleared the cache.
// While the fence exists readers simply serve the database without caching.
const tokenCacheFenceSeconds = 10

// invalidateTokenCacheForMutation is called before a token metadata mutation
// writes to the database: it raises the fence and invalidates metadata while preserving outstanding
// quota reservations, so no
// reader can act on (or re-publish) the pre-mutation metadata.
func invalidateTokenCacheForMutation(key string) error {
	if !common.RedisEnabled || key == "" {
		return nil
	}
	ctx := context.Background()
	err := common.RDB.Set(ctx, getTokenCacheFenceKey(key), 1, time.Duration(tokenCacheFenceSeconds)*time.Second).Err()
	if err != nil {
		return err
	}
	return common.RDB.Eval(ctx, `
if tonumber(redis.call('HGET', KEYS[1], 'CacheSchemaVersion') or '0') ~= -1 then
  redis.call('HDEL', KEYS[1], 'CacheSchemaVersion')
end
return 1`, []string{getTokenCacheKey(key)}).Err()
}

// cacheInitToken publishes a database snapshot only when no mutation fence is
// active and the hash is cold. Existing hashes retain quota reservations while
// invalidated metadata is refreshed. Return 0 for a fence, 1 for initialization,
// and 2 for a retained quota hash.
func cacheInitToken(token Token) (int, error) {
	if !common.RedisEnabled {
		return 0, nil
	}
	allowIps := ""
	if token.AllowIps != nil {
		allowIps = *token.AllowIps
	}
	const script = `
if redis.call('EXISTS', KEYS[1]) == 1
  and tonumber(redis.call('HGET', KEYS[1], 'QuotaRevision') or '0') ~= tonumber(ARGV[21]) then
  if tonumber(redis.call('HGET', KEYS[1], 'CacheSchemaVersion') or '0') == -1 then return -1 end
end
if redis.call('EXISTS', KEYS[2]) == 1 then
  return 0
end
if redis.call('EXISTS', KEYS[1]) == 1 then
  redis.call('HSETNX', KEYS[1], 'QuotaRevision', ARGV[21])
  if tonumber(redis.call('HGET', KEYS[1], 'CacheSchemaVersion') or '0') ~= 2 then
    redis.call('HSET', KEYS[1], 'Status', ARGV[3], 'Name', ARGV[4], 'ExpiredTime', ARGV[7],
      'UnlimitedQuota', ARGV[8], 'ModelLimitsEnabled', ARGV[9], 'ModelLimits', ARGV[10],
      'AllowIps', ARGV[11], 'Group', ARGV[12], 'CrossGroupRetry', ARGV[13], 'AutoGroups', ARGV[14],
      'AllowUserQuotaQuery', ARGV[17], 'ManagedBindingRef', ARGV[19], 'ManagementCreatorID', ARGV[20], 'CacheSchemaVersion', 2)
  end
  redis.call('EXPIRE', KEYS[1], ARGV[18])
  return 2
end
redis.call('HSET', KEYS[1],
  'Id', ARGV[1], 'UserId', ARGV[2], 'Status', ARGV[3], 'Name', ARGV[4],
  'CreatedTime', ARGV[5], 'AccessedTime', ARGV[6], 'ExpiredTime', ARGV[7],
  'UnlimitedQuota', ARGV[8], 'ModelLimitsEnabled', ARGV[9], 'ModelLimits', ARGV[10],
  'AllowIps', ARGV[11], 'Group', ARGV[12], 'CrossGroupRetry', ARGV[13],
  'AutoGroups', ARGV[14], 'RemainQuota', ARGV[15], 'UsedQuota', ARGV[16],
  'AllowUserQuotaQuery', ARGV[17], 'ManagedBindingRef', ARGV[19], 'ManagementCreatorID', ARGV[20], 'QuotaRevision', ARGV[21], 'CacheSchemaVersion', 2)
redis.call('EXPIRE', KEYS[1], ARGV[18])
return 1`

	result, err := common.RDB.Eval(context.Background(), script, []string{
		getTokenCacheKey(token.Key), getTokenCacheFenceKey(token.Key),
	},
		token.Id, token.UserId, token.Status, token.Name,
		token.CreatedTime, token.AccessedTime, token.ExpiredTime,
		strconv.FormatBool(token.UnlimitedQuota), strconv.FormatBool(token.ModelLimitsEnabled),
		token.ModelLimits, allowIps, token.Group, strconv.FormatBool(token.CrossGroupRetry),
		token.AutoGroups, token.RemainQuota, token.UsedQuota,
		strconv.FormatBool(token.AllowUserQuotaQuery),
		tokenCacheTTLSeconds(),
		token.ManagedBindingRef, token.ManagementCreatorID, token.QuotaRevision,
	).Int()
	if result == -1 && err == nil {
		return result, ErrTokenQuotaUpdateUnknown
	}
	return result, err
}

// cacheGetTokenByKey 从缓存读取 token；不完整的哈希（如仅有配额字段）会被拒绝。
func cacheGetTokenByKey(key string) (*Token, error) {
	if !common.RedisEnabled {
		return nil, fmt.Errorf("redis is not enabled")
	}
	var token Token
	if err := common.RedisHGetObj(getTokenCacheKey(key), &token); err != nil {
		return nil, err
	}
	if token.Id <= 0 || token.CacheSchemaVersion != 2 {
		return nil, fmt.Errorf("token cache is incomplete")
	}
	token.Key = key
	return &token, nil
}
