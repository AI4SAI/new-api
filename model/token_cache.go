package model

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/QuantumNous/new-api/common"
)

func (token Token) cacheMAC() (string, error) {
	key := getTokenCacheKey(token.Key)
	token.Key = ""
	token.RemainQuota = 0
	token.UsedQuota = 0
	token.AccessedTime = 0
	// The atomic budget path owns this revision and retains it during repairs,
	// just as reservation/settlement paths own the quota counters.
	token.QuotaRevision = 0
	if token.AllowIps != nil && *token.AllowIps == "" {
		token.AllowIps = nil
	}
	if token.BillingContextRef != nil && *token.BillingContextRef == "" {
		token.BillingContextRef = nil
	}
	return authCacheMAC(key, struct {
		Token                   Token
		AutoGroups              string
		MetadataRevision        int64
		BillingContextConfirmed bool
		CacheSchemaVersion      int
		CacheExpiresAt          int64
	}{token, token.AutoGroups, token.MetadataRevision, token.BillingContextConfirmed,
		token.CacheSchemaVersion, token.CacheExpiresAt})
}

func getTokenCacheKey(key string) string {
	return fmt.Sprintf("token:%s", common.GenerateHMAC(key))
}

// Keep the deployed key names for mixed-version fills and settlements.
// common.RDB uses standalone Redis, without Cluster cross-slot support.
func getTokenCacheFenceKey(key string) string {
	return fmt.Sprintf("token:fence:%s", common.GenerateHMAC(key))
}

func getTokenMetadataVersionKey(key string) string {
	return fmt.Sprintf("token:metadata-version:%s", common.GenerateHMAC(key))
}

var ErrTokenMetadataStale = errors.New("token metadata update is not yet observable")

// Unknown commit/publication results retain their fence until a current DB
// snapshot or the original control operation resolves them.
func setTokenMetadataFence(key string, revision int64) error {
	if !common.RedisEnabled {
		return nil
	}
	return common.RDB.Eval(context.Background(), `
if tonumber(redis.call('GET', KEYS[1]) or '0') < tonumber(ARGV[1]) then
  redis.call('SET', KEYS[1], ARGV[1])
else
  redis.call('PERSIST', KEYS[1])
end
return 1`, []string{getTokenCacheFenceKey(key)}, revision).Err()
}

func tokenMetadataFloor(key string) (int64, error) {
	values, err := common.RDB.MGet(context.Background(), getTokenCacheFenceKey(key), getTokenMetadataVersionKey(key)).Result()
	if err != nil {
		return 0, err
	}
	var floor int64
	for _, value := range values {
		if value == nil {
			continue
		}
		number, err := strconv.ParseInt(fmt.Sprint(value), 10, 64)
		if err != nil {
			return 0, err
		}
		if number < 0 {
			return 0, ErrTokenMetadataStale
		}
		floor = max(floor, number)
	}
	return floor, nil
}

func publishCommittedTokenMetadata(key string, revision int64) error {
	if !common.RedisEnabled {
		return nil
	}
	return common.RDB.Eval(context.Background(), `
local revision = tonumber(ARGV[1])
if tonumber(redis.call('GET', KEYS[1]) or '0') < revision then redis.call('SET', KEYS[1], ARGV[1]) end
if tonumber(redis.call('GET', KEYS[2]) or '0') <= revision then redis.call('DEL', KEYS[2]) end
return 1`, []string{getTokenMetadataVersionKey(key), getTokenCacheFenceKey(key)}, revision).Err()
}

func resolveTokenMetadataFence(key string, observed, attempted int64) error {
	return common.RDB.Eval(context.Background(), `
local observed, attempted = tonumber(ARGV[1]), tonumber(ARGV[2])
local committed = tonumber(redis.call('GET', KEYS[1]) or '0')
if committed > observed then return 0 end
redis.call('SET', KEYS[1], ARGV[1])
local pending = tonumber(redis.call('GET', KEYS[2]) or '0')
if pending <= observed or pending == attempted then redis.call('DEL', KEYS[2]) end
return 1`, []string{getTokenMetadataVersionKey(key), getTokenCacheFenceKey(key)}, observed, attempted).Err()
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
	return common.RDB.Eval(ctx, `
if tonumber(redis.call('GET', KEYS[2]) or '0') <= 0 then
  redis.call('SET', KEYS[2], -1, 'EX', ARGV[1])
end
if tonumber(redis.call('HGET', KEYS[1], 'CacheSchemaVersion') or '0') ~= -1 then
  redis.call('HDEL', KEYS[1], 'CacheSchemaVersion')
end
return 1`, []string{getTokenCacheKey(key), getTokenCacheFenceKey(key)}, tokenCacheFenceSeconds).Err()
}

// cacheInitToken publishes database metadata after checking the pending and
// committed metadata floors. Repairs preserve outstanding quota reservations
// and unresolved budget changes. Malformed counters are replaced from the
// snapshot, as they cannot be used by the atomic quota paths.
// Returns 0 when fenced, 1 after initialization, or 2 for an existing hash.
func cacheInitToken(token Token) (int, error) {
	if !common.RedisEnabled {
		return 0, nil
	}
	allowIps := ""
	if token.AllowIps != nil {
		allowIps = *token.AllowIps
	}
	billingRef := ""
	if token.BillingContextRef != nil {
		billingRef = *token.BillingContextRef
	}
	cacheKey := getTokenCacheKey(token.Key)
	var existing Token
	readErr := common.RedisHGetObj(cacheKey, &existing)
	if readErr != nil {
		// Decoding stops at the first unreadable field, before CacheMAC.
		existing.CacheMAC, _ = common.RDB.HGet(context.Background(), cacheKey, "CacheMAC").Result()
	}
	existing.Key = token.Key
	existingMAC, macErr := existing.cacheMAC()
	repair := readErr != nil || macErr != nil || !validAuthCacheMAC(existingMAC, existing.CacheMAC, existing.CacheExpiresAt)
	token.MetadataRevision = max(token.MetadataRevision, 1)
	token.CacheSchemaVersion = 5
	token.CacheExpiresAt = time.Now().Add(time.Duration(tokenCacheTTLSeconds()) * time.Second).UnixMilli()
	mac, err := token.cacheMAC()
	if err != nil {
		return 0, err
	}
	const script = `
local metadata = tonumber(ARGV[24])
local committed = tonumber(redis.call('GET', KEYS[3]) or '0')
local pending = tonumber(redis.call('GET', KEYS[2]) or '0')
if pending < 0 then return 0 end
local cached = tonumber(redis.call('HGET', KEYS[1], 'MetadataRevision') or '0')
if metadata < math.max(committed, pending, cached) then return -2 end
if committed < metadata then redis.call('SET', KEYS[3], ARGV[24]) end
if pending > 0 and pending <= metadata then redis.call('DEL', KEYS[2]) end
if redis.call('EXISTS', KEYS[1]) == 1
  and tonumber(redis.call('HGET', KEYS[1], 'QuotaRevision') or '0') ~= tonumber(ARGV[21]) then
  if tonumber(redis.call('HGET', KEYS[1], 'CacheSchemaVersion') or '0') == -1 then return -1 end
end
local exists = redis.call('EXISTS', KEYS[1])
if exists == 1 then
  redis.call('HSETNX', KEYS[1], 'QuotaRevision', ARGV[21])
  if cached == metadata then
    local schema = tonumber(redis.call('HGET', KEYS[1], 'CacheSchemaVersion') or '0')
    if (schema == 5 and ARGV[28] ~= 'true') or (redis.call('HGET', KEYS[1], 'CacheMAC') or '') ~= ARGV[29] then
      redis.call('EXPIRE', KEYS[1], ARGV[18])
      return 2
    end
  end
end
redis.call('HDEL', KEYS[1], 'DeletedAt')
redis.call('HSET', KEYS[1],
  'Id', ARGV[1], 'UserId', ARGV[2], 'Status', ARGV[3], 'Name', ARGV[4],
  'CreatedTime', ARGV[5], 'ExpiredTime', ARGV[7],
  'UnlimitedQuota', ARGV[8], 'ModelLimitsEnabled', ARGV[9], 'ModelLimits', ARGV[10],
  'AllowIps', ARGV[11], 'Group', ARGV[12], 'CrossGroupRetry', ARGV[13],
  'AutoGroups', ARGV[14], 'AllowUserQuotaQuery', ARGV[17],
  'ManagedBindingRef', ARGV[19], 'ManagementCreatorID', ARGV[20],
  'BillingContextRef', ARGV[22], 'BillingContextConfirmed', ARGV[23], 'MetadataRevision', ARGV[24],
  'ManagedSubjectRef', ARGV[25], 'CacheSchemaVersion', 5,
  'CacheExpiresAt', ARGV[26], 'CacheMAC', ARGV[27])
for _, counter in ipairs({{'AccessedTime', ARGV[6]}, {'RemainQuota', ARGV[15]}, {'UsedQuota', ARGV[16]}, {'QuotaRevision', ARGV[21]}}) do
  if not string.match(redis.call('HGET', KEYS[1], counter[1]) or '', '^-?%d+$') then
    redis.call('HSET', KEYS[1], counter[1], counter[2])
  end
end
redis.call('EXPIRE', KEYS[1], ARGV[18])
if exists == 1 then
  return 2
end
return 1`

	result, err := common.RDB.Eval(context.Background(), script, []string{
		cacheKey, getTokenCacheFenceKey(token.Key), getTokenMetadataVersionKey(token.Key),
	},
		token.Id, token.UserId, token.Status, token.Name,
		token.CreatedTime, token.AccessedTime, token.ExpiredTime,
		strconv.FormatBool(token.UnlimitedQuota), strconv.FormatBool(token.ModelLimitsEnabled),
		token.ModelLimits, allowIps, token.Group, strconv.FormatBool(token.CrossGroupRetry),
		token.AutoGroups, token.RemainQuota, token.UsedQuota,
		strconv.FormatBool(token.AllowUserQuotaQuery),
		tokenCacheTTLSeconds(),
		token.ManagedBindingRef, token.ManagementCreatorID, token.QuotaRevision,
		billingRef, strconv.FormatBool(token.BillingContextConfirmed),
		token.MetadataRevision,
		token.ManagedSubjectRef,
		token.CacheExpiresAt, mac, strconv.FormatBool(repair), existing.CacheMAC,
	).Int()
	if result == -1 && err == nil {
		return result, ErrTokenQuotaUpdateUnknown
	}
	if result == -2 && err == nil {
		return result, ErrTokenMetadataStale
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
	if token.Id <= 0 || token.CacheSchemaVersion != 5 || token.MetadataRevision <= 0 {
		return nil, fmt.Errorf("token cache is incomplete")
	}
	floor, err := tokenMetadataFloor(key)
	if err != nil {
		return nil, err
	}
	if token.MetadataRevision < floor {
		return nil, ErrTokenMetadataStale
	}
	token.Key = key
	mac, err := token.cacheMAC()
	if err != nil || !validAuthCacheMAC(mac, token.CacheMAC, token.CacheExpiresAt) {
		return nil, fmt.Errorf("token cache integrity check failed")
	}
	return &token, nil
}
