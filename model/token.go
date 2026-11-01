package model

import (
	"errors"
	"fmt"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/bytedance/gopkg/util/gopool"
	"gorm.io/gorm"
)

type Token struct {
	Id                      int            `json:"id"`
	UserId                  int            `json:"user_id" gorm:"index"`
	Key                     string         `json:"key" gorm:"type:varchar(128);uniqueIndex"`
	Status                  int            `json:"status" gorm:"default:1"`
	Name                    string         `json:"name" gorm:"index" `
	CreatedTime             int64          `json:"created_time" gorm:"bigint"`
	AccessedTime            int64          `json:"accessed_time" gorm:"bigint"`
	ExpiredTime             int64          `json:"expired_time" gorm:"bigint;default:-1"` // -1 means never expired
	RemainQuota             int            `json:"remain_quota" gorm:"default:0"`
	UnlimitedQuota          bool           `json:"unlimited_quota"`
	ModelLimitsEnabled      bool           `json:"model_limits_enabled"`
	ModelLimits             string         `json:"model_limits" gorm:"type:text"`
	AllowIps                *string        `json:"allow_ips" gorm:"default:''"`
	UsedQuota               int            `json:"used_quota" gorm:"default:0"` // used quota
	Group                   string         `json:"group" gorm:"default:''"`
	CrossGroupRetry         bool           `json:"cross_group_retry"` // 跨分组重试，仅auto分组有效
	AutoGroups              string         `json:"-" gorm:"type:text"`
	DeletedAt               gorm.DeletedAt `gorm:"index"`
	QuotaRevision           int64          `json:"quota_revision" gorm:"not null;default:0"`
	MetadataRevision        int64          `json:"-" gorm:"not null;default:1"`
	QuotaMutationRef        string         `json:"-" gorm:"type:varchar(32)"`
	ManagementCreatorID     int            `json:"management_creator_id,omitempty" gorm:"not null;default:0"`
	ManagedBindingRef       string         `json:"managed_binding_ref,omitempty" gorm:"type:varchar(36)"`
	BillingContextRef       *string        `json:"billing_context_ref,omitempty" gorm:"type:varchar(36);uniqueIndex"`
	CreationRequestSHA      string         `json:"-" gorm:"type:varchar(64)"`
	BillingContextConfirmed bool           `json:"-" gorm:"not null;default:false"`
	CacheSchemaVersion      int            `json:"-" gorm:"-"`
	// 允许用此令牌查询所属用户的额度；新建令牌默认开启，已有令牌升级后保持关闭
	AllowUserQuotaQuery bool `json:"allow_user_quota_query"`
}

const ManagedTokenDisplayName = "Pilot"

func (token *Token) GetAutoGroups() ([]string, error) {
	if token.AutoGroups == "" {
		return nil, nil
	}
	var groups []string
	if err := common.UnmarshalJsonStr(token.AutoGroups, &groups); err != nil {
		return nil, err
	}
	return groups, nil
}

func (token *Token) SetAutoGroups(groups []string) error {
	if len(groups) == 0 {
		token.AutoGroups = ""
		return nil
	}
	data, err := common.Marshal(groups)
	if err != nil {
		return err
	}
	token.AutoGroups = string(data)
	return nil
}

func (token *Token) Clean() {
	token.Key = ""
}

func MaskTokenKey(key string) string {
	if key == "" {
		return ""
	}
	if len(key) <= 4 {
		return strings.Repeat("*", len(key))
	}
	if len(key) <= 8 {
		return key[:2] + "****" + key[len(key)-2:]
	}
	return key[:4] + "**********" + key[len(key)-4:]
}

func (token *Token) GetFullKey() string {
	return token.Key
}

func (token *Token) GetMaskedKey() string {
	return MaskTokenKey(token.Key)
}

func (token *Token) GetIpLimits() []string {
	// delete empty spaces
	//split with \n
	ipLimits := make([]string, 0)
	if token.AllowIps == nil {
		return ipLimits
	}
	cleanIps := strings.ReplaceAll(*token.AllowIps, " ", "")
	if cleanIps == "" {
		return ipLimits
	}
	ips := strings.SplitSeq(cleanIps, "\n")
	for ip := range ips {
		ip = strings.TrimSpace(ip)
		ip = strings.ReplaceAll(ip, ",", "")
		if ip != "" {
			ipLimits = append(ipLimits, ip)
		}
	}
	return ipLimits
}

func GetAllUserTokens(userId int, startIdx int, num int, externalOnly ...bool) ([]*Token, error) {
	var tokens []*Token
	var err error
	err = visibleTokenQuery(DB, externalOnly).Where("user_id = ?", userId).Order("id desc").Limit(num).Offset(startIdx).Find(&tokens).Error
	return tokens, err
}

// sanitizeLikePattern 校验并清洗用户输入的 LIKE 搜索模式。
// 规则：
//  1. 转义 ! 和 _（使用 ! 作为 ESCAPE 字符，兼容 MySQL/PostgreSQL/SQLite）
//  2. 连续的 % 合并为单个 %
//  3. 最多允许 2 个 %
//  4. 含 % 时（模糊搜索），去掉 % 后关键词长度必须 >= 2
//  5. 不含 % 时按精确匹配
func sanitizeLikePattern(input string) (string, error) {
	// 1. 先转义 ESCAPE 字符 ! 自身，再转义 _
	//    使用 ! 而非 \ 作为 ESCAPE 字符，避免 MySQL 中反斜杠的字符串转义问题
	input = strings.ReplaceAll(input, "!", "!!")
	input = strings.ReplaceAll(input, `_`, `!_`)

	if err := validateLikePattern(input); err != nil {
		return "", err
	}

	// 5. 无 % 时，精确全匹配
	return input, nil
}

func validateLikePattern(input string) error {
	// 1. 连续的 % 直接拒绝
	if strings.Contains(input, "%%") {
		return common.NewMessage("The search pattern cannot contain consecutive % wildcards")
	}

	// 2. 统计 % 数量，不得超过 2
	count := strings.Count(input, "%")
	if count > 2 {
		return common.NewMessage("The search pattern can contain at most 2 % wildcards")
	}

	// 3. 含 % 时，去掉 % 后关键词长度必须 >= 2
	if count > 0 {
		stripped := strings.ReplaceAll(input, "%", "")
		if len(stripped) < 2 {
			return common.NewMessage("Fuzzy search keywords must be at least 2 characters long")
		}
	}

	return nil
}

const searchHardLimit = 100

func SearchUserTokens(userId int, keyword string, token string, offset int, limit int, humanMetadata bool) (tokens []*Token, total int64, err error) {
	// model 层强制截断
	if limit <= 0 || limit > searchHardLimit {
		limit = searchHardLimit
	}
	if offset < 0 {
		offset = 0
	}

	if token != "" {
		token = strings.TrimPrefix(token, "sk-")
	}

	// 超量用户（令牌数超过上限）只允许精确搜索，禁止模糊搜索
	maxTokens := operation_setting.GetMaxUserTokens()
	hasFuzzy := strings.Contains(keyword, "%") || strings.Contains(token, "%")
	if hasFuzzy {
		count, err := CountUserTokens(userId)
		if err != nil {
			common.SysLog(common.LogText("failed to count user tokens: %s", err.Error()))
			return nil, 0, common.NewMessage("Failed to get the token count")
		}
		if int(count) > maxTokens {
			return nil, 0, common.NewMessage("Token count exceeds the limit. Only exact search is allowed, do not use the % wildcard")
		}
	}

	baseQuery := visibleTokenQuery(DB.Model(&Token{}), []bool{humanMetadata && token != ""}).Where("user_id = ?", userId)

	// 非空才加 LIKE 条件，空则跳过（不过滤该字段）
	if keyword != "" {
		keywordPattern, err := sanitizeLikePattern(keyword)
		if err != nil {
			return nil, 0, err
		}
		if humanMetadata {
			baseQuery = baseQuery.Where("CASE WHEN COALESCE(managed_binding_ref, '') <> '' THEN ? ELSE name END LIKE ? ESCAPE '!'", ManagedTokenDisplayName, keywordPattern)
		} else {
			baseQuery = baseQuery.Where("name LIKE ? ESCAPE '!'", keywordPattern)
		}
	}
	if token != "" {
		tokenPattern, err := sanitizeLikePattern(token)
		if err != nil {
			return nil, 0, err
		}
		baseQuery = baseQuery.Where(commonKeyCol+" LIKE ? ESCAPE '!'", tokenPattern)
	}

	// 先查匹配总数（用于分页，受 maxTokens 上限保护，避免全表 COUNT）
	err = baseQuery.Limit(maxTokens).Count(&total).Error
	if err != nil {
		common.SysError(common.LogText("failed to count search tokens: %s", err.Error()))
		return nil, 0, common.NewMessage("Failed to search tokens")
	}

	// 再分页查数据
	err = baseQuery.Order("id desc").Offset(offset).Limit(limit).Find(&tokens).Error
	if err != nil {
		common.SysError(common.LogText("failed to search tokens: %s", err.Error()))
		return nil, 0, common.NewMessage("Failed to search tokens")
	}
	return tokens, total, nil
}

func ValidateUserToken(key string) (token *Token, err error) {
	if key == "" {
		return nil, ErrTokenNotProvided
	}
	token, err = GetTokenByKey(key, false)
	if err == nil {
		if token.Status == common.TokenStatusExhausted ||
			token.Status == common.TokenStatusExpired ||
			token.Status != common.TokenStatusEnabled {
			return token, ErrTokenInvalid
		}
		if token.ExpiredTime != -1 && token.ExpiredTime < common.GetTimestamp() {
			if !common.RedisEnabled {
				token.Status = common.TokenStatusExpired
				err := token.SelectUpdate()
				if err != nil {
					common.SysLog(common.LogText("failed to update token status%s", err.Error()))
				}
			}
			return token, ErrTokenInvalid
		}
		if !token.UnlimitedQuota && token.RemainQuota <= 0 {
			if !common.RedisEnabled {
				token.Status = common.TokenStatusExhausted
				err := token.SelectUpdate()
				if err != nil {
					common.SysLog(common.LogText("failed to update token status%s", err.Error()))
				}
			}
			return token, ErrTokenInvalid
		}
		return token, nil
	}
	common.SysLog(common.LogText("ValidateUserToken: failed to get token: %s", err.Error()))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrTokenInvalid
	}
	return nil, fmt.Errorf("%w: %v", ErrDatabase, err)
}

func GetTokenByIds(id int, userId int, externalOnly ...bool) (*Token, error) {
	if id == 0 || userId == 0 {
		return nil, common.NewMessage("Token ID or user ID is empty")
	}
	token := Token{Id: id, UserId: userId}
	var err error = nil
	err = visibleTokenQuery(DB, externalOnly).First(&token, "id = ? and user_id = ?", id, userId).Error
	return &token, err
}

func GetTokenById(id int) (*Token, error) {
	if id == 0 {
		return nil, errors.New("token id is empty")
	}
	token := Token{Id: id}
	var err error = nil
	err = DB.First(&token, "id = ?", id).Error
	return &token, err
}

func GetTokenByKey(key string, fromDB bool) (token *Token, err error) {
	if !fromDB && common.RedisEnabled {
		// Try Redis first
		token, err := cacheGetTokenByKey(key)
		if err == nil {
			return token, nil
		}
		// Don't return error - fall through to DB
	}
	token = &Token{}
	if err = DB.Where(commonKeyCol+" = ?", key).First(token).Error; err != nil {
		return nil, err
	}
	if common.RedisEnabled {
		// 冷缓存时用数据库快照初始化；已存在的哈希只刷新 TTL，
		// 避免快照覆盖 Redis 中已被原子预扣的余额。初始化失败不影响本次读取。
		if _, cacheErr := cacheInitToken(*token); cacheErr != nil {
			if errors.Is(cacheErr, ErrTokenQuotaUpdateUnknown) || errors.Is(cacheErr, ErrTokenMetadataStale) {
				return nil, cacheErr
			}
			common.SysLog(common.LogText("failed to init token cache: %s", cacheErr.Error()))
		}
	}
	return token, nil
}

func (token *Token) Insert() error {
	var err error
	err = DB.Create(token).Error
	return err
}

var ErrBillingContextConflict = errors.New("key billing context conflicts with its original creation")
var ErrBillingContextRetired = errors.New("the original key creation was retired")

// BindPlaygroundBillingContext applies a confirmed control-plane receipt once.
func BindPlaygroundBillingContext(userID int, reference string) error {
	if userID <= 0 || len(reference) != 36 {
		return ErrBillingContextConflict
	}
	err := DB.Transaction(func(tx *gorm.DB) error {
		var user User
		if err := lockForUpdate(tx).Select("id", "playground_billing_context_ref").First(&user, userID).Error; err != nil {
			return err
		}
		if user.PlaygroundBillingContextRef != nil {
			if *user.PlaygroundBillingContextRef != reference {
				return ErrBillingContextConflict
			}
			return nil
		}
		return tx.Model(&user).Update("playground_billing_context_ref", reference).Error
	})
	if err != nil {
		return err
	}
	user, err := GetUserById(userID, false)
	if err != nil {
		return err
	}
	return updateUserCache(*user)
}

func GetPlaygroundBillingContext(userID int) (*string, error) {
	var user User
	err := DB.Select("id", "playground_billing_context_ref").First(&user, userID).Error
	return user.PlaygroundBillingContextRef, err
}

func GetTokenByBillingContext(userID int, reference string) (*Token, error) {
	var token Token
	err := DB.Where("user_id = ? AND billing_context_ref = ?", userID, reference).First(&token).Error
	return &token, err
}

// InsertPendingBillingToken creates one disabled key per immutable context.
// A retry never changes the original key, parameters, or later user status.
func (token *Token) InsertPendingBillingToken() error {
	if token.BillingContextRef == nil || *token.BillingContextRef == "" || len(token.CreationRequestSHA) != 64 {
		return ErrBillingContextConflict
	}
	var previous Token
	read := func() error {
		err := DB.Unscoped().Where("billing_context_ref = ?", *token.BillingContextRef).First(&previous).Error
		if err == nil {
			if previous.UserId != token.UserId || previous.CreationRequestSHA != token.CreationRequestSHA || previous.ManagedBindingRef != token.ManagedBindingRef {
				return ErrBillingContextConflict
			}
			if previous.DeletedAt.Valid {
				return ErrBillingContextRetired
			}
			*token = previous
		}
		return err
	}
	err := read()
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	token.Status, token.BillingContextConfirmed = common.TokenStatusDisabled, false
	if err = DB.Create(token).Error; err != nil {
		if recovered := read(); !errors.Is(recovered, gorm.ErrRecordNotFound) {
			return recovered
		}
	}
	return err
}

func (token *Token) ConfirmBillingContext() (err error) {
	var attempted int64
	defer func() { token.resolveMetadataOutcome(&err, attempted) }()
	err = DB.Transaction(func(tx *gorm.DB) error {
		var current Token
		if err := lockForUpdate(tx).Where("id = ? AND user_id = ?", token.Id, token.UserId).First(&current).Error; err != nil {
			return err
		}
		if current.BillingContextRef == nil || token.BillingContextRef == nil || *current.BillingContextRef != *token.BillingContextRef || current.CreationRequestSHA != token.CreationRequestSHA {
			return ErrBillingContextConflict
		}
		if !current.BillingContextConfirmed {
			next := max(current.MetadataRevision, 1) + 1
			attempted, token.Key = next, current.Key
			if err := setTokenMetadataFence(current.Key, next); err != nil {
				return err
			}
			if err := tx.Model(&current).Updates(map[string]any{"billing_context_confirmed": true, "status": common.TokenStatusEnabled,
				"metadata_revision": next}).Error; err != nil {
				return err
			}
			current.BillingContextConfirmed, current.Status = true, common.TokenStatusEnabled
			current.MetadataRevision = next
		}
		*token = current
		return nil
	})
	if err == nil {
		err = publishCommittedTokenMetadata(token.Key, token.MetadataRevision)
	}
	return err
}

var ErrTokenQuotaRevisionConflict = errors.New("token quota revision conflict")
var ErrTokenQuotaUpdateUnknown = errors.New("token quota update outcome is unknown")

type TokenQuotaAdjustment struct {
	Delta            int
	ExpectedRevision int64
}

// Update never writes a loaded balance. Explicit quota increments are bound to
// a management revision, so a lost response cannot turn a retry into more quota.
func (token *Token) Update(adjustments ...TokenQuotaAdjustment) (err error) {
	var attempted int64
	defer func() { token.resolveMetadataOutcome(&err, attempted) }()
	if len(adjustments) > 1 {
		return errors.New("invalid quota adjustment")
	}
	adjustment := TokenQuotaAdjustment{}
	if len(adjustments) == 1 {
		adjustment = adjustments[0]
	}
	delta := adjustment.Delta
	if delta > common.MaxWalletQuota || delta < -common.MaxWalletQuota || adjustment.ExpectedRevision < 0 {
		return errors.New("invalid quota adjustment")
	}
	cacheAdjusted := false
	mutationRef := common.GetUUID()
	bodyCompleted := false
	compensate := func() {
		if !cacheAdjusted {
			return
		}
		result, compensateErr := cacheReverseTokenBudget(token.Id, token.Key, -delta, adjustment.ExpectedRevision)
		if compensateErr != nil || result != cacheQuotaOK {
			common.SysError("failed to compensate token quota adjustment")
			err = errors.Join(ErrTokenQuotaUpdateUnknown, err, errors.New("token quota adjustment compensation failed"), compensateErr)
		}
		cacheAdjusted = false
	}
	err = DB.Transaction(func(tx *gorm.DB) (writeErr error) {
		var current Token
		if writeErr = lockForUpdate(tx).First(&current, token.Id).Error; writeErr != nil {
			return writeErr
		}
		if delta != 0 {
			if current.QuotaRevision != adjustment.ExpectedRevision {
				return ErrTokenQuotaRevisionConflict
			}
			if common.RedisEnabled {
				result, cacheErr := cacheAdjustTokenBudget(token.Id, token.Key, delta, adjustment.ExpectedRevision)
				if cacheErr == nil && result == cacheQuotaMiss {
					// Hydrate from the transaction's locked snapshot without a second DB connection.
					if _, cacheErr = cacheInitToken(current); cacheErr == nil {
						result, cacheErr = cacheAdjustTokenBudget(token.Id, token.Key, delta, adjustment.ExpectedRevision)
					}
				}
				if cacheErr != nil {
					return errors.Join(ErrTokenQuotaUpdateUnknown, cacheErr)
				}
				if result == cacheQuotaConflict {
					return ErrTokenQuotaRevisionConflict
				}
				if result == cacheQuotaUnknown {
					return ErrTokenQuotaUpdateUnknown
				}
				if result != cacheQuotaOK {
					return errors.New("token quota adjustment unavailable or insufficient")
				}
				cacheAdjusted = true
			}
		}
		// Run failed-write compensation while the DB row lock is still held.
		defer func() {
			if writeErr != nil && cacheAdjusted {
				err = writeErr
				compensate()
				writeErr = err
			}
		}()
		next := max(current.MetadataRevision, 1) + 1
		attempted, token.Key = next, current.Key
		if cacheErr := setTokenMetadataFence(current.Key, next); cacheErr != nil {
			return cacheErr
		}
		changes := map[string]any{"name": token.Name, "expired_time": token.ExpiredTime,
			"unlimited_quota": token.UnlimitedQuota, "model_limits_enabled": token.ModelLimitsEnabled,
			"model_limits": token.ModelLimits, "allow_ips": token.AllowIps, "group": token.Group,
			"cross_group_retry": token.CrossGroupRetry, "auto_groups": token.AutoGroups,
			"allow_user_quota_query": token.AllowUserQuotaQuery, "metadata_revision": next}
		query := tx.Model(token)
		if delta != 0 {
			changes["remain_quota"] = gorm.Expr("remain_quota + ?", delta)
			changes["quota_revision"] = gorm.Expr("quota_revision + 1")
			changes["quota_mutation_ref"] = mutationRef
			query = query.Where("quota_revision = ? AND remain_quota + ? >= 0 AND remain_quota + ? <= ?", adjustment.ExpectedRevision, delta, delta, common.MaxWalletQuota)
		}
		result := query.Updates(changes)
		if result.Error != nil {
			return result.Error
		}
		if delta != 0 && result.RowsAffected != 1 {
			return errors.New("token quota adjustment unavailable or insufficient")
		}
		bodyCompleted = true
		token.MetadataRevision = next
		return nil
	})
	if err != nil && delta != 0 && bodyCompleted {
		commitErr := err
		// COMMIT can succeed even when its acknowledgement is lost. Read the
		// exact mutation marker under the same row lock before any compensation.
		resolutionErr := DB.Transaction(func(tx *gorm.DB) error {
			var current Token
			if readErr := lockForUpdate(tx).First(&current, token.Id).Error; readErr != nil {
				return readErr
			}
			if current.QuotaMutationRef == mutationRef {
				err = nil
				return nil
			}
			if current.QuotaRevision != adjustment.ExpectedRevision {
				return ErrTokenQuotaUpdateUnknown
			}
			err = commitErr
			compensate()
			return nil
		})
		if resolutionErr != nil {
			return errors.Join(ErrTokenQuotaUpdateUnknown, commitErr, resolutionErr)
		}
	}
	if err == nil && cacheAdjusted {
		result, cacheErr := cacheConfirmTokenBudget(token.Id, token.Key, adjustment.ExpectedRevision+1)
		if cacheErr != nil || (result != cacheQuotaOK && result != cacheQuotaMiss) {
			return errors.Join(ErrTokenQuotaUpdateUnknown, cacheErr)
		}
	}
	if err == nil {
		err = publishCommittedTokenMetadata(token.Key, token.MetadataRevision)
	}
	return err
}

func (token *Token) SelectUpdate() (err error) {
	if token.Status == common.TokenStatusEnabled && token.BillingContextRef != nil && !token.BillingContextConfirmed {
		return ErrBillingContextConflict
	}
	return token.mutateMetadata(map[string]any{"status": token.Status}, false)
}

func (token *Token) Delete() (err error) {
	return token.mutateMetadata(nil, true)
}

// mutateMetadata serializes control-plane mutations, not inference requests.
func (token *Token) mutateMetadata(fields map[string]any, deleting bool) (err error) {
	var attempted int64
	defer func() { token.resolveMetadataOutcome(&err, attempted) }()
	err = DB.Transaction(func(tx *gorm.DB) error {
		var current Token
		if err := lockForUpdate(tx).First(&current, token.Id).Error; err != nil {
			return err
		}
		next := max(current.MetadataRevision, 1) + 1
		attempted, token.Key = next, current.Key
		if err := setTokenMetadataFence(current.Key, next); err != nil {
			return err
		}
		if fields == nil {
			fields = map[string]any{}
		}
		fields["metadata_revision"] = next
		if err := tx.Model(&current).Updates(fields).Error; err != nil {
			return err
		}
		if deleting {
			if err := tx.Delete(&current).Error; err != nil {
				return err
			}
		}
		token.Key, token.MetadataRevision = current.Key, next
		return nil
	})
	if err == nil {
		err = publishCommittedTokenMetadata(token.Key, token.MetadataRevision)
	}
	return err
}

// A locked control-plane read distinguishes rollback from committed state.
// It never clears a concurrently newer mutation's fence or changes Key status.
func (token *Token) resolveMetadataOutcome(operationErr *error, attempted int64) {
	if *operationErr == nil || attempted <= 0 || !common.RedisEnabled {
		return
	}
	if err := DB.Transaction(func(tx *gorm.DB) error {
		var current Token
		if err := lockForUpdate(tx.Unscoped()).First(&current, token.Id).Error; err != nil {
			return err
		}
		if current.Key != token.Key {
			return ErrBillingContextConflict
		}
		return resolveTokenMetadataFence(current.Key, max(current.MetadataRevision, 1), attempted)
	}); err != nil {
		*operationErr = errors.Join(*operationErr, ErrTokenMetadataStale)
	}
}

func (token *Token) IsModelLimitsEnabled() bool {
	return token.ModelLimitsEnabled
}

func (token *Token) GetModelLimits() []string {
	if token.ModelLimits == "" {
		return []string{}
	}
	return strings.Split(token.ModelLimits, ",")
}

func (token *Token) GetModelLimitsMap() map[string]bool {
	limits := token.GetModelLimits()
	limitsMap := make(map[string]bool)
	for _, limit := range limits {
		limitsMap[limit] = true
	}
	return limitsMap
}

func DisableModelLimits(tokenId int) error {
	token, err := GetTokenById(tokenId)
	if err != nil {
		return err
	}
	token.ModelLimitsEnabled = false
	token.ModelLimits = ""
	return token.Update()
}

func DeleteTokenById(id int, userId int) (err error) {
	// Why we need userId here? In case user want to delete other's token.
	if id == 0 || userId == 0 {
		return common.NewMessage("Token ID or user ID is empty")
	}
	token := Token{Id: id, UserId: userId}
	err = DB.Where(token).First(&token).Error
	if err != nil {
		return err
	}
	return token.Delete()
}

func IncreaseTokenQuota(tokenId int, key string, quota int) (err error) {
	if quota < 0 {
		return errors.New("quota cannot be negative")
	}
	if common.RedisEnabled {
		gopool.Go(func() {
			// 守卫式增量：哈希不存在时跳过，由下次读取从数据库水合，
			// 绝不创建只有配额字段的残缺哈希。
			if _, err := cacheApplyTokenQuotaDelta(tokenId, key, int64(quota)); err != nil {
				common.SysLog(common.LogText("failed to increase token quota: %s", err.Error()))
			}
		})
	}
	if common.BatchUpdateEnabled {
		addNewRecord(BatchUpdateTypeTokenQuota, tokenId, quota)
		return nil
	}
	return increaseTokenQuota(tokenId, quota)
}

func increaseTokenQuota(id int, quota int) (err error) {
	err = DB.Model(&Token{}).Where("id = ?", id).Updates(
		map[string]any{
			"remain_quota":  gorm.Expr("remain_quota + ?", quota),
			"used_quota":    gorm.Expr("used_quota - ?", quota),
			"accessed_time": common.GetTimestamp(),
		},
	).Error
	return err
}

func DecreaseTokenQuota(id int, key string, quota int) (err error) {
	if quota < 0 {
		return errors.New("quota cannot be negative")
	}
	if common.RedisEnabled {
		gopool.Go(func() {
			if _, err := cacheApplyTokenQuotaDelta(id, key, int64(-quota)); err != nil {
				common.SysLog(common.LogText("failed to decrease token quota: %s", err.Error()))
			}
		})
	}
	if common.BatchUpdateEnabled {
		addNewRecord(BatchUpdateTypeTokenQuota, id, -quota)
		return nil
	}
	return decreaseTokenQuota(id, quota)
}

func decreaseTokenQuota(id int, quota int) (err error) {
	err = DB.Model(&Token{}).Where("id = ?", id).Updates(
		map[string]any{
			"remain_quota":  gorm.Expr("remain_quota - ?", quota),
			"used_quota":    gorm.Expr("used_quota + ?", quota),
			"accessed_time": common.GetTimestamp(),
		},
	).Error
	return err
}

// CountUserTokens returns total number of tokens for the given user, used for pagination
func CountUserTokens(userId int, externalOnly ...bool) (int64, error) {
	var total int64
	err := visibleTokenQuery(DB.Model(&Token{}), externalOnly).Where("user_id = ?", userId).Count(&total).Error
	return total, err
}

// BatchDeleteTokens 删除指定用户的一组令牌，返回成功删除数量
func BatchDeleteTokens(ids []int, userId int, externalOnly ...bool) (count int, operationErr error) {
	if len(ids) == 0 {
		return 0, common.NewMessage("Token IDs cannot be empty")
	}

	tx := DB.Begin()

	var tokens []Token
	defer func() {
		for i := range tokens {
			tokens[i].resolveMetadataOutcome(&operationErr, tokens[i].MetadataRevision)
		}
	}()
	if err := lockForUpdate(visibleTokenQuery(tx, externalOnly)).Where("user_id = ? AND id IN (?)", userId, ids).Find(&tokens).Error; err != nil {
		tx.Rollback()
		return 0, err
	}
	for i := range tokens {
		tokens[i].MetadataRevision = max(tokens[i].MetadataRevision, 1) + 1
		if err := setTokenMetadataFence(tokens[i].Key, tokens[i].MetadataRevision); err != nil {
			tx.Rollback()
			return 0, err
		}
		if err := tx.Model(&tokens[i]).Update("metadata_revision", tokens[i].MetadataRevision).Error; err != nil {
			tx.Rollback()
			return 0, err
		}
	}

	if err := visibleTokenQuery(tx, externalOnly).Where("user_id = ? AND id IN (?)", userId, ids).Delete(&Token{}).Error; err != nil {
		tx.Rollback()
		return 0, err
	}

	if err := tx.Commit().Error; err != nil {
		return 0, err
	}
	for _, token := range tokens {
		if err := publishCommittedTokenMetadata(token.Key, token.MetadataRevision); err != nil {
			return len(tokens), err
		}
	}

	return len(tokens), nil
}

func GetTokenKeysByIds(ids []int, userId int, externalOnly ...bool) ([]Token, error) {
	var tokens []Token
	err := visibleTokenQuery(DB, externalOnly).Where("billing_context_ref IS NULL OR billing_context_confirmed = ?", true).Select("id", commonKeyCol).
		Where("user_id = ? AND id IN (?)", userId, ids).
		Find(&tokens).Error
	return tokens, err
}

// InvalidateUserTokensCache 清理指定用户所有令牌在 Redis 中的缓存，
// 配合 InvalidateUserCache 使用，可在用户被禁用/删除时立即阻断其令牌的请求。
// 下一次请求将从数据库重新加载令牌及用户状态，从而立即识别出被禁用的用户。
func InvalidateUserTokensCache(userId int) error {
	if !common.RedisEnabled {
		return nil
	}
	if userId <= 0 {
		return errors.New("invalid user id")
	}
	var tokens []Token
	if err := DB.Unscoped().
		Select("id", commonKeyCol).
		Where("user_id = ?", userId).
		Find(&tokens).Error; err != nil {
		return err
	}
	return invalidateTokensCache(tokens)
}

func invalidateTokensCache(tokens []Token) error {
	if !common.RedisEnabled {
		return nil
	}
	var firstErr error
	for _, t := range tokens {
		if t.Key == "" {
			continue
		}
		if err := invalidateTokenCacheForMutation(t.Key); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func visibleTokenQuery(query *gorm.DB, externalOnly []bool) *gorm.DB {
	if len(externalOnly) > 0 && externalOnly[0] {
		return query.Where("managed_binding_ref IS NULL OR managed_binding_ref = ?", "")
	}
	return query
}

type TokenLogVisibility struct {
	Managed     bool
	FullDetails bool
}

// Derive disclosure from immutable provenance, including retired credentials.
// Log and primary databases can be separate; names never establish provenance.
func UserTokenLogVisibility(userID int) (map[int]TokenLogVisibility, error) {
	var tokens []Token
	err := DB.Unscoped().Select("id", "managed_binding_ref", "management_creator_id").Where("user_id = ?", userID).Find(&tokens).Error
	if err != nil {
		return nil, err
	}
	visibility := make(map[int]TokenLogVisibility, len(tokens))
	for _, token := range tokens {
		managed := token.ManagedBindingRef != ""
		visibility[token.Id] = TokenLogVisibility{Managed: managed, FullDetails: !managed && token.ManagementCreatorID > 0}
	}
	return visibility, nil
}
