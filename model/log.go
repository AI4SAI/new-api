package model

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
	"github.com/shopspring/decimal"

	"gorm.io/gorm"
)

func applyExplicitLogTextFilter(tx *gorm.DB, column string, value string) (*gorm.DB, error) {
	if value == "" {
		return tx, nil
	}
	if strings.Contains(value, "%") {
		condition, pattern, err := buildLogLikeCondition(column, value)
		if err != nil {
			return nil, err
		}
		return tx.Where(condition, pattern), nil
	}
	return tx.Where(column+" = ?", value), nil
}

func buildLogLikeCondition(column string, value string) (string, string, error) {
	if common.UsingLogDatabase(common.DatabaseTypeClickHouse) {
		pattern, err := sanitizeClickHouseLikePattern(value)
		if err != nil {
			return "", "", err
		}
		return column + " LIKE ?", pattern, nil
	}

	pattern, err := sanitizeLikePattern(value)
	if err != nil {
		return "", "", err
	}
	return column + " LIKE ? ESCAPE '!'", pattern, nil
}

func sanitizeClickHouseLikePattern(input string) (string, error) {
	input = strings.ReplaceAll(input, `\`, `\\`)
	input = strings.ReplaceAll(input, `_`, `\_`)

	if err := validateLikePattern(input); err != nil {
		return "", err
	}
	return input, nil
}

type Log struct {
	Id                     int               `json:"id" gorm:"index:idx_created_at_id,priority:2;index:idx_user_id_id,priority:2;index:idx_model_usage_completion,priority:3"`
	UserId                 int               `json:"user_id" gorm:"index;index:idx_user_id_id,priority:1;index:idx_model_usage_period,priority:1;index:idx_model_usage_completion,priority:1;index:idx_model_usage_observed,priority:1"`
	CreatedAt              int64             `json:"created_at" gorm:"bigint;index:idx_created_at_id,priority:1;index:idx_created_at_type;index:idx_model_usage_observed,priority:3"`
	Type                   int               `json:"type" gorm:"index:idx_created_at_type"`
	Content                string            `json:"content"`
	Username               string            `json:"username" gorm:"index;index:index_username_model_name,priority:2;default:''"`
	TokenName              string            `json:"token_name" gorm:"index;default:''"`
	ModelName              string            `json:"model_name" gorm:"index;index:index_username_model_name,priority:1;default:''"`
	Quota                  int               `json:"quota" gorm:"default:0"`
	PromptTokens           int               `json:"prompt_tokens" gorm:"default:0"`
	CompletionTokens       int               `json:"completion_tokens" gorm:"default:0"`
	UseTime                int               `json:"use_time" gorm:"default:0"`
	IsStream               bool              `json:"is_stream"`
	ChannelId              int               `json:"channel" gorm:"index"`
	ChannelName            string            `json:"channel_name" gorm:"->"`
	TokenId                int               `json:"token_id" gorm:"default:0;index"`
	BillingContextRef      string            `json:"billing_context_ref,omitempty" gorm:"type:varchar(36);index;index:idx_model_usage_period,priority:2;index:idx_model_usage_completion,priority:2;index:idx_model_usage_observed,priority:2"`
	BillingPolicyEpoch     string            `json:"policy_epoch,omitempty" gorm:"type:varchar(20);not null;default:'';index:idx_model_usage_period,priority:3"`
	RequestStartedAt       int64             `json:"request_started_at,omitempty" gorm:"not null;default:0;index:idx_model_usage_period,priority:4"`
	BillingProduct         string            `json:"billing_product,omitempty" gorm:"type:varchar(256)"`
	Group                  string            `json:"group" gorm:"index"`
	Ip                     string            `json:"ip" gorm:"index;default:''"`
	RequestId              string            `json:"request_id,omitempty" gorm:"type:varchar(64);index:idx_logs_request_id;default:''"`
	UpstreamRequestId      string            `json:"upstream_request_id,omitempty" gorm:"type:varchar(128);index:idx_logs_upstream_request_id;default:''"`
	Other                  string            `json:"other"`
	Metering               *LogTokenMetering `json:"metering,omitempty" gorm:"-"`
	MeteredInputTokens     *int64            `json:"-"`
	MeteredCacheReadTokens *int64            `json:"-"`
	MeteredOutputTokens    *int64            `json:"-"`
}

// don't use iota, avoid change log type value
const (
	LogTypeUnknown = 0
	LogTypeTopup   = 1
	LogTypeConsume = 2
	LogTypeManage  = 3
	LogTypeSystem  = 4
	LogTypeError   = 5
	LogTypeRefund  = 6
	LogTypeLogin   = 7
)

func ensureLogRequestId(log *Log) {
	if log != nil && log.RequestId == "" {
		log.RequestId = common.NewRequestId()
	}
}

func createLog(log *Log) error {
	ensureLogRequestId(log)
	if log.Type == LogTypeConsume {
		metering := log.TokenMetering()
		log.MeteredInputTokens, log.MeteredCacheReadTokens, log.MeteredOutputTokens =
			metering.InputTokens, metering.CacheReadTokens, metering.OutputTokens
	}
	return LOG_DB.Create(log).Error
}

func clickHouseLogOrder(prefix string) string {
	return prefix + "created_at desc, " + prefix + "request_id desc"
}

func assignDisplayLogIds(logs []*Log, startIdx int) {
	for i := range logs {
		logs[i].Id = startIdx + i + 1
	}
}

func formatUserLogs(logs []*Log, startIdx int, tokenVisibility ...map[int]TokenLogVisibility) {
	for i := range logs {
		formatUserLog(logs[i], tokenVisibility...)
	}
	assignDisplayLogIds(logs, startIdx)
}

func formatUserLog(log *Log, tokenVisibility ...map[int]TokenLogVisibility) {
	if log.Type == LogTypeConsume {
		log.Metering = log.TokenMetering()
	}
	if len(tokenVisibility) != 0 && tokenVisibility[0] != nil {
		visibility := tokenVisibility[0][log.TokenId]
		if !visibility.FullDetails {
			name := log.TokenName
			if name == "" && log.TokenId > 0 {
				name = fmt.Sprintf("Key #%d", log.TokenId)
			}
			if visibility.Managed {
				name = ManagedTokenDisplayName
			}
			*log = Log{Id: log.Id, UserId: log.UserId, CreatedAt: log.CreatedAt, Type: log.Type,
				ModelName: log.ModelName, BillingProduct: log.BillingProduct, Group: log.Group, Quota: log.Quota, PromptTokens: log.PromptTokens,
				CompletionTokens: log.CompletionTokens, UseTime: log.UseTime, IsStream: log.IsStream,
				TokenId: log.TokenId, TokenName: name, Metering: log.Metering,
				Other: formatLogOtherJSON(log.Other, logOtherVisibilityBillingFacts)}
			return
		}
	}
	log.ChannelName = ""
	log.Other = formatLogOtherJSON(log.Other, logOtherVisibilityUser)
}

// FormatAdminLogs removes root-only diagnostics while retaining operational
// admin_info. Root callers must not pass their results through this formatter.
func FormatAdminLogs(logs []*Log) {
	for i := range logs {
		if logs[i].Type == LogTypeConsume {
			logs[i].Metering = logs[i].TokenMetering()
		}
		logs[i].Other = formatLogOtherJSON(logs[i].Other, logOtherVisibilityAdmin)
	}
}

// FormatRootLogs normalizes legacy metadata into the current scoped shape
// without removing root-only diagnostics.
func FormatRootLogs(logs []*Log) {
	for i := range logs {
		if logs[i].Type == LogTypeConsume {
			logs[i].Metering = logs[i].TokenMetering()
		}
		logs[i].Other = formatLogOtherJSON(logs[i].Other, logOtherVisibilityRoot)
	}
}

func GetLogByTokenId(tokenId int) (logs []*Log, err error) {
	order := "id desc"
	if common.UsingLogDatabase(common.DatabaseTypeClickHouse) {
		order = clickHouseLogOrder("")
	}
	err = LOG_DB.Model(&Log{}).Where("token_id = ?", tokenId).Order(order).Limit(common.MaxRecentItems).Find(&logs).Error
	formatUserLogs(logs, 0)
	return logs, err
}

func RecordLog(userId int, logType int, content *common.Message) {
	if logType == LogTypeConsume && !common.LogConsumeEnabled {
		return
	}
	username, _ := GetUsernameById(userId, false)
	other := NewLogOther()
	log := &Log{
		UserId:    userId,
		Username:  username,
		CreatedAt: common.GetTimestamp(),
		Type:      logType,
		Content:   other.setContent([]*common.Message{content}),
		Other:     other.JSONString(),
	}
	err := createLog(log)
	if err != nil {
		common.SysLog(common.LogText("failed to record log: %s", err.Error()))
	}
}

// RecordLogWithAdminInfo stores operator metadata under other.admin_info and
// an optional, user-visible operation descriptor under other.op for localization.
func RecordLogWithAdminInfo(userId int, logType int, content string, adminInfo *AuditAdminInfo, operation *AuditOperation, request ...*gin.Context) {
	if logType == LogTypeConsume && !common.LogConsumeEnabled {
		return
	}
	username, _ := GetUsernameById(userId, false)
	log := &Log{
		UserId:    userId,
		Username:  username,
		CreatedAt: common.GetTimestamp(),
		Type:      logType,
		Content:   content,
	}
	if logType == LogTypeManage {
		var c *gin.Context
		if len(request) > 0 {
			c = request[0]
		}
		actorRole := 0
		if c != nil {
			actorRole = c.GetInt("role")
		}
		RecordAuditLog(c, AuditLog{UserId: userId, Username: username, ActorRole: actorRole, Category: AuditCategoryOperation, Content: content, Other: AuditOther{AdminInfo: adminInfo, Op: operation}, Success: true})
		return
	}
	if len(request) > 0 && request[0] != nil {
		log.RequestId = request[0].GetString(common.RequestIdKey)
	}
	if adminInfo != nil || operation != nil {
		data, err := common.Marshal(AuditOther{AdminInfo: adminInfo, Op: operation})
		if err != nil {
			common.SysError(common.LogText("failed to encode log admin info: %s", err.Error()))
			return
		}
		log.Other = string(data)
	}
	if err := createLog(log); err != nil {
		common.SysLog(common.LogText("failed to record log: %s", err.Error()))
	}
}

// RecordLoginLog writes new login events to the independent audit table.
// username 由调用方传入（登录流程已持有用户对象），避免额外的数据库查询。
// content 为英文兜底文本（用于导出）；action+params 供前端本地化渲染。
// other 包含 login_method、user_agent 等结构化信息。
func RecordLoginLog(userId, actorRole int, username string, content string, ip string, action string, params map[string]any, other AuditOther, request ...*gin.Context) {
	other.Op = &AuditOperation{Action: action, Params: params}
	var c *gin.Context
	if len(request) > 0 {
		c = request[0]
	}
	RecordAuditLog(c, AuditLog{UserId: userId, Username: username, ActorRole: actorRole, Category: AuditCategoryLogin, Action: action, Content: content, Ip: ip, Other: other, Success: true})
}

// RecordOperationAuditLog writes new operation/security events to the audit table.
// logUserId 为日志归属者，管理审计日志应归属实际操作者；目标资源/用户放入
// action params。username 内部按 logUserId 查询。content 为英文兜底文本（供导出使用）。
// action+params 写入 Other.op，供前端本地化渲染（普通用户可见，不含敏感信息）。
// adminInfo 存放操作者身份（写入 Other.admin_info，普通用户查询时剥离）；
// auditInfo 存放路由/方法/结果等中间件兜底信息（写入 Other.audit_info，普通用户查询时剥离）。
func RecordOperationAuditLog(logUserId, actorRole int, content string, ip string, action string, params map[string]any, adminInfo *AuditAdminInfo, auditInfo *AuditRequestInfo, request ...*gin.Context) {
	username, _ := GetUsernameById(logUserId, false)
	other := AuditOther{
		Op:        &AuditOperation{Action: action, Params: params},
		AdminInfo: adminInfo,
		AuditInfo: auditInfo,
	}
	var c *gin.Context
	if len(request) > 0 {
		c = request[0]
	}
	category := AuditCategoryOperation
	if adminInfo == nil {
		category = AuditCategorySecurity
	}
	status, success := 200, true
	if auditInfo != nil {
		status = auditInfo.Status
		success = auditInfo.Success
	}
	RecordAuditLog(c, AuditLog{UserId: logUserId, Username: username, ActorRole: actorRole, Category: category, Action: action, Content: content, Ip: ip, Status: status, Success: success, Other: other})
}

func RecordTopupLog(userId int, content *common.Message, callerIp string, paymentMethod string, callbackPaymentMethod string) {
	username, _ := GetUsernameById(userId, false)
	other := NewLogOther()
	other.MergeAdmin(map[string]any{
		"server_ip":               common.GetIp(),
		"node_name":               common.NodeName,
		"caller_ip":               callerIp,
		"payment_method":          paymentMethod,
		"callback_payment_method": callbackPaymentMethod,
		"version":                 common.Version,
	})
	log := &Log{
		UserId:    userId,
		Username:  username,
		CreatedAt: common.GetTimestamp(),
		Type:      LogTypeTopup,
		Content:   other.setContent([]*common.Message{content}),
		Ip:        callerIp,
		Other:     other.JSONString(),
	}
	err := createLog(log)
	if err != nil {
		common.SysLog(common.LogText("failed to record topup log: %s", err.Error()))
	}
}

func RecordErrorLog(c *gin.Context, userId int, channelId int, modelName string, tokenName string, content string, tokenId int, useTimeSeconds int,
	isStream bool, group string, other *LogOther) {
	logger.LogInfo(c, common.LogText("record error log: userId=%d, channelId=%d, modelName=%s, tokenName=%s, content=%s", userId, channelId, modelName, tokenName, common.LocalLogPreview(content)))
	username := c.GetString("username")
	requestId := c.GetString(common.RequestIdKey)
	upstreamRequestId := c.GetString(common.UpstreamRequestIdKey)
	otherStr := other.JSONString()
	// 判断是否需要记录 IP
	needRecordIp := false
	if settingMap, err := GetUserSetting(userId, false); err == nil {
		if settingMap.RecordIpLog {
			needRecordIp = true
		}
	}
	log := &Log{
		UserId:           userId,
		Username:         username,
		CreatedAt:        common.GetTimestamp(),
		Type:             LogTypeError,
		Content:          content,
		PromptTokens:     0,
		CompletionTokens: 0,
		TokenName:        tokenName,
		ModelName:        modelName,
		Quota:            0,
		ChannelId:        channelId,
		TokenId:          tokenId,
		UseTime:          useTimeSeconds,
		IsStream:         isStream,
		Group:            group,
		Ip: func() string {
			if needRecordIp {
				return c.ClientIP()
			}
			return ""
		}(),
		RequestId:         requestId,
		UpstreamRequestId: upstreamRequestId,
		Other:             otherStr,
	}
	err := createLog(log)
	if err != nil {
		logger.LogError(c, common.LogText("failed to record log: %s", err.Error()))
	}
}

type RecordConsumeLogParams struct {
	ChannelId        int               `json:"channel_id"`
	PromptTokens     int               `json:"prompt_tokens"`
	CompletionTokens int               `json:"completion_tokens"`
	ModelName        string            `json:"model_name"`
	TokenName        string            `json:"token_name"`
	Quota            int               `json:"quota"`
	Content          []*common.Message `json:"content"`
	TokenId          int               `json:"token_id"`
	UseTimeSeconds   int               `json:"use_time_seconds"`
	IsStream         bool              `json:"is_stream"`
	Group            string            `json:"group"`
	Other            *LogOther         `json:"other"`
}

func RecordConsumeLog(c *gin.Context, userId int, params RecordConsumeLogParams) {
	if !common.LogConsumeEnabled {
		return
	}
	logger.LogInfo(c, common.LogText("record consume log: userId=%d, params=%s", userId, common.GetJsonString(params)))
	username := c.GetString("username")
	requestId := c.GetString(common.RequestIdKey)
	upstreamRequestId := c.GetString(common.UpstreamRequestIdKey)
	createdAt := common.GetTimestamp()
	other := params.Other
	content := other.setContent(params.Content)
	otherStr := other.JSONString()
	// 判断是否需要记录 IP
	needRecordIp := false
	if settingMap, err := GetUserSetting(userId, false); err == nil {
		if settingMap.RecordIpLog {
			needRecordIp = true
		}
	}
	log := &Log{
		UserId:             userId,
		Username:           username,
		CreatedAt:          createdAt,
		Type:               LogTypeConsume,
		Content:            content,
		PromptTokens:       params.PromptTokens,
		CompletionTokens:   params.CompletionTokens,
		TokenName:          params.TokenName,
		ModelName:          params.ModelName,
		Quota:              params.Quota,
		ChannelId:          params.ChannelId,
		TokenId:            params.TokenId,
		BillingContextRef:  c.GetString("model_billing_context_ref"),
		BillingPolicyEpoch: c.GetString("model_billing_policy_epoch"),
		RequestStartedAt:   c.GetInt64("model_billing_request_started_at"),
		BillingProduct:     c.GetString("model_billing_product"),
		UseTime:            params.UseTimeSeconds,
		IsStream:           params.IsStream,
		Group:              params.Group,
		Ip: func() string {
			if needRecordIp {
				return c.ClientIP()
			}
			return ""
		}(),
		RequestId:         requestId,
		UpstreamRequestId: upstreamRequestId,
		Other:             otherStr,
	}
	err := createLog(log)
	if err != nil {
		logger.LogError(c, common.LogText("failed to record log: %s", err.Error()))
	}
	if common.DataExportEnabled {
		LogQuotaData(QuotaDataLogParams{
			UserID:    userId,
			Username:  username,
			ModelName: params.ModelName,
			Quota:     params.Quota,
			CreatedAt: createdAt,
			TokenUsed: params.PromptTokens + params.CompletionTokens,
			UseGroup:  params.Group,
			TokenID:   params.TokenId,
			ChannelID: params.ChannelId,
			NodeName:  common.NodeName,
		})
	}
}

type RecordTaskBillingLogParams struct {
	UserId    int
	LogType   int
	Content   []*common.Message
	ChannelId int
	ModelName string
	Quota     int
	TokenId   int
	Group     string
	Other     *LogOther
	NodeName  string // 任务发起节点；为空时回退当前节点
}

func RecordTaskBillingLog(params RecordTaskBillingLogParams) {
	if params.LogType == LogTypeConsume && !common.LogConsumeEnabled {
		return
	}
	username, _ := GetUsernameById(params.UserId, false)
	tokenName := ""
	if params.TokenId > 0 {
		if token, err := GetTokenById(params.TokenId); err == nil {
			tokenName = token.Name
		}
	}
	createdAt := common.GetTimestamp()
	other := params.Other
	log := &Log{
		UserId:    params.UserId,
		Username:  username,
		CreatedAt: createdAt,
		Type:      params.LogType,
		Content:   other.setContent(params.Content),
		TokenName: tokenName,
		ModelName: params.ModelName,
		Quota:     params.Quota,
		ChannelId: params.ChannelId,
		TokenId:   params.TokenId,
		Group:     params.Group,
		Other:     other.JSONString(),
	}
	err := createLog(log)
	if err != nil {
		common.SysLog(common.LogText("failed to record task billing log: %s", err.Error()))
	}
	if params.LogType == LogTypeConsume && common.DataExportEnabled {
		nodeName := params.NodeName
		if nodeName == "" {
			nodeName = common.NodeName
		}
		LogQuotaData(QuotaDataLogParams{
			UserID:    params.UserId,
			Username:  username,
			ModelName: params.ModelName,
			Quota:     params.Quota,
			CreatedAt: createdAt,
			UseGroup:  params.Group,
			TokenID:   params.TokenId,
			ChannelID: params.ChannelId,
			NodeName:  nodeName,
		})
	}
}

// LogFilter is the usage-log search shared by the log list and the log export.
// Username and Channel are administrator filters.
type LogFilter struct {
	Type               int
	StartTimestamp     int64
	EndTimestamp       int64
	ModelName          string
	Username           string
	TokenName          string
	Channel            int
	Group              string
	RequestId          string
	UpstreamRequestId  string
	UserID             *int
	TokenID            *int
	TokenVisibility    map[int]TokenLogVisibility
	BillingContextRef  *string
	BillingPolicyEpoch *string
	BillingProduct     string
	IncludeMetering    bool
	Context            context.Context
}

func (f LogFilter) apply(tx *gorm.DB) (*gorm.DB, error) {
	var err error
	if f.Context != nil {
		tx = tx.WithContext(f.Context)
	}
	if f.UserID != nil {
		tx = tx.Where("logs.user_id = ?", *f.UserID)
	}
	if f.TokenID != nil {
		tx = tx.Where("logs.token_id = ?", *f.TokenID)
	}
	if f.TokenVisibility != nil {
		// Management grants read model usage, not unrelated owner account events.
		tx = tx.Where("logs.type IN ?", []int{LogTypeConsume, LogTypeError, LogTypeRefund})
	}
	if f.BillingContextRef != nil {
		tx = tx.Where("logs.billing_context_ref = ?", *f.BillingContextRef)
	}
	if f.BillingPolicyEpoch != nil {
		tx = tx.Where("logs.billing_policy_epoch = ?", *f.BillingPolicyEpoch)
	}
	if f.BillingProduct != "" {
		tx = tx.Where("(logs.billing_product = ? OR ((logs.billing_product IS NULL OR logs.billing_product = '') AND logs.model_name = ?))", f.BillingProduct, f.BillingProduct)
	}
	if f.Type != LogTypeUnknown {
		tx = tx.Where("logs.type = ?", f.Type)
	}
	if tx, err = applyExplicitLogTextFilter(tx, "logs.model_name", f.ModelName); err != nil {
		return nil, err
	}
	if tx, err = applyExplicitLogTextFilter(tx, "logs.username", f.Username); err != nil {
		return nil, err
	}
	if f.TokenName != "" {
		managedIDs := []int{}
		for id, visibility := range f.TokenVisibility {
			if visibility.Managed {
				managedIDs = append(managedIDs, id)
			}
		}
		if len(managedIDs) == 0 {
			tx = tx.Where("logs.token_name = ?", f.TokenName)
		} else if f.TokenName == ManagedTokenDisplayName {
			tx = tx.Where("(logs.token_id IN ? OR logs.token_name = ?)", managedIDs, f.TokenName)
		} else {
			tx = tx.Where("logs.token_id NOT IN ? AND logs.token_name = ?", managedIDs, f.TokenName)
		}
	}
	if f.RequestId != "" {
		tx = tx.Where("logs.request_id = ?", f.RequestId)
	}
	if f.UpstreamRequestId != "" {
		tx = tx.Where("logs.upstream_request_id = ?", f.UpstreamRequestId)
	}
	timeColumn := "logs.created_at"
	if f.BillingPolicyEpoch != nil && *f.BillingPolicyEpoch != "" {
		timeColumn = "logs.request_started_at"
	}
	if f.StartTimestamp != 0 {
		tx = tx.Where(timeColumn+" >= ?", f.StartTimestamp)
	}
	if f.EndTimestamp != 0 {
		tx = tx.Where(timeColumn+" <= ?", f.EndTimestamp)
	}
	if f.Channel != 0 {
		tx = tx.Where("logs.channel_id = ?", f.Channel)
	}
	if f.Group != "" {
		tx = tx.Where("logs."+logGroupCol+" = ?", f.Group)
	}
	return tx, nil
}

func GetAllLogs(filter LogFilter, startIdx int, num int) (logs []*Log, total int64, err error) {
	tx, err := filter.apply(LOG_DB)
	if err != nil {
		return nil, 0, err
	}
	err = tx.Model(&Log{}).Count(&total).Error
	if err != nil {
		return nil, 0, err
	}
	order := "logs.created_at desc, logs.id desc"
	if common.UsingLogDatabase(common.DatabaseTypeClickHouse) {
		order = clickHouseLogOrder("logs.")
	}
	err = tx.Order(order).Limit(num).Offset(startIdx).Find(&logs).Error
	if err != nil {
		return nil, 0, err
	}
	if common.UsingLogDatabase(common.DatabaseTypeClickHouse) {
		assignDisplayLogIds(logs, startIdx)
	}

	channelIds := types.NewSet[int]()
	for _, log := range logs {
		if log.ChannelId != 0 {
			channelIds.Add(log.ChannelId)
		}
	}

	if channelIds.Len() > 0 {
		var channels []struct {
			Id   int    `gorm:"column:id"`
			Name string `gorm:"column:name"`
		}
		if common.MemoryCacheEnabled {
			// Cache get channel
			for _, channelId := range channelIds.Items() {
				if cacheChannel, err := CacheGetChannel(channelId); err == nil {
					channels = append(channels, struct {
						Id   int    `gorm:"column:id"`
						Name string `gorm:"column:name"`
					}{
						Id:   channelId,
						Name: cacheChannel.Name,
					})
				}
			}
		} else {
			// Bulk query channels from DB
			if err = DB.Table("channels").Select("id, name").Where("id IN ?", channelIds.Items()).Find(&channels).Error; err != nil {
				return logs, total, err
			}
		}
		channelMap := make(map[int]string, len(channels))
		for _, channel := range channels {
			channelMap[channel.Id] = channel.Name
		}
		for i := range logs {
			logs[i].ChannelName = channelMap[logs[i].ChannelId]
		}
	}

	return logs, total, err
}

const logSearchCountLimit = 10000

func GetUserLogs(userId int, filter LogFilter, startIdx int, num int) (logs []*Log, total int64, err error) {
	tx, err := filter.apply(LOG_DB.Where("logs.user_id = ?", userId))
	if err != nil {
		return nil, 0, err
	}
	err = tx.Model(&Log{}).Limit(logSearchCountLimit).Count(&total).Error
	if err != nil {
		common.SysError(common.LogText("failed to count user logs: %s", err.Error()))
		return nil, 0, common.NewMessage("Failed to query logs")
	}
	order := "logs.id desc"
	if common.UsingLogDatabase(common.DatabaseTypeClickHouse) {
		order = clickHouseLogOrder("logs.")
	}
	err = tx.Order(order).Limit(num).Offset(startIdx).Find(&logs).Error
	if err != nil {
		common.SysError(common.LogText("failed to search user logs: %s", err.Error()))
		return nil, 0, common.NewMessage("Failed to query logs")
	}

	formatUserLogs(logs, startIdx, filter.TokenVisibility)
	return logs, total, err
}

// StreamAllLogs calls fn with each log matching filter, newest first, as an
// administrator with role sees it. Rows are read one at a time, so an export
// never holds the whole result in memory.
func StreamAllLogs(ctx context.Context, filter LogFilter, role int, fn func(*Log) error) error {
	tx, err := filter.apply(LOG_DB.WithContext(ctx))
	if err != nil {
		return err
	}
	visibility := logOtherVisibilityAdmin
	if role >= common.RoleRootUser {
		visibility = logOtherVisibilityRoot
	}
	channelNames := make(map[int]string)
	return streamLogs(tx, "logs.created_at desc, logs.id desc", func(log *Log) error {
		if log.ChannelId != 0 {
			name, ok := channelNames[log.ChannelId]
			if !ok {
				if channel, err := CacheGetChannel(log.ChannelId); err == nil {
					name = channel.Name
				}
				channelNames[log.ChannelId] = name
			}
			log.ChannelName = name
		}
		log.Other = formatLogOtherJSON(log.Other, visibility)
		return fn(log)
	})
}

// StreamUserLogs is StreamAllLogs for one user's own logs, shaped like the
// user log list.
func StreamUserLogs(ctx context.Context, userId int, filter LogFilter, fn func(*Log) error) error {
	tx, err := filter.apply(LOG_DB.WithContext(ctx).Where("logs.user_id = ?", userId))
	if err != nil {
		return err
	}
	count := 0
	return streamLogs(tx, "logs.id desc", func(log *Log) error {
		count++
		log.Id = count
		formatUserLog(log, filter.TokenVisibility)
		return fn(log)
	})
}

func streamLogs(tx *gorm.DB, order string, fn func(*Log) error) error {
	if common.UsingLogDatabase(common.DatabaseTypeClickHouse) {
		order = clickHouseLogOrder("logs.")
	}
	rows, err := tx.Model(&Log{}).Order(order).Rows()
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var log Log
		if err := LOG_DB.ScanRows(rows, &log); err != nil {
			return err
		}
		if err := fn(&log); err != nil {
			return err
		}
	}
	return rows.Err()
}

type ModelUsageActivity struct {
	PolicyEpoch   string `json:"policy_epoch"`
	Model         string `json:"model"`
	FromTimestamp int64  `json:"from_timestamp"`
	ToTimestamp   int64  `json:"to_timestamp"`
}

// CompletedModelUsage discovers affected billing periods without copying raw
// requests or their financial amounts to the control plane. Completion overlap
// catches ordinary out-of-order commits; request start can be arbitrarily old.
func CompletedModelUsage(ctx context.Context, userID, tokenID int, bindingRef string,
	afterLogID, pageAfterLogID, completedSince int64, limit int) ([]ModelUsageActivity, int64, bool, error) {
	if common.UsingLogDatabase(common.DatabaseTypeClickHouse) {
		return nil, 0, false, fmt.Errorf("model usage collection requires relational log identifiers")
	}
	query := LOG_DB.WithContext(ctx).Model(&Log{}).Where(
		"user_id = ? AND token_id = ? AND billing_context_ref = ? AND type = ? AND billing_policy_epoch <> '' AND id > ?",
		userID, tokenID, bindingRef, LogTypeConsume, pageAfterLogID)
	if completedSince > 0 {
		query = query.Where("(id > ? OR created_at >= ?)", afterLogID, completedSince)
	} else {
		query = query.Where("id > ?", afterLogID)
	}
	var logs []Log
	if err := query.Select("id, billing_policy_epoch, billing_product, model_name, request_started_at").
		Order("id").Limit(limit + 1).Find(&logs).Error; err != nil {
		return nil, 0, false, err
	}
	more := len(logs) > limit
	if more {
		logs = logs[:limit]
	}
	type activityKey struct {
		epoch, model string
		hour         int64
	}
	groups := make(map[activityKey]ModelUsageActivity)
	next := pageAfterLogID
	for _, entry := range logs {
		product := entry.BillingProduct
		if product == "" {
			product = entry.ModelName
		}
		key := activityKey{entry.BillingPolicyEpoch, product, entry.RequestStartedAt / 3600}
		group, exists := groups[key]
		if !exists {
			group = ModelUsageActivity{entry.BillingPolicyEpoch, product, entry.RequestStartedAt, entry.RequestStartedAt}
		} else {
			group.FromTimestamp = min(group.FromTimestamp, entry.RequestStartedAt)
			group.ToTimestamp = max(group.ToTimestamp, entry.RequestStartedAt)
		}
		groups[key] = group
		next = int64(entry.Id)
	}
	result := make([]ModelUsageActivity, 0, len(groups))
	for _, group := range groups {
		result = append(result, group)
	}
	slices.SortFunc(result, func(a, b ModelUsageActivity) int {
		if a.PolicyEpoch == b.PolicyEpoch {
			if a.Model == b.Model {
				return cmp.Compare(a.FromTimestamp, b.FromTimestamp)
			}
			return cmp.Compare(a.Model, b.Model)
		}
		return cmp.Compare(a.PolicyEpoch, b.PolicyEpoch)
	})
	return result, next, more, nil
}

type Stat struct {
	Quota                int    `json:"quota"`
	Rpm                  int    `json:"rpm"`
	Tpm                  int    `json:"tpm"`
	RequestCount         int64  `json:"request_count"`
	RequestStartedAt     *int64 `json:"request_started_at"`
	LastRequestStartedAt *int64 `json:"last_request_started_at"`
	InputTokens          *int64 `json:"input_tokens"`
	CacheReadTokens      *int64 `json:"cache_read_tokens"`
	OutputTokens         *int64 `json:"output_tokens"`
	MeteringAvailable    bool   `json:"metering_available" gorm:"-"`
}

// Metering uses the same source rows as the charge. Parse optional metadata in
// Go so malformed historical JSON or an oversized counter cannot break quota SUM.
func (stat *Stat) readMetering(query *gorm.DB) {
	rows, err := query.Session(&gorm.Session{}).Select("quota, prompt_tokens, completion_tokens, other").Rows()
	if err != nil {
		common.SysError(common.LogText("failed to query log stat: %s", err.Error()))
		return
	}
	defer rows.Close()
	total := LogTokenMetering{InputTokens: new(int64), CacheReadTokens: new(int64), OutputTokens: new(int64)}
	count, quota := int64(0), decimal.Zero
	for rows.Next() {
		var entry Log
		if err = LOG_DB.ScanRows(rows, &entry); err != nil {
			break
		}
		count++
		quota = quota.Add(decimal.NewFromInt(int64(entry.Quota)))
		measured := entry.TokenMetering()
		total.InputTokens = addLogTokenCounts(total.InputTokens, measured.InputTokens)
		total.CacheReadTokens = addLogTokenCounts(total.CacheReadTokens, measured.CacheReadTokens)
		total.OutputTokens = addLogTokenCounts(total.OutputTokens, measured.OutputTokens)
	}
	if err == nil {
		err = rows.Err()
	}
	if err != nil {
		common.SysError(common.LogText("failed to query log stat: %s", err.Error()))
		return
	}
	// A log may arrive or expire between these reads. Do not attach counters from
	// a different source set to the original charge observation.
	if count != stat.RequestCount || !quota.Equal(decimal.NewFromInt(int64(stat.Quota))) {
		return
	}
	stat.InputTokens, stat.CacheReadTokens, stat.OutputTokens = total.InputTokens, total.CacheReadTokens, total.OutputTokens
	stat.MeteringAvailable = true
}

func SumUsedQuota(logType int, startTimestamp int64, endTimestamp int64, modelName string, username string, tokenName string, channel int, group string, nativeIdentity ...LogFilter) (stat Stat, err error) {
	tx := LOG_DB.Table("logs").Select("COALESCE(sum(quota), 0) quota, COUNT(*) request_count")
	timeColumn := "created_at"
	if len(nativeIdentity) == 1 && nativeIdentity[0].BillingPolicyEpoch != nil && *nativeIdentity[0].BillingPolicyEpoch != "" {
		timeColumn = "request_started_at"
		fields := "COALESCE(sum(quota), 0) quota, COUNT(*) request_count, MIN(request_started_at) request_started_at, MAX(request_started_at) last_request_started_at"
		if nativeIdentity[0].IncludeMetering {
			for _, field := range []string{"input_tokens", "cache_read_tokens", "output_tokens"} {
				column := "metered_" + field
				fields += fmt.Sprintf(", CASE WHEN COUNT(%s) = COUNT(*) AND COALESCE(SUM(%s), 0) <= %d THEN COALESCE(SUM(%s), 0) ELSE NULL END %s",
					column, column, common.MaxWalletQuota, column, field)
			}
		}
		tx = tx.Select(fields)
	}

	// 为rpm和tpm创建单独的查询
	rpmTpmQuery := LOG_DB.Table("logs").Select("count(*) rpm, COALESCE(sum(prompt_tokens), 0) + COALESCE(sum(completion_tokens), 0) tpm")
	if len(nativeIdentity) == 1 {
		nativeIdentity[0].BillingProduct = modelName
		modelName = ""
		tx, err = nativeIdentity[0].apply(tx)
		if err != nil {
			return stat, err
		}
		rpmTpmQuery, err = nativeIdentity[0].apply(rpmTpmQuery)
		if err != nil {
			return stat, err
		}
		if nativeIdentity[0].TokenVisibility != nil {
			tokenName = ""
		}
	}

	if tx, err = applyExplicitLogTextFilter(tx, "username", username); err != nil {
		return stat, err
	}
	if rpmTpmQuery, err = applyExplicitLogTextFilter(rpmTpmQuery, "username", username); err != nil {
		return stat, err
	}
	if tokenName != "" {
		tx = tx.Where("token_name = ?", tokenName)
		rpmTpmQuery = rpmTpmQuery.Where("token_name = ?", tokenName)
	}
	if startTimestamp != 0 {
		tx = tx.Where(timeColumn+" >= ?", startTimestamp)
	}
	if endTimestamp != 0 {
		tx = tx.Where(timeColumn+" <= ?", endTimestamp)
	}
	if tx, err = applyExplicitLogTextFilter(tx, "model_name", modelName); err != nil {
		return stat, err
	}
	if rpmTpmQuery, err = applyExplicitLogTextFilter(rpmTpmQuery, "model_name", modelName); err != nil {
		return stat, err
	}
	if channel != 0 {
		tx = tx.Where("channel_id = ?", channel)
		rpmTpmQuery = rpmTpmQuery.Where("channel_id = ?", channel)
	}
	if group != "" {
		tx = tx.Where(logGroupCol+" = ?", group)
		rpmTpmQuery = rpmTpmQuery.Where(logGroupCol+" = ?", group)
	}

	tx = tx.Where("type = ?", LogTypeConsume)
	rpmTpmQuery = rpmTpmQuery.Where("type = ?", LogTypeConsume)

	// 只统计最近60秒的rpm和tpm
	rpmTpmQuery = rpmTpmQuery.Where("created_at >= ?", time.Now().Add(-60*time.Second).Unix())

	// 执行查询
	if err := tx.Scan(&stat).Error; err != nil {
		common.SysError(common.LogText("failed to query log stat: %s", err.Error()))
		return stat, common.NewMessage("Failed to query statistics")
	}
	if len(nativeIdentity) == 1 && nativeIdentity[0].IncludeMetering {
		if timeColumn == "request_started_at" {
			stat.MeteringAvailable = true
		} else {
			stat.readMetering(tx)
		}
	}
	if len(nativeIdentity) == 1 && nativeIdentity[0].BillingPolicyEpoch != nil {
		return stat, nil // Financial collection does not need the console's last-minute rate.
	}
	var rateStat struct {
		Rpm int
		Tpm int
	}
	if err := rpmTpmQuery.Scan(&rateStat).Error; err != nil {
		common.SysError(common.LogText("failed to query rpm/tpm stat: %s", err.Error()))
		return stat, common.NewMessage("Failed to query statistics")
	}
	stat.Rpm = rateStat.Rpm
	stat.Tpm = rateStat.Tpm

	return stat, nil
}

func SumUsedToken(logType int, startTimestamp int64, endTimestamp int64, modelName string, username string, tokenName string) (token int) {
	tx := LOG_DB.Table("logs").Select("COALESCE(sum(prompt_tokens), 0) + COALESCE(sum(completion_tokens), 0)")
	if username != "" {
		tx = tx.Where("username = ?", username)
	}
	if tokenName != "" {
		tx = tx.Where("token_name = ?", tokenName)
	}
	if startTimestamp != 0 {
		tx = tx.Where("created_at >= ?", startTimestamp)
	}
	if endTimestamp != 0 {
		tx = tx.Where("created_at <= ?", endTimestamp)
	}
	if modelName != "" {
		tx = tx.Where("model_name = ?", modelName)
	}
	tx.Where("type = ?", LogTypeConsume).Scan(&token)
	return token
}

func CountOldLog(ctx context.Context, targetTimestamp int64) (int64, error) {
	var total int64
	if err := LOG_DB.WithContext(ctx).Model(&Log{}).Where("created_at < ?", targetTimestamp).Count(&total).Error; err != nil {
		return 0, err
	}
	return total, nil
}

func DeleteOldLogBatch(ctx context.Context, targetTimestamp int64, limit int) (int64, error) {
	if limit <= 0 {
		limit = 100
	}
	if nil != ctx.Err() {
		return 0, ctx.Err()
	}

	if common.UsingLogDatabase(common.DatabaseTypeClickHouse) {
		// ClickHouse DELETE is a heavy mutation that rewrites data parts, so
		// per-batch mutations would be pathologically slow. Remove all matching
		// rows in a single synchronous mutation regardless of limit; the reported
		// count lets the caller's progress loop complete in one pass.
		total, err := CountOldLog(ctx, targetTimestamp)
		if err != nil {
			return 0, err
		}
		if total == 0 {
			return 0, nil
		}
		if err := LOG_DB.WithContext(ctx).Exec(
			"ALTER TABLE logs DELETE WHERE created_at < ? SETTINGS mutations_sync = 1",
			targetTimestamp,
		).Error; err != nil {
			return 0, err
		}
		return total, nil
	}

	result := LOG_DB.WithContext(ctx).Where("created_at < ?", targetTimestamp).Limit(limit).Delete(&Log{})
	if nil != result.Error {
		return 0, result.Error
	}
	return result.RowsAffected, nil
}
