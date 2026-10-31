package model

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/QuantumNous/new-api/common"
)

// LogTokenMetering reports normalized total input, its cache-read subset and
// output. Nil means unavailable, never zero. Counters must be exact in JSON/JS.
type LogTokenMetering struct {
	InputTokens     *int64 `json:"input_tokens"`
	CacheReadTokens *int64 `json:"cache_read_tokens"`
	OutputTokens    *int64 `json:"output_tokens"`
}

func (metering *LogTokenMetering) validateCacheSubset() {
	if metering.InputTokens != nil && metering.CacheReadTokens != nil && *metering.CacheReadTokens > *metering.InputTokens {
		metering.CacheReadTokens = nil
	}
}

func logTokenCount(value int64) *int64 {
	if value < 0 || value > common.MaxWalletQuota {
		return nil
	}
	return &value
}

func addLogTokenCounts(left, right *int64) *int64 {
	if left == nil || right == nil || *right > common.MaxWalletQuota-*left {
		return nil
	}
	return logTokenCount(*left + *right)
}

func logJSONTokenCount(fields map[string]json.RawMessage, key string) *int64 {
	var value *int64
	if common.Unmarshal(fields[key], &value) != nil || value == nil {
		return nil
	}
	return logTokenCount(*value)
}

func (entry *Log) TokenMetering() *LogTokenMetering {
	result := &LogTokenMetering{OutputTokens: logTokenCount(int64(entry.CompletionTokens))}
	defer result.validateCacheSubset()
	fields := map[string]json.RawMessage{}
	if strings.TrimSpace(entry.Other) != "" && common.UnmarshalJsonStr(entry.Other, &fields) != nil {
		return result
	}
	result.CacheReadTokens = logJSONTokenCount(fields, "cache_tokens")
	if _, present := fields["input_tokens_total"]; present {
		result.InputTokens = logJSONTokenCount(fields, "input_tokens_total")
		return result
	}
	var claude bool
	var semantic string
	if raw, present := fields["claude"]; present && common.Unmarshal(raw, &claude) != nil {
		return result
	}
	if raw, present := fields["usage_semantic"]; present && common.Unmarshal(raw, &semantic) != nil {
		return result
	}
	result.InputTokens = logTokenCount(int64(entry.PromptTokens))
	if !claude && semantic != "anthropic" {
		return result
	}
	written := logJSONTokenCount(fields, "cache_write_tokens")
	if _, present := fields["cache_write_tokens"]; !present {
		_, short := fields["cache_creation_tokens_5m"]
		_, long := fields["cache_creation_tokens_1h"]
		if short || long {
			// The native writer omits zero-valued split cache-creation buckets.
			written = new(int64)
			for _, name := range []string{"cache_creation_tokens_5m", "cache_creation_tokens_1h"} {
				if _, present := fields[name]; present {
					written = addLogTokenCounts(written, logJSONTokenCount(fields, name))
				}
			}
		} else {
			written = logJSONTokenCount(fields, "cache_creation_tokens")
		}
	}
	result.InputTokens = addLogTokenCounts(addLogTokenCounts(result.InputTokens, result.CacheReadTokens), written)
	return result
}

const (
	logOtherAdminInfoKey    = "admin_info"
	logOtherRootInfoKey     = "root_info"
	logOtherAuditInfoKey    = "audit_info"
	logOtherContentPartsKey = "content_parts"
)

// legacySensitiveLogOtherKeys are historical top-level fields that must never
// be written via SetPublic and must be stripped from user-visible projections.
var legacySensitiveLogOtherKeys = []string{
	"channel_id",
	"channel_name",
	"channel_type",
	"reject_reason",
}

type logOtherVisibility int

const (
	logOtherVisibilityUser logOtherVisibility = iota
	logOtherVisibilityAdmin
	logOtherVisibilityRoot
	logOtherVisibilityBillingFacts
)

// LogOther separates usage-log metadata by the audience allowed to see it.
// Its maps stay private so callers cannot accidentally place privileged fields
// in the user-visible top level.
type LogOther struct {
	public    map[string]any
	adminInfo map[string]any
	rootInfo  map[string]any
	auditInfo map[string]any
}

func NewLogOther() *LogOther {
	return &LogOther{}
}

func isReservedLogOtherKey(key string) bool {
	switch key {
	case logOtherAdminInfoKey, logOtherRootInfoKey, logOtherAuditInfoKey:
		return true
	default:
		return slices.Contains(legacySensitiveLogOtherKeys, key)
	}
}

// SetPublic records metadata that log owners may receive from self/token log APIs.
// It rejects role-scoped and legacy-sensitive keys so new writers cannot recreate
// the historical channel/reject-reason leak.
func (o *LogOther) SetPublic(key string, value any) bool {
	if o == nil || key == "" || isReservedLogOtherKey(key) {
		return false
	}
	if o.public == nil {
		o.public = make(map[string]any)
	}
	o.public[key] = value
	return true
}

func (o *LogOther) MergePublic(values map[string]any) {
	for key, value := range values {
		o.SetPublic(key, value)
	}
}

// setContent stores structured content under content_parts, which the web
// console renders in the viewer's language, and returns the English text kept
// in the content column for exports and API callers.
func (o *LogOther) setContent(parts []*common.Message) string {
	if len(parts) == 0 {
		return ""
	}
	o.SetPublic(logOtherContentPartsKey, parts)
	texts := make([]string, 0, len(parts))
	for _, part := range parts {
		texts = append(texts, part.Error())
	}
	return strings.Join(texts, ", ")
}

func (o *LogOther) SetAdmin(key string, value any) bool {
	if o == nil || key == "" {
		return false
	}
	if o.adminInfo == nil {
		o.adminInfo = make(map[string]any)
	}
	o.adminInfo[key] = value
	return true
}

func (o *LogOther) MergeAdmin(values map[string]any) {
	for key, value := range values {
		o.SetAdmin(key, value)
	}
}

func (o *LogOther) SetRoot(key string, value any) bool {
	if o == nil || key == "" {
		return false
	}
	if o.rootInfo == nil {
		o.rootInfo = make(map[string]any)
	}
	o.rootInfo[key] = value
	return true
}

func (o *LogOther) MergeRoot(values map[string]any) {
	for key, value := range values {
		o.SetRoot(key, value)
	}
}

func (o *LogOther) SetAudit(key string, value any) bool {
	if o == nil || key == "" {
		return false
	}
	if o.auditInfo == nil {
		o.auditInfo = make(map[string]any)
	}
	o.auditInfo[key] = value
	return true
}

func (o *LogOther) MergeAudit(values map[string]any) {
	for key, value := range values {
		o.SetAudit(key, value)
	}
}

func copyLogOtherMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	copyValues := make(map[string]any, len(values))
	maps.Copy(copyValues, values)
	return copyValues
}

func (o *LogOther) toMap() map[string]any {
	result := make(map[string]any)
	if o == nil {
		return result
	}

	maps.Copy(result, o.public)
	if adminInfo := copyLogOtherMap(o.adminInfo); len(adminInfo) > 0 {
		result[logOtherAdminInfoKey] = adminInfo
	}
	if auditInfo := copyLogOtherMap(o.auditInfo); len(auditInfo) > 0 {
		result[logOtherAuditInfoKey] = auditInfo
	}
	if rootInfo := copyLogOtherMap(o.rootInfo); len(rootInfo) > 0 {
		result[logOtherRootInfoKey] = rootInfo
	}
	return result
}

func (o *LogOther) jsonString() string {
	if o == nil {
		return ""
	}
	data, err := common.Marshal(o.toMap())
	if err != nil {
		common.SysError(common.LogText("failed to marshal log other: %s", err.Error()))
		return ""
	}
	return string(data)
}

// JSONString returns the complete stored representation, including all
// privileged scopes. API projections must use the role-specific formatter.
func (o *LogOther) JSONString() string {
	return o.jsonString()
}

// Snapshot returns a detached top-level view for tests and read-only
// inspection. Mutating it cannot add or replace fields in LogOther.
func (o *LogOther) Snapshot() map[string]any {
	if o == nil {
		return nil
	}
	return o.toMap()
}

func (o *LogOther) MarshalJSON() ([]byte, error) {
	return common.Marshal(o.toMap())
}

func normalizeLegacyRejectReason(values map[string]json.RawMessage) bool {
	rejectReason, ok := values["reject_reason"]
	if !ok {
		return false
	}

	adminInfo := make(map[string]json.RawMessage)
	if rawAdminInfo, exists := values[logOtherAdminInfoKey]; exists {
		_ = common.Unmarshal(rawAdminInfo, &adminInfo)
	}
	if adminInfo == nil {
		adminInfo = make(map[string]json.RawMessage)
	}
	if _, exists := adminInfo["reject_reason"]; !exists {
		adminInfo["reject_reason"] = rejectReason
	}
	encodedAdminInfo, err := common.Marshal(adminInfo)
	if err != nil {
		return false
	}
	values[logOtherAdminInfoKey] = encodedAdminInfo
	delete(values, "reject_reason")
	return true
}

// formatLogOtherJSON applies the role projection while keeping untouched JSON
// values as RawMessage. This preserves integers larger than JavaScript's safe
// range instead of round-tripping them through float64.
func formatLogOtherJSON(value string, visibility logOtherVisibility) string {
	if value == "" {
		return ""
	}

	var values map[string]json.RawMessage
	if err := common.UnmarshalJsonStr(value, &values); err != nil {
		if visibility == logOtherVisibilityRoot {
			return value
		}
		return "{}"
	}

	changed := false
	if visibility == logOtherVisibilityBillingFacts {
		facts := map[string]json.RawMessage{}
		for _, key := range []string{"input_tokens_total", "cache_tokens", "cache_write_tokens",
			"cache_creation_tokens", "cache_creation_tokens_5m", "cache_creation_tokens_1h",
			"model_price", "model_ratio", "group_ratio", "completion_ratio", "cache_ratio", "user_group_ratio", "fixed_price", "image_count"} {
			var number *float64
			if raw, exists := values[key]; exists && common.Unmarshal(raw, &number) == nil && number != nil {
				facts[key] = raw
			}
		}
		for key, allowed := range map[string][]string{"billing_unit": {"token", "request"}, "billing_mode": {"tiered_expr"}} {
			var label string
			if raw, exists := values[key]; exists && common.Unmarshal(raw, &label) == nil && slices.Contains(allowed, label) {
				facts[key] = raw
			}
		}
		values, changed = facts, true
	} else if visibility == logOtherVisibilityUser {
		for _, key := range []string{logOtherAdminInfoKey, logOtherRootInfoKey, logOtherAuditInfoKey} {
			if _, exists := values[key]; exists {
				delete(values, key)
				changed = true
			}
		}
		for _, key := range legacySensitiveLogOtherKeys {
			if _, exists := values[key]; exists {
				delete(values, key)
				changed = true
			}
		}
	} else {
		changed = normalizeLegacyRejectReason(values)
		if visibility == logOtherVisibilityAdmin {
			if _, exists := values[logOtherRootInfoKey]; exists {
				delete(values, logOtherRootInfoKey)
				changed = true
			}
		}
	}

	if !changed {
		return value
	}
	formatted, err := common.Marshal(values)
	if err != nil {
		if visibility == logOtherVisibilityRoot {
			return value
		}
		return "{}"
	}
	return string(formatted)
}
