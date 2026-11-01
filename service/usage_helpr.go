package service

import (
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/tokenkit"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

//func GetPromptTokens(textRequest dto.GeneralOpenAIRequest, relayMode int) (int, error) {
//	switch relayMode {
//	case constant.RelayModeChatCompletions:
//		return CountTokenMessages(textRequest.Messages, textRequest.Model)
//	case constant.RelayModeCompletions:
//		return CountTokenInput(textRequest.Prompt, textRequest.Model), nil
//	case constant.RelayModeModerations:
//		return CountTokenInput(textRequest.Input, textRequest.Model), nil
//	}
//	return 0, errors.New("unknown relay mode")
//}

func ResponseText2Usage(c *gin.Context, responseText string, modeName string, promptTokens int) *dto.Usage {
	common.SetContextKey(c, constant.ContextKeyLocalCountTokens, true)
	usage := &dto.Usage{}
	usage.PromptTokens = promptTokens
	usage.CompletionTokens = tokenkit.Estimate(modeName, responseText)
	usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
	return usage
}

func ValidUsage(usage *dto.Usage) bool {
	return usage != nil && (usage.PromptTokens != 0 || usage.CompletionTokens != 0)
}

// ConfirmedOpenAIStreamUsage distinguishes complete upstream counters, including
// explicit zero, from omitted counters. Optional cache fields retain the
// provider's existing zero-default semantics; missing whole usage does not.
func ConfirmedOpenAIStreamUsage(data []byte, usage *dto.Usage, responses bool) bool {
	if usage == nil {
		return false
	}
	path := "usage"
	if responses {
		path = "response.usage"
	}
	raw := gjson.GetBytes(data, path)
	if !raw.IsObject() {
		return false
	}
	var counts struct {
		Prompt     *int `json:"prompt_tokens"`
		Completion *int `json:"completion_tokens"`
		Input      *int `json:"input_tokens"`
		Output     *int `json:"output_tokens"`
		Total      *int `json:"total_tokens"`
	}
	if common.Unmarshal([]byte(raw.Raw), &counts) != nil {
		return false
	}
	prompt, completion := counts.Prompt, counts.Completion
	details := usage.PromptTokensDetails
	if responses {
		prompt, completion = counts.Input, counts.Output
		if usage.InputTokensDetails != nil {
			details = *usage.InputTokensDetails
		}
	}
	if prompt == nil || completion == nil || *prompt < 0 || *completion < 0 ||
		*prompt > common.MaxQuota || *completion > common.MaxQuota ||
		(counts.Total != nil && (*counts.Total < 0 || *counts.Total != *prompt+*completion)) {
		return false
	}
	for _, count := range []int{details.CachedTokens, details.CachedCreationTokens, details.CacheWriteTokens,
		details.ImageTokens, details.AudioTokens, details.TextTokens, usage.PromptCacheHitTokens} {
		if count < 0 || count > *prompt {
			return false
		}
	}
	outputDetails := usage.CompletionTokenDetails
	if responses && usage.OutputTokensDetails != nil {
		outputDetails = *usage.OutputTokensDetails
	}
	for _, count := range []int{outputDetails.ImageTokens, outputDetails.AudioTokens, outputDetails.TextTokens, outputDetails.ReasoningTokens} {
		if count < 0 || count > *completion {
			return false
		}
	}
	if usage.BillingUsage != nil {
		canonical, ok := usageFromBillingUsage(usage)
		if !ok || usage.BillingUsage.Estimated {
			return false
		}
		input := canonical.PromptTokens
		if canonical.UsageSemantic == dto.BillingUsageSemanticAnthropic {
			input += canonical.PromptTokensDetails.CachedTokens + canonical.PromptTokensDetails.CacheCreationTokensTotal()
		}
		cache := details.CachedTokens
		if cache == 0 {
			cache = usage.PromptCacheHitTokens
		}
		cacheWrite := canonical.PromptTokensDetails.CacheCreationTokensTotal()
		if input != *prompt || canonical.CompletionTokens != *completion || canonical.PromptTokensDetails.CachedTokens != cache ||
			cacheWrite < 0 || cacheWrite > *prompt || cacheWrite != details.CacheCreationTokensTotal() {
			return false
		}
	}
	return true
}
