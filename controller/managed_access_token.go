package controller

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func requireManagedProvisioner(c *gin.Context) bool {
	key, err := os.ReadFile(os.Getenv("MANAGED_ACCOUNT_PROVISION_KEY_FILE"))
	expected := strings.TrimSpace(string(key))
	if err != nil || len(expected) < 32 || c.GetInt("role") != common.RoleRootUser ||
		subtle.ConstantTimeCompare([]byte(c.GetHeader("X-Managed-Provisioning-Key")), []byte(expected)) != 1 {
		c.AbortWithStatus(http.StatusForbidden)
		return false
	}
	return true
}

// EnsureManagedAccount commits identity and a zero-funded new account together.
// The external claim makes a lost create response safe to retry. An existing
// account is adopted only by an explicit native ID or its verified OIDC subject.
func EnsureManagedAccount(c *gin.Context) {
	if !requireManagedProvisioner(c) {
		return
	}
	var req struct {
		AccountRef   string `json:"account_ref"`
		Username     string `json:"username"`
		ExpectedName string `json:"expected_name"`
		UserID       int    `json:"user_id"`
		OIDCSubject  string `json:"oidc_subject"`
		OIDCIssuer   string `json:"oidc_issuer"`
	}
	if common.DecodeJson(c.Request.Body, &req) != nil || (len(req.AccountRef) < 36 || len(req.AccountRef) > 64) || req.UserID < 0 ||
		len(req.OIDCSubject) > 128 || req.Username == "" || strings.TrimSpace(req.Username) != req.Username ||
		common.Validate.StructExcept(&model.User{Username: req.Username}, "Password") != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if req.OIDCSubject != "" {
		if req.OIDCIssuer == "" || system_setting.GetOIDCSettings().WellKnown != req.OIDCIssuer+"/.well-known/openid-configuration" {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		req.OIDCSubject = model.OIDCIdentityKey(req.OIDCIssuer, req.OIDCSubject)
	} else if req.OIDCIssuer != "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	var user model.User
	err := model.DB.Transaction(func(tx *gorm.DB) error {
		var claim model.ExternalIdentityClaim
		err := tx.Where("provider = ? AND subject = ?", "managed-account", req.AccountRef).First(&claim).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		id := req.UserID
		if err == nil {
			if id != 0 && id != claim.UserId {
				return errors.New("managed account owner differs")
			}
			id = claim.UserId
		}
		if id != 0 {
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&user, id).Error; err != nil {
				return err
			}
			if user.Username != req.Username && user.Username != req.ExpectedName {
				return errors.New("managed account name changed")
			}
		} else if req.OIDCSubject != "" {
			err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("oidc_id = ?", req.OIDCSubject).First(&user).Error
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
		}
		if user.Id == 0 {
			user = model.User{Username: req.Username, DisplayName: req.Username, Role: common.RoleCommonUser,
				Status: common.UserStatusEnabled, OidcId: req.OIDCSubject}
			if err := user.InsertWithTx(tx, 0); err != nil {
				return err
			}
			if err := tx.Model(&user).Update("quota", 0).Error; err != nil {
				return err
			}
			user.Quota = 0
		}
		if user.Role != common.RoleCommonUser || user.Status != common.UserStatusEnabled ||
			(user.OidcId != "" && user.OidcId != req.OIDCSubject) {
			return errors.New("managed account identity differs")
		}
		if err := model.ClaimExternalIdentityWithTx(tx, "managed-account", req.AccountRef, user.Id); err != nil {
			return err
		}
		if req.OIDCSubject != "" {
			if err := model.ClaimExternalIdentityWithTx(tx, "oidc", req.OIDCSubject, user.Id); err != nil {
				return err
			}
		}
		updates := map[string]any{"username": req.Username, "oidc_id": req.OIDCSubject}
		if user.DisplayName == user.Username && user.Username != req.Username && req.ExpectedName == user.Username {
			updates["display_name"] = req.Username
		}
		if err := tx.Model(&user).Updates(updates).Error; err != nil {
			return err
		}
		user.Username, user.OidcId = req.Username, req.OIDCSubject
		return nil
	})
	if err == nil {
		err = model.PublishUserAuthCache(user.Id)
	}
	if err != nil {
		common.ApiError(c, err)
		return
	}
	recordManageAuditFor(c, user.Id, "user.update", map[string]any{"managed_account_ref": req.AccountRef})
	common.ApiSuccess(c, gin.H{"id": user.Id, "username": user.Username, "oidc_id": user.OidcId,
		"role": user.Role, "status": user.Status, "quota": user.Quota})
}

// EnsureManagedRedemption preserves the original grant across lost responses.
func EnsureManagedRedemption(c *gin.Context) {
	if !requireManagedProvisioner(c) {
		return
	}
	if !operation_setting.IsPaymentComplianceConfirmed() {
		common.ApiError(c, errors.New("native funding is not enabled"))
		return
	}
	var req struct {
		GrantRef string `json:"grant_ref"`
		UserID   int    `json:"user_id"`
		Name     string `json:"name"`
		Quota    int    `json:"quota"`
	}
	if common.DecodeJson(c.Request.Body, &req) != nil || len(req.GrantRef) != 36 || req.UserID <= 0 ||
		req.Quota <= 0 || common.ValidateWalletQuota(req.Quota) != nil || len(req.Name) == 0 || len(req.Name) > 20 {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	value := model.Redemption{UserId: c.GetInt("id"), Name: req.Name, Quota: req.Quota,
		Key: common.GetUUID(), Status: common.RedemptionCodeStatusEnabled, CreatedTime: common.GetTimestamp(),
		ManagedGrantRef: &req.GrantRef, ManagedOwnerID: req.UserID}
	err := model.DB.Transaction(func(tx *gorm.DB) error {
		var owner model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&owner, req.UserID).Error; err != nil {
			return err
		}
		if owner.Role != common.RoleCommonUser || owner.Status != common.UserStatusEnabled {
			return errors.New("managed account is inactive")
		}
		var claim model.ExternalIdentityClaim
		if err := tx.Where("provider = ? AND user_id = ?", "managed-account", req.UserID).First(&claim).Error; err != nil {
			return err
		}
		var current model.Redemption
		err := tx.Unscoped().Where("managed_grant_ref = ?", req.GrantRef).First(&current).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&value).Error; err != nil {
				return err
			}
			err = tx.Unscoped().Where("managed_grant_ref = ?", req.GrantRef).First(&current).Error
		}
		if err != nil {
			return err
		}
		if current.DeletedAt.Valid || current.ManagedOwnerID != req.UserID || current.UserId != c.GetInt("id") ||
			current.Name != req.Name || current.Quota != req.Quota {
			return errors.New("managed grant differs")
		}
		value = current
		return nil
	})
	if err != nil {
		common.ApiError(c, err)
		return
	}
	recordManageAudit(c, "redemption.create", map[string]any{"grant_ref": req.GrantRef, "redemption_id": value.Id, "user_id": req.UserID})
	common.ApiSuccess(c, value)
}

// CreateManagedAccessToken lets the trusted provisioning operator delegate
// model-key management without changing a person's password or browser session.
func CreateManagedAccessToken(c *gin.Context) {
	if !requireManagedProvisioner(c) {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	var req struct {
		AccountRef  string   `json:"account_ref"`
		Name        string   `json:"name"`
		Scopes      []string `json:"scopes"`
		PreviousRef string   `json:"previous_token_ref"`
	}
	if err != nil || id <= 0 {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if common.DecodeJson(c.Request.Body, &req) != nil || len(req.AccountRef) < 36 || len(req.AccountRef) > 64 ||
		!strings.HasPrefix(req.Name, "portal-model-") || len(req.Name) > 64 {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	scopes, err := service.NormalizeAccessTokenScopes(id, common.RoleCommonUser, req.Scopes)
	if err != nil || len(scopes) == 0 || slices.ContainsFunc(scopes, func(scope string) bool {
		return !slices.Contains([]string{"api_key:read", "api_key:write", "api_key:reveal", "wallet:write"}, scope)
	}) {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	encoded, _ := common.Marshal([]string{"managed-pat/v1", req.AccountRef, req.Name})
	slot := fmt.Sprintf("%x", sha256.Sum256(encoded))
	mac := hmac.New(sha256.New, []byte(c.GetHeader("X-Managed-Provisioning-Key")))
	_, _ = mac.Write(encoded)
	raw := model.AccessTokenPrefix + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	token := model.UserAccessToken{Name: req.Name, UserId: id, TokenHash: model.AccessTokenFingerprint(raw),
		TokenHint: model.AccessTokenHint(raw), CreatedAt: common.GetTimestamp(), Managed: true, ManagedSlot: &slot}
	if err := token.SetScopes(scopes); err != nil {
		common.ApiError(c, err)
		return
	}
	err = model.DB.Transaction(func(tx *gorm.DB) error {
		var user model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&user, id).Error; err != nil {
			return err
		}
		if user.Role != common.RoleCommonUser || user.Status != common.UserStatusEnabled {
			return errors.New("managed account identity differs")
		}
		var claim model.ExternalIdentityClaim
		if err := tx.Where("provider = ? AND subject = ? AND user_id = ?", "managed-account", req.AccountRef, id).First(&claim).Error; err != nil {
			return err
		}
		// Identical attempts return the same secret, including a response lost
		// after commit. Rotation requires the current fingerprint, so a delayed
		// old worker cannot revoke credentials saved by a newer attempt.
		var previous model.UserAccessToken
		err := tx.Where("managed_slot = ?", slot).First(&previous).Error
		if err == nil {
			if previous.UserId != id || !previous.Managed || previous.Name != req.Name || previous.Scopes != token.Scopes {
				return errors.New("managed credential slot differs")
			}
			if previous.TokenHash != token.TokenHash {
				if req.PreviousRef != previous.TokenHash {
					return errors.New("managed credential changed")
				}
				if err := tx.Model(&previous).Updates(map[string]any{"token_hash": token.TokenHash, "token_hint": token.TokenHint}).Error; err != nil {
					return err
				}
			}
			token.Id = previous.Id
		} else {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			if err := tx.Create(&token).Error; err != nil {
				return err
			}
		}
		if req.PreviousRef != "" && req.PreviousRef != token.TokenHash {
			var legacy model.UserAccessToken
			err := tx.Where("token_hash = ?", req.PreviousRef).First(&legacy).Error
			if err == nil {
				if legacy.UserId != id || legacy.Managed || legacy.Scopes != token.Scopes ||
					legacy.Name != strings.Replace(req.Name, "portal-model-", "pilot-", 1) {
					return errors.New("legacy service credential differs")
				}
				if err := tx.Delete(&legacy).Error; err != nil {
					return err
				}
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
		}
		return nil
	})
	if err != nil {
		common.ApiError(c, err)
		return
	}
	recordManageAuditFor(c, id, "access_token.generate", map[string]any{"token_id": token.Id, "name": token.Name, "scopes": scopes})
	common.ApiSuccess(c, gin.H{"token": raw, "item": newAccessTokenItem(&token)})
}
