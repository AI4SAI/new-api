package model

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	ExternalIdentityProviderTelegram = "telegram"
	ExternalIdentityProviderOIDC     = "oidc"
)

// OIDCIdentityKey is the collation-safe index key. ExternalIdentityClaim
// preserves the exact signed issuer and subject alongside it.
func OIDCIdentityKey(issuer, subject string) string {
	encoded, _ := common.Marshal([]string{"oidc/v1", issuer, subject})
	return fmt.Sprintf("v1:%x", sha256.Sum256(encoded))
}

var ErrExternalIdentityAlreadyClaimed = errors.New("external identity is already claimed")

// ExternalIdentityClaim is the durable ownership record for an identity issued
// by an external provider. The two unique indexes make both the provider
// subject and the user's provider slot single-owner without relying on a
// check-then-update sequence.
type ExternalIdentityClaim struct {
	Id          int64     `json:"id" gorm:"primaryKey"`
	Provider    string    `json:"provider" gorm:"type:varchar(32);not null;uniqueIndex:idx_external_identity_subject,priority:1;uniqueIndex:idx_external_identity_user,priority:1"`
	Subject     string    `json:"subject" gorm:"type:varchar(128);not null;uniqueIndex:idx_external_identity_subject,priority:2"`
	UserId      int       `json:"user_id" gorm:"not null;index;uniqueIndex:idx_external_identity_user,priority:2"`
	CreatedAt   time.Time `json:"created_at"`
	OIDCIssuer  *string   `json:"-" gorm:"column:oidc_issuer;type:text"`
	OIDCSubject *string   `json:"-" gorm:"column:oidc_subject;type:text"`
}

func (ExternalIdentityClaim) TableName() string {
	return "external_identity_claims"
}

// ClaimExternalIdentityWithTx atomically claims a provider subject for one
// user. Repeating the exact mapping is idempotent; every competing subject or
// user is rejected. Ownership is read back instead of trusting RowsAffected,
// whose duplicate-key semantics differ between supported databases.
func ClaimExternalIdentityWithTx(tx *gorm.DB, provider, subject string, userId int) error {
	provider = strings.TrimSpace(provider)
	subject = strings.TrimSpace(subject)
	if provider == ExternalIdentityProviderOIDC {
		return errors.New("OIDC claim requires its verified issuer and subject")
	}
	return claimExternalIdentityWithTx(tx, ExternalIdentityClaim{Provider: provider, Subject: subject, UserId: userId})
}

func claimExternalIdentityWithTx(tx *gorm.DB, claim ExternalIdentityClaim) error {
	if tx == nil || claim.Provider == "" || claim.Subject == "" || claim.UserId <= 0 {
		return errors.New("external identity claim is invalid")
	}
	if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&claim).Error; err != nil {
		return err
	}
	var owner ExternalIdentityClaim
	if err := lockForUpdate(tx).Where("provider = ? AND subject = ?", claim.Provider, claim.Subject).First(&owner).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrExternalIdentityAlreadyClaimed
		}
		return err
	}
	if owner.UserId != claim.UserId || owner.Subject != claim.Subject {
		return ErrExternalIdentityAlreadyClaimed
	}
	if claim.Provider == ExternalIdentityProviderOIDC &&
		(owner.OIDCIssuer == nil || owner.OIDCSubject == nil || claim.OIDCIssuer == nil || claim.OIDCSubject == nil ||
			*owner.OIDCIssuer != *claim.OIDCIssuer || *owner.OIDCSubject != *claim.OIDCSubject) {
		return ErrExternalIdentityAlreadyClaimed
	}
	// The provider/user unique index also rejects a second identity for this slot.
	return nil
}

// BindOIDCIdentityWithTx owns the exact verified identity and its native user
// projection in the same transaction. The caller owns login/registration proof.
func BindOIDCIdentityWithTx(tx *gorm.DB, userId int, issuer, subject string) error {
	if tx == nil || userId <= 0 || issuer == "" || subject == "" {
		return ErrAccountBindingChanged
	}
	var user User
	if err := lockForUpdate(tx).Select("id", "oidc_id").First(&user, userId).Error; err != nil {
		return err
	}
	key := OIDCIdentityKey(issuer, subject)
	if user.OidcId != "" && user.OidcId != key {
		return ErrExternalIdentityAlreadyClaimed
	}
	if err := claimExternalIdentityWithTx(tx, ExternalIdentityClaim{Provider: ExternalIdentityProviderOIDC, Subject: key, UserId: userId, OIDCIssuer: &issuer, OIDCSubject: &subject}); err != nil {
		return err
	}
	if user.OidcId == key {
		return nil
	}
	return tx.Model(&User{}).Where("id = ?", userId).Update("oidc_id", key).Error
}

// GetUserByOIDCIdentity requires the exact signed pair and native projection.
// Legacy digest-only bindings are not imported or repaired on a login path.
func GetUserByOIDCIdentity(issuer, subject string) (*User, error) {
	if issuer == "" || subject == "" {
		return nil, ErrAccountBindingChanged
	}
	key := OIDCIdentityKey(issuer, subject)
	var claim ExternalIdentityClaim
	err := DB.Where("provider = ? AND subject = ?", ExternalIdentityProviderOIDC, key).First(&claim).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		var count int64
		if err := DB.Unscoped().Model(&User{}).Where("oidc_id = ?", key).Count(&count).Error; err != nil {
			return nil, err
		}
		if count != 0 {
			return nil, ErrAccountBindingChanged
		}
		return nil, gorm.ErrRecordNotFound
	}
	if err != nil {
		return nil, err
	}
	if claim.Subject != key || claim.OIDCIssuer == nil || claim.OIDCSubject == nil || *claim.OIDCIssuer != issuer || *claim.OIDCSubject != subject {
		return nil, ErrAccountBindingChanged
	}
	var user User
	if err := DB.Unscoped().First(&user, claim.UserId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAccountBindingChanged
		}
		return nil, err
	}
	if user.DeletedAt.Valid || user.OidcId != key {
		return nil, ErrAccountBindingChanged
	}
	return &user, nil
}

func ReleaseExternalIdentityWithTx(tx *gorm.DB, provider string, userId int) error {
	provider = strings.TrimSpace(provider)
	if tx == nil || provider == "" || userId == 0 {
		return errors.New("external identity release is invalid")
	}
	return tx.Where("provider = ? AND user_id = ?", provider, userId).
		Delete(&ExternalIdentityClaim{}).Error
}

func GetUserByTelegramID(telegramID string) (*User, error) {
	var user User
	err := DB.Where("telegram_id = ?", telegramID).First(&user).Error
	return &user, err
}

// BindTelegramForSessionWithTx preserves single ownership and the session that
// started the binding. The caller consumes its OAuth flow in this transaction.
func BindTelegramForSessionWithTx(tx *gorm.DB, identity AuthSessionIdentity, telegramID string) error {
	if err := ValidateAuthSessionWithTx(tx, identity); err != nil {
		return err
	}
	var user User
	if err := tx.Select("id", "telegram_id").First(&user, identity.UserID).Error; err != nil {
		return err
	}
	if user.TelegramId != "" {
		return ErrExternalIdentityAlreadyClaimed
	}
	if err := ClaimExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, telegramID, user.Id); err != nil {
		return err
	}
	result := tx.Model(&User{}).Where("id = ? AND (telegram_id = ? OR telegram_id IS NULL)", user.Id, "").Update("telegram_id", telegramID)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrExternalIdentityAlreadyClaimed
	}
	return nil
}

func releaseAllExternalIdentitiesWithTx(tx *gorm.DB, userId int) error {
	if tx == nil || userId == 0 {
		return errors.New("external identity release is invalid")
	}
	return tx.Where("user_id = ?", userId).Delete(&ExternalIdentityClaim{}).Error
}

// InitializeExternalIdentityClaims imports legacy Telegram bindings after the
// claim table is migrated. Existing duplicate ownership fails migration rather
// than preserving an ambiguous login identity.
func InitializeExternalIdentityClaims() error {
	var users []User
	if err := DB.Unscoped().Select("id", "telegram_id").
		Where("telegram_id <> ?", "").Find(&users).Error; err != nil {
		return err
	}
	return DB.Transaction(func(tx *gorm.DB) error {
		for _, user := range users {
			if err := ClaimExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, user.TelegramId, user.Id); err != nil {
				return fmt.Errorf("backfill Telegram identity for user %d: %w", user.Id, err)
			}
		}
		return nil
	})
}
