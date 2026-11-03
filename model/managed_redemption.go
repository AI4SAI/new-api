package model

import (
	"errors"

	"github.com/QuantumNous/new-api/common"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrManagedReclaimConflict = errors.New("managed reclaim differs from original grant or execution state")
var ErrManagedReclaimInvalid = errors.New("invalid managed reclaim")

type ManagedReclaimRequest struct {
	GrantRef                  string `json:"grant_ref"`
	UserID                    int    `json:"user_id"`
	Quota                     *int   `json:"quota"`
	ExpectedExecutionRevision *int64 `json:"expected_execution_revision"`
}

type ManagedReclaimReceipt struct {
	Exists         bool   `json:"exists"`
	Completed      bool   `json:"completed"`
	GrantRef       string `json:"grant_ref"`
	RedemptionID   int    `json:"redemption_id,omitempty"`
	UserID         int    `json:"user_id"`
	Status         int    `json:"status,omitempty"`
	Quota          int    `json:"quota,omitempty"`
	Outcome        string `json:"outcome,omitempty"`
	ReclaimedQuota int    `json:"reclaimed_quota"`
	ReclaimedAt    int64  `json:"reclaimed_at"`
}

func (grant *Redemption) reclaimReceipt() *ManagedReclaimReceipt {
	receipt := &ManagedReclaimReceipt{Exists: true, Completed: grant.ReclaimedAt > 0,
		GrantRef: *grant.ManagedGrantRef, RedemptionID: grant.Id, UserID: grant.ManagedOwnerID,
		Status: grant.Status, Quota: grant.Quota, ReclaimedQuota: grant.ReclaimedQuota,
		ReclaimedAt: grant.ReclaimedAt}
	if receipt.Completed {
		receipt.Outcome = "reclaimed"
		if grant.Status == common.RedemptionCodeStatusDisabled {
			receipt.Outcome = "cancelled"
		}
	}
	return receipt
}

func ValidManagedGrantRef(ref string) bool {
	value, err := uuid.Parse(ref)
	return err == nil && value.String() == ref
}

func reclaimOwner(tx *gorm.DB, userID int) (*User, error) {
	var user User
	if err := lockForUpdate(tx).First(&user, userID).Error; err != nil {
		return nil, err
	}
	if user.Role != common.RoleCommonUser {
		return nil, ErrManagedReclaimConflict
	}
	var claim ExternalIdentityClaim
	if err := tx.Where("provider = ? AND user_id = ?", "managed-account", userID).First(&claim).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func ReadManagedRedemptionReclaim(grantRef string, userID int) (*ManagedReclaimReceipt, error) {
	if !ValidManagedGrantRef(grantRef) || userID <= 0 {
		return nil, ErrManagedReclaimInvalid
	}
	var grant Redemption
	err := DB.Unscoped().Where("managed_grant_ref = ?", grantRef).First(&grant).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return &ManagedReclaimReceipt{GrantRef: grantRef, UserID: userID}, nil
	}
	if err != nil {
		return nil, err
	}
	if grant.DeletedAt.Valid || grant.ManagedOwnerID != userID {
		return nil, ErrManagedReclaimConflict
	}
	if grant.ReclaimedAt > 0 {
		user, err := GetUserById(userID, false)
		if err != nil {
			return nil, err
		}
		if err := populateUserCache(*user); err != nil {
			return nil, err
		}
	}
	return grant.reclaimReceipt(), nil
}

// ReclaimManagedRedemption records one fixed removal on its original grant.
// A cancelled unredeemed code removes no user quota. Real request settlement
// remains an independent delta and may legitimately make the balance negative.
func ReclaimManagedRedemption(request ManagedReclaimRequest) (*ManagedReclaimReceipt, error) {
	if !ValidManagedGrantRef(request.GrantRef) || request.UserID <= 0 || request.Quota == nil || *request.Quota < 0 ||
		*request.Quota > common.MaxWalletQuota || request.ExpectedExecutionRevision == nil || *request.ExpectedExecutionRevision < 0 {
		return nil, ErrManagedReclaimInvalid
	}
	var attempted int64
	err := DB.Transaction(func(tx *gorm.DB) error {
		var grant Redemption
		// An absent reference still needs a durable cancellation receipt. Check
		// without a gap lock; an off owner fence rejects any old late creator.
		initialErr := tx.Unscoped().Where("managed_grant_ref = ?", request.GrantRef).First(&grant).Error
		if errors.Is(initialErr, gorm.ErrRecordNotFound) {
			if *request.Quota == 0 {
				return ErrManagedReclaimInvalid
			}
			owner, err := reclaimOwner(tx, request.UserID)
			if err != nil {
				return err
			}
			if owner.ModelExecutionRevision != *request.ExpectedExecutionRevision || owner.ModelExecutionUntil != 0 {
				return ErrManagedReclaimConflict
			}
			cancelled := Redemption{UserId: 0, Key: common.GetUUID(), Name: "managed-cancelled", Quota: *request.Quota,
				Status: common.RedemptionCodeStatusDisabled, CreatedTime: common.GetTimestamp(), ManagedGrantRef: &request.GrantRef,
				ManagedOwnerID: request.UserID, ManagedExecutionRevision: request.ExpectedExecutionRevision,
				ReclaimedQuota: *request.Quota, ReclaimedAt: common.GetTimestamp()}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&cancelled).Error; err != nil {
				return err
			}
		} else if initialErr != nil {
			return initialErr
		}
		// Redemption and Redeem share the grant -> owner lock order.
		if err := lockForUpdate(tx.Unscoped()).Where("managed_grant_ref = ?", request.GrantRef).First(&grant).Error; err != nil {
			return err
		}
		if grant.DeletedAt.Valid || grant.ManagedOwnerID != request.UserID || *request.Quota > grant.Quota {
			return ErrManagedReclaimConflict
		}
		if grant.ReclaimedAt > 0 {
			if grant.ReclaimedQuota != *request.Quota {
				return ErrManagedReclaimConflict
			}
			return nil
		}
		owner, err := reclaimOwner(tx, request.UserID)
		if err != nil {
			return err
		}
		if owner.ModelExecutionRevision != *request.ExpectedExecutionRevision || owner.ModelExecutionUntil != 0 {
			return ErrManagedReclaimConflict
		}
		delta := *request.Quota
		switch grant.Status {
		case common.RedemptionCodeStatusEnabled:
			if grant.UsedUserId != 0 || delta != grant.Quota {
				return ErrManagedReclaimConflict
			}
			delta = 0
			grant.Status = common.RedemptionCodeStatusDisabled
		case common.RedemptionCodeStatusUsed:
			if grant.UsedUserId != request.UserID {
				return ErrManagedReclaimConflict
			}
		default:
			return ErrManagedReclaimConflict
		}
		if owner.Quota < -common.MaxWalletQuota+delta || owner.Quota > common.MaxWalletQuota ||
			owner.QuotaReclaimedTotal < 0 || owner.QuotaReclaimedTotal > int64(common.MaxWalletQuota-delta) {
			return ErrWalletQuotaLimitExceeded
		}
		if delta > 0 {
			attempted = owner.QuotaReclaimedTotal + int64(delta)
			if err := setUserQuotaReclaimFence(owner.Id, attempted); err != nil {
				return err
			}
			if err := tx.Model(&User{}).Where("id = ?", owner.Id).Updates(map[string]any{
				"quota": gorm.Expr("quota - ?", delta), "quota_reclaimed_total": attempted}).Error; err != nil {
				return err
			}
		}
		return tx.Model(&grant).Updates(map[string]any{"status": grant.Status, "reclaimed_quota": *request.Quota,
			"reclaimed_at": common.GetTimestamp()}).Error
	})
	if err != nil && attempted > 0 {
		// A failed COMMIT acknowledgement is not evidence of rollback. The
		// original receipt plus a fresh locked owner read resolves the outcome.
		readErr := DB.Transaction(func(tx *gorm.DB) error {
			var grant Redemption
			if e := lockForUpdate(tx).Where("managed_grant_ref = ?", request.GrantRef).First(&grant).Error; e != nil {
				return e
			}
			owner, e := reclaimOwner(tx, request.UserID)
			if e != nil {
				return e
			}
			if grant.ReclaimedAt > 0 && grant.ReclaimedQuota == *request.Quota {
				err = nil
				return nil
			}
			return resolveUserQuotaReclaimFence(owner.Id, attempted, owner.QuotaReclaimedTotal)
		})
		if readErr != nil {
			return nil, errors.Join(ErrUserQuotaReclaimPending, err)
		}
	}
	if err != nil {
		return nil, err
	}
	return ReadManagedRedemptionReclaim(request.GrantRef, request.UserID)
}
