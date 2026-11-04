package model

import (
	"errors"
	"fmt"
	"github.com/QuantumNous/new-api/common"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm/logger"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestExternalIdentityClaimEnforcesSingleOwnerAtomically(t *testing.T) {
	truncateTables(t)

	first := User{Username: "telegram-owner-one", Password: "password", AffCode: "telegram-owner-one"}
	second := User{Username: "telegram-owner-two", Password: "password", AffCode: "telegram-owner-two"}
	require.NoError(t, DB.Create(&first).Error)
	require.NoError(t, DB.Create(&second).Error)

	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		return ClaimExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, "telegram-123", first.Id)
	}))
	err := DB.Transaction(func(tx *gorm.DB) error {
		return ClaimExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, "telegram-123", second.Id)
	})
	assert.ErrorIs(t, err, ErrExternalIdentityAlreadyClaimed)

	err = DB.Transaction(func(tx *gorm.DB) error {
		return ClaimExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, "telegram-456", first.Id)
	})
	assert.ErrorIs(t, err, ErrExternalIdentityAlreadyClaimed)

	var claims []ExternalIdentityClaim
	require.NoError(t, DB.Find(&claims).Error)
	require.Len(t, claims, 1)
	assert.Equal(t, first.Id, claims[0].UserId)
	assert.Equal(t, "telegram-123", claims[0].Subject)

	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		return ReleaseExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, first.Id)
	}))
	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		return ClaimExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, "telegram-123", second.Id)
	}))
}

func TestClearTelegramBindingReleasesIdentityClaim(t *testing.T) {
	truncateTables(t)

	user := User{Username: "telegram-unbind", Password: "password", TelegramId: "telegram-unbind-id"}
	require.NoError(t, DB.Create(&user).Error)
	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		return ClaimExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, user.TelegramId, user.Id)
	}))

	require.NoError(t, user.ClearBinding(ExternalIdentityProviderTelegram))
	assert.Empty(t, user.TelegramId)

	var count int64
	require.NoError(t, DB.Model(&ExternalIdentityClaim{}).Where("user_id = ?", user.Id).Count(&count).Error)
	assert.Zero(t, count)
}

func TestInitializeExternalIdentityClaimsIsIdempotent(t *testing.T) {
	truncateTables(t)

	user := User{Username: "telegram-legacy", Password: "password", TelegramId: "telegram-legacy-id"}
	require.NoError(t, DB.Create(&user).Error)
	require.NoError(t, InitializeExternalIdentityClaims())
	require.NoError(t, InitializeExternalIdentityClaims())

	var claim ExternalIdentityClaim
	require.NoError(t, DB.Where("provider = ? AND subject = ?", ExternalIdentityProviderTelegram, user.TelegramId).
		First(&claim).Error)
	assert.Equal(t, user.Id, claim.UserId)
}

func TestInitializeExternalIdentityClaimsRejectsAmbiguousLegacyBindings(t *testing.T) {
	truncateTables(t)

	first := User{Username: "telegram-legacy-one", Password: "password", TelegramId: "duplicate-telegram-id", AffCode: "telegram-legacy-one"}
	second := User{Username: "telegram-legacy-two", Password: "password", TelegramId: "duplicate-telegram-id", AffCode: "telegram-legacy-two"}
	require.NoError(t, DB.Create(&first).Error)
	require.NoError(t, DB.Create(&second).Error)

	err := InitializeExternalIdentityClaims()
	assert.ErrorIs(t, err, ErrExternalIdentityAlreadyClaimed)

	var count int64
	require.NoError(t, DB.Model(&ExternalIdentityClaim{}).Count(&count).Error)
	assert.Zero(t, count)
}

// The upgrade keeps existing provider ownership and both unique indexes; the
// two nullable facts never participate in database collation or identity lookup.
type externalIdentityClaimBeforeOIDC struct {
	Id        int64  `gorm:"primaryKey"`
	Provider  string `gorm:"type:varchar(32);not null;uniqueIndex:idx_external_identity_subject,priority:1;uniqueIndex:idx_external_identity_user,priority:1"`
	Subject   string `gorm:"type:varchar(128);not null;uniqueIndex:idx_external_identity_subject,priority:2"`
	UserId    int    `gorm:"not null;index;uniqueIndex:idx_external_identity_user,priority:2"`
	CreatedAt time.Time
}

func TestOIDCIdentityDatabaseMatrix(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			var driver gorm.Dialector
			switch dialect {
			case "sqlite":
				driver = sqlite.Open(t.TempDir() + "/oidc.db?_pragma=busy_timeout(30000)&_pragma=journal_mode(WAL)&_txlock=immediate")
			case "mysql":
				dsn := os.Getenv("TEST_MYSQL_DSN")
				if dsn == "" {
					t.Skip("TEST_MYSQL_DSN not configured")
				}
				driver = mysql.Open(dsn)
			case "postgres":
				dsn := os.Getenv("TEST_POSTGRES_DSN")
				if dsn == "" {
					t.Skip("TEST_POSTGRES_DSN not configured")
				}
				driver = postgres.Open(dsn)
			}
			db, err := gorm.Open(driver, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
			require.NoError(t, err)
			sqlDB, err := db.DB()
			require.NoError(t, err)
			sqlDB.SetMaxOpenConns(8)
			priorDB, priorType, priorRedis := DB, common.MainDatabaseType(), common.RedisEnabled
			DB = db
			common.SetMainDatabaseType(common.DatabaseType(dialect))
			common.RedisEnabled = false
			initCol()
			t.Cleanup(func() {
				DB = priorDB
				common.SetMainDatabaseType(priorType)
				common.RedisEnabled = priorRedis
				initCol()
				_ = sqlDB.Close()
			})
			versionSQL := "SELECT VERSION()"
			if dialect == "sqlite" {
				versionSQL = "SELECT sqlite_version()"
			}
			var version string
			require.NoError(t, db.Raw(versionSQL).Scan(&version).Error)
			t.Logf("database: %s %s", dialect, version)
			if dialect == "mysql" {
				var collation string
				require.NoError(t, db.Raw("SELECT @@collation_database").Scan(&collation).Error)
				require.True(t, strings.HasSuffix(collation, "_ci"))
				t.Logf("collation: %s", collation)
			}
			// Use only the dedicated test database supplied by TEST_*_DSN.
			tables := []any{&ExternalIdentityClaim{}, &User{}, &UserSession{}, &AuthFlow{}, &Token{}, &UserAccessToken{}, &UserOAuthBinding{}, &TwoFA{}, &TwoFABackupCode{}, &PasskeyCredential{}}
			require.NoError(t, db.Migrator().DropTable(tables...))
			t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(tables...)) })
			// Verify fresh and repeated migration before testing the existing schema.
			require.NoError(t, db.AutoMigrate(&ExternalIdentityClaim{}))
			require.NoError(t, db.AutoMigrate(&ExternalIdentityClaim{}))
			for _, name := range []string{"oidc_issuer", "oidc_subject"} {
				columns, columnErr := db.Migrator().ColumnTypes(&ExternalIdentityClaim{})
				require.NoError(t, columnErr)
				found := false
				for _, column := range columns {
					if column.Name() == name {
						nullable, ok := column.Nullable()
						require.True(t, ok)
						assert.True(t, nullable)
						found = true
					}
				}
				require.True(t, found)
			}
			require.NoError(t, db.Migrator().DropTable(&ExternalIdentityClaim{}))
			require.NoError(t, db.Table("external_identity_claims").AutoMigrate(&externalIdentityClaimBeforeOIDC{}))
			require.NoError(t, db.Table("external_identity_claims").Create(&externalIdentityClaimBeforeOIDC{Provider: "telegram", Subject: "retained", UserId: 999}).Error)
			require.NoError(t, db.AutoMigrate(tables...))
			require.NoError(t, db.AutoMigrate(tables...))
			var legacy ExternalIdentityClaim
			require.NoError(t, db.Where("provider = ?", "telegram").First(&legacy).Error)
			assert.Equal(t, "retained", legacy.Subject)
			assert.Nil(t, legacy.OIDCIssuer)
			assert.Nil(t, legacy.OIDCSubject)
			require.True(t, db.Migrator().HasIndex(&ExternalIdentityClaim{}, "idx_external_identity_subject"))
			require.True(t, db.Migrator().HasIndex(&ExternalIdentityClaim{}, "idx_external_identity_user"))
			users := make([]User, 6)
			for i := range users {
				users[i] = User{Username: fmt.Sprintf("oidc-owner-%d", i), AffCode: fmt.Sprintf("oidc-%d", i), Password: "local-password", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, AuthVersion: 1}
				require.NoError(t, db.Create(&users[i]).Error)
			}
			issuer, subject := "https://issuer.example.test/Realm", "CaseSubject"
			start := make(chan struct{})
			results := make(chan error, 2)
			var wg sync.WaitGroup
			for _, user := range users[:2] {
				wg.Go(func() {
					<-start
					results <- db.Transaction(func(tx *gorm.DB) error { return BindOIDCIdentityWithTx(tx, user.Id, issuer, subject) })
				})
			}
			close(start)
			wg.Wait()
			close(results)
			success, denied := 0, 0
			for result := range results {
				if result == nil {
					success++
				} else {
					require.ErrorIs(t, result, ErrExternalIdentityAlreadyClaimed)
					denied++
				}
			}
			require.Equal(t, 1, success)
			require.Equal(t, 1, denied)
			owner, err := GetUserByOIDCIdentity(issuer, subject)
			require.NoError(t, err)
			require.NoError(t, db.Transaction(func(tx *gorm.DB) error { return BindOIDCIdentityWithTx(tx, owner.Id, issuer, subject) }))
			require.ErrorIs(t, db.Transaction(func(tx *gorm.DB) error { return BindOIDCIdentityWithTx(tx, owner.Id, issuer, "another") }), ErrExternalIdentityAlreadyClaimed)
			var claim ExternalIdentityClaim
			require.NoError(t, db.Where("provider = ? AND user_id = ?", "oidc", owner.Id).First(&claim).Error)
			require.NotNil(t, claim.OIDCIssuer)
			require.NotNil(t, claim.OIDCSubject)
			assert.Equal(t, issuer, *claim.OIDCIssuer)
			assert.Equal(t, subject, *claim.OIDCSubject)
			// Case-sensitive facts must stay distinct even under a MySQL CI collation.
			require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
				return BindOIDCIdentityWithTx(tx, users[2].Id, issuer, strings.ToLower(subject))
			}))
			require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
				return BindOIDCIdentityWithTx(tx, users[3].Id, strings.ToLower(issuer), subject)
			}))
			for _, mapping := range []struct {
				issuer, subject string
				id              int
			}{{issuer, strings.ToLower(subject), users[2].Id}, {strings.ToLower(issuer), subject, users[3].Id}} {
				found, readErr := GetUserByOIDCIdentity(mapping.issuer, mapping.subject)
				require.NoError(t, readErr)
				assert.Equal(t, mapping.id, found.Id)
			}
			// The one canonical row and native projection must agree exactly on reads.
			for _, field := range []string{"oidc_issuer", "oidc_subject", "subject", "oidc_id"} {
				t.Run("reject inconsistent "+field, func(t *testing.T) {
					target := db.Model(&ExternalIdentityClaim{}).Where("id = ?", claim.Id)
					original := claim.Subject
					if field == "oidc_issuer" {
						original = issuer
					}
					if field == "oidc_subject" {
						original = subject
					}
					if field == "oidc_id" {
						target = db.Model(&User{}).Where("id = ?", owner.Id)
					}
					require.NoError(t, target.Update(field, "inconsistent").Error)
					_, readErr := GetUserByOIDCIdentity(issuer, subject)
					require.Error(t, readErr)
					require.NoError(t, target.Update(field, original).Error)
				})
			}
			forced := errors.New("transaction rollback")
			require.ErrorIs(t, db.Transaction(func(tx *gorm.DB) error {
				if err := BindOIDCIdentityWithTx(tx, users[4].Id, issuer, "rollback"); err != nil {
					return err
				}
				return forced
			}), forced)
			_, err = GetUserByOIDCIdentity(issuer, "rollback")
			require.ErrorIs(t, err, gorm.ErrRecordNotFound)
			var after User
			require.NoError(t, db.First(&after, users[4].Id).Error)
			assert.Empty(t, after.OidcId)
			require.Error(t, UpdateUserBindColumn(users[4].Id, "oidc_id", claim.Subject))
			require.Error(t, db.Transaction(func(tx *gorm.DB) error {
				return UpdateUserBindColumnForSessionWithTx(tx, AuthSessionIdentity{UserID: users[4].Id}, "oidc_id", claim.Subject)
			}))
			require.NoError(t, owner.ClearBinding("oidc"))
			_, err = GetUserByOIDCIdentity(issuer, subject)
			require.ErrorIs(t, err, gorm.ErrRecordNotFound)
			require.NoError(t, db.Transaction(func(tx *gorm.DB) error { return BindOIDCIdentityWithTx(tx, users[4].Id, issuer, subject) }))
			// Soft deletion reserves ownership; hard deletion uses the native purge.
			require.NoError(t, db.Delete(&users[4]).Error)
			_, err = GetUserByOIDCIdentity(issuer, subject)
			require.Error(t, err)
			require.ErrorIs(t, db.Transaction(func(tx *gorm.DB) error { return BindOIDCIdentityWithTx(tx, users[5].Id, issuer, subject) }), ErrExternalIdentityAlreadyClaimed)
			_, err = HardDeleteUserById(users[4].Id)
			require.NoError(t, err)
			require.NoError(t, db.Transaction(func(tx *gorm.DB) error { return BindOIDCIdentityWithTx(tx, users[5].Id, issuer, subject) }))
			// Concurrent native registration rolls back the losing user and claim.
			start = make(chan struct{})
			results = make(chan error, 2)
			for i := range 2 {
				wg.Go(func() {
					<-start
					results <- db.Transaction(func(tx *gorm.DB) error {
						user := User{Username: fmt.Sprintf("oidc-register-%d", i), Status: common.UserStatusEnabled, Role: common.RoleCommonUser}
						if err := user.InsertWithTx(tx, 0); err != nil {
							return err
						}
						return BindOIDCIdentityWithTx(tx, user.Id, issuer, "registration")
					})
				})
			}
			close(start)
			wg.Wait()
			close(results)
			success, denied = 0, 0
			for result := range results {
				if result == nil {
					success++
				} else {
					require.ErrorIs(t, result, ErrExternalIdentityAlreadyClaimed)
					denied++
				}
			}
			require.Equal(t, 1, success)
			require.Equal(t, 1, denied)
			var count int64
			require.NoError(t, db.Model(&User{}).Where("username LIKE ?", "oidc-register-%").Count(&count).Error)
			assert.EqualValues(t, 1, count)
			registered, err := GetUserByOIDCIdentity(issuer, "registration")
			require.NoError(t, err)
			require.NoError(t, db.Transaction(func(tx *gorm.DB) error { return BindOIDCIdentityWithTx(tx, registered.Id, issuer, "registration") }))
		})
	}
}
