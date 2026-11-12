package model

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type MigrationIdentityFields struct {
	ID        int    `gorm:"primaryKey"`
	Name      string `gorm:"size:64;unique"`
	Reference string `gorm:"size:64;uniqueIndex"`
	Provider  string `gorm:"size:32;uniqueIndex:,composite:provider_subject"`
	Subject   string `gorm:"size:64;uniqueIndex:,composite:provider_subject"`
}

type migrationIdentityV1 struct {
	MigrationIdentityFields
	Digest string `gorm:"type:char(32)"`
}

type migrationIdentityV2 struct {
	MigrationIdentityFields
	Digest string `gorm:"type:char(64)"`
	Note   string `gorm:"size:128"`
}

type migrationConstraintV1 struct {
	ID   int    `gorm:"primaryKey"`
	Name string `gorm:"size:64"`
}

type migrationConstraintV2 struct {
	ID   int    `gorm:"primaryKey"`
	Name string `gorm:"size:64;unique"`
}

type migrationDecimalV1 struct {
	ID    int     `gorm:"primaryKey"`
	Price float64 `gorm:"type:decimal(10,6);default:0"`
}

type migrationDecimalV2 struct {
	ID    int     `gorm:"primaryKey"`
	Price float64 `gorm:"type:decimal(12,6);not null;default:0"`
}

type migrationDecimalV3 struct {
	ID    int     `gorm:"primaryKey"`
	Price float64 `gorm:"type:decimal(12,6);not null;default:1.25"`
}

func TestMigrationSchemaStability(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			var dsn string
			switch dialect {
			case "sqlite":
				dsn = "local"
				previousPath := common.SQLitePath
				common.SQLitePath = filepath.Join(t.TempDir(), "migration.db")
				t.Cleanup(func() { common.SQLitePath = previousPath })
			case "mysql":
				dsn = os.Getenv("TEST_MYSQL_DSN")
			case "postgres":
				dsn = os.Getenv("TEST_POSTGRES_DSN")
			}
			if dsn == "" {
				t.Skip("test database DSN is not configured")
			}
			t.Setenv("MIGRATION_TEST_DSN", dsn)
			db, _, err := chooseDB("MIGRATION_TEST_DSN", false)
			require.NoError(t, err)
			sqlDB, err := db.DB()
			require.NoError(t, err)
			t.Cleanup(func() { _ = sqlDB.Close() })
			recorder := &migrationSQLRecorder{}
			db = db.Session(&gorm.Session{Logger: recorder})

			t.Run("identity_and_indexes", func(t *testing.T) {
				const table = "migration_identity_test"
				t.Cleanup(func() { _ = db.Migrator().DropTable(table) })
				require.NoError(t, db.Table(table).AutoMigrate(&migrationIdentityV1{}))
				row := migrationIdentityV1{
					MigrationIdentityFields: MigrationIdentityFields{ID: 1, Name: "root", Reference: "token-reference", Provider: "oidc", Subject: "subject"},
					Digest:                  "old-digest",
				}
				require.NoError(t, db.Table(table).Create(&row).Error)
				recorder.reset()
				require.NoError(t, db.Table(table).AutoMigrate(&migrationIdentityV1{}))
				assert.Empty(t, recorder.schemaMutations())

				require.NoError(t, db.Table(table).AutoMigrate(&migrationIdentityV2{}))
				columns, err := db.Table(table).Migrator().ColumnTypes(&migrationIdentityV2{})
				require.NoError(t, err)
				for _, column := range columns {
					if column.Name() == "digest" {
						length, ok := column.Length()
						require.True(t, ok)
						assert.EqualValues(t, 64, length)
					}
				}
				assert.True(t, db.Table(table).Migrator().HasColumn(&migrationIdentityV2{}, "note"))
				recorder.reset()
				require.NoError(t, db.Table(table).AutoMigrate(&migrationIdentityV2{}))
				assert.Empty(t, recorder.schemaMutations())
				var saved migrationIdentityV2
				require.NoError(t, db.Table(table).First(&saved, 1).Error)
				assert.Equal(t, row.MigrationIdentityFields, saved.MigrationIdentityFields)
				expectedDigest := row.Digest
				if dialect == "postgres" {
					expectedDigest += strings.Repeat(" ", 64-len(row.Digest))
				}
				assert.Equal(t, expectedDigest, saved.Digest)
				for _, duplicate := range []migrationIdentityV2{
					{MigrationIdentityFields: MigrationIdentityFields{Name: "root", Reference: "other-1", Provider: "other", Subject: "1"}},
					{MigrationIdentityFields: MigrationIdentityFields{Name: "other-2", Reference: "token-reference", Provider: "other", Subject: "2"}},
					{MigrationIdentityFields: MigrationIdentityFields{Name: "other-3", Reference: "other-3", Provider: "oidc", Subject: "subject"}},
				} {
					assert.Error(t, db.Table(table).Create(&duplicate).Error)
				}
			})

			t.Run("quota_cache_tokens", func(t *testing.T) {
				for _, upgrade := range []bool{false, true} {
					t.Run(fmt.Sprintf("upgrade=%v", upgrade), func(t *testing.T) {
						const table = "migration_quota_cache_tokens_test"
						quotaDB := db.Table(table).Session(&gorm.Session{})
						t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(table)) })
						require.NoError(t, quotaDB.AutoMigrate(&QuotaData{}))
						if upgrade {
							// The deployed shape differs only by these two new columns.
							require.NoError(t, quotaDB.Migrator().DropColumn(&QuotaData{}, "CacheReadTokens"))
							require.NoError(t, quotaDB.Migrator().DropColumn(&QuotaData{}, "CacheCreationTokens"))
						}
						original := []QuotaData{
							{Id: 1, UserID: 71, Username: "retained-user", ModelName: "retained-model", CreatedAt: 1700000000,
								UseGroup: "default", TokenID: 81, ChannelID: 91, NodeName: "retained-node", TokenUsed: 420, Count: 7, Quota: 321},
							{Id: 2, UserID: 71, Username: "retained-user", ModelName: "retained-model", CreatedAt: 1700003600,
								UseGroup: "default", TokenID: 82, ChannelID: 92, NodeName: "retained-node", TokenUsed: 84, Count: 2, Quota: 63},
						}
						require.NoError(t, quotaDB.Omit("CacheReadTokens", "CacheCreationTokens").Create(&original).Error)
						for round := range 2 {
							recorder.reset()
							require.NoError(t, quotaDB.AutoMigrate(&QuotaData{}))
							if round == 1 {
								assert.Empty(t, recorder.schemaMutations(), "the second startup must not repeat DDL")
							}
							var stored []QuotaData
							require.NoError(t, quotaDB.Order("id").Find(&stored).Error)
							assert.Equal(t, original, stored, "all existing dimensions and aggregate values must survive migration %d", round+1)
							var nullCounters int64
							require.NoError(t, quotaDB.Where("cache_read_tokens IS NULL OR cache_creation_tokens IS NULL").Count(&nullCounters).Error)
							assert.Zero(t, nullCounters, "new columns must initialize existing rows to zero")
						}
						wide := QuotaData{Id: 3, CacheReadTokens: 1 << 33, CacheCreationTokens: 1 << 34}
						require.NoError(t, quotaDB.Create(&wide).Error)
						var loaded QuotaData
						require.NoError(t, quotaDB.Where("id = ?", wide.Id).Take(&loaded).Error)
						assert.Equal(t, wide.CacheReadTokens, loaded.CacheReadTokens)
						assert.Equal(t, wide.CacheCreationTokens, loaded.CacheCreationTokens)
						// An old writer omits the new counters and still gets SQL defaults.
						require.NoError(t, quotaDB.Create(map[string]any{"id": 4, "count": 1, "quota": 29, "token_used": 11}).Error)
						var defaults struct {
							CacheReadTokens     *int64
							CacheCreationTokens *int64
						}
						require.NoError(t, quotaDB.Where("id = ?", 4).Take(&defaults).Error)
						require.NotNil(t, defaults.CacheReadTokens)
						require.NotNil(t, defaults.CacheCreationTokens)
						assert.Zero(t, *defaults.CacheReadTokens)
						assert.Zero(t, *defaults.CacheCreationTokens)
					})
				}
			})

			t.Run("token_self_disable_source", func(t *testing.T) {
				for _, upgrade := range []bool{false, true} {
					t.Run(fmt.Sprintf("upgrade=%v", upgrade), func(t *testing.T) {
						const table = "migration_token_self_disable_test"
						isolated := db
						if dialect == "postgres" {
							// Explicit Token index names are shared within a PostgreSQL schema.
							isolated = db.Begin()
							require.NoError(t, isolated.Error)
							t.Cleanup(func() { require.NoError(t, isolated.Rollback().Error) })
							schemaName := fmt.Sprintf("self_disable_test_%d", time.Now().UnixNano())
							require.NoError(t, isolated.Exec("CREATE SCHEMA ?", clause.Table{Name: schemaName}).Error)
							require.NoError(t, isolated.Exec("SET LOCAL search_path TO ?", clause.Table{Name: schemaName}).Error)
						}
						tokenDB := isolated.Table(table).Session(&gorm.Session{})
						t.Cleanup(func() { require.NoError(t, isolated.Migrator().DropTable(table)) })
						require.NoError(t, tokenDB.AutoMigrate(&Token{}))
						if upgrade {
							require.NoError(t, tokenDB.Migrator().DropColumn(&Token{}, "SelfDisabledByUserID"))
						}
						original := Token{Id: 1, UserId: 71, Key: "retained-source-key", Status: common.TokenStatusDisabled,
							Name: "retained", ExpiredTime: -1, RemainQuota: 120, UsedQuota: 30, QuotaRevision: 2,
							MetadataRevision: 4, ManagedSubjectRef: "member-a"}
						require.NoError(t, tokenDB.Omit("SelfDisabledByUserID").Create(&original).Error)
						for round := range 2 {
							recorder.reset()
							require.NoError(t, tokenDB.AutoMigrate(&Token{}))
							if round == 1 {
								assert.Empty(t, recorder.schemaMutations())
							}
							var stored Token
							require.NoError(t, tokenDB.First(&stored, original.Id).Error)
							assert.Equal(t, original, stored, "migration preserves original key identity, quota and authorization")
							assert.False(t, stored.CanSelfEnable(7), "unknown historical disables do not acquire self-enable permission")
						}
						var source struct{ SelfDisabledByUserID *int }
						require.NoError(t, tokenDB.Where("id = ?", original.Id).Take(&source).Error)
						require.NotNil(t, source.SelfDisabledByUserID)
						assert.Zero(t, *source.SelfDisabledByUserID)
						require.NoError(t, tokenDB.Where("id = ?", original.Id).Update("self_disabled_by_user_id", 7).Error)
						require.NoError(t, tokenDB.AutoMigrate(&Token{}))
						var stored Token
						require.NoError(t, tokenDB.First(&stored, original.Id).Error)
						assert.True(t, stored.CanSelfEnable(7), "normal restarts retain an established member pause")
					})
				}
			})

			t.Run("unique_constraint_changes", func(t *testing.T) {
				const table = "migration_constraint_test"
				t.Cleanup(func() { _ = db.Migrator().DropTable(table) })
				require.NoError(t, db.Table(table).AutoMigrate(&migrationConstraintV1{}))
				require.NoError(t, db.Table(table).Create(&migrationConstraintV1{Name: "existing"}).Error)
				require.NoError(t, db.Table(table).AutoMigrate(&migrationConstraintV2{}))
				assert.Error(t, db.Table(table).Create(&migrationConstraintV2{Name: "existing"}).Error)
				recorder.reset()
				require.NoError(t, db.Table(table).AutoMigrate(&migrationConstraintV2{}))
				assert.Empty(t, recorder.schemaMutations())
				require.NoError(t, db.Table(table).AutoMigrate(&migrationConstraintV1{}))
				require.NoError(t, db.Table(table).Create(&migrationConstraintV1{Name: "existing"}).Error)
			})

			if dialect == "postgres" {
				t.Run("renamed_unique_constraints", func(t *testing.T) {
					const table = "migration_renamed_unique"
					t.Cleanup(func() { _ = db.Migrator().DropTable(table) })
					tableDB := db.Table(table).Session(&gorm.Session{})
					require.NoError(t, tableDB.AutoMigrate(&migrationConstraintV1{}))
					original := migrationConstraintV1{Name: "existing"}
					require.NoError(t, tableDB.Create(&original).Error)
					for _, name := range []string{"models_model_name_key", `imported "model" name`} {
						require.NoError(t, db.Exec("ALTER TABLE ? ADD CONSTRAINT ? UNIQUE (name)", clause.Table{Name: table}, clause.Column{Name: name}).Error)
					}
					require.NoError(t, db.Exec("ALTER TABLE ? ADD CONSTRAINT keep_composite UNIQUE (id, name)", clause.Table{Name: table}).Error)
					require.NoError(t, db.Exec("CREATE INDEX keep_name_lookup ON ? (name)", clause.Table{Name: table}).Error)
					// A unique field must keep the old names and still reject duplicates.
					require.NoError(t, tableDB.AutoMigrate(&migrationConstraintV2{}))
					require.Error(t, tableDB.Create(&migrationConstraintV2{Name: "existing"}).Error)
					require.NoError(t, db.Exec("CREATE TABLE migration_unique_reference (name varchar(64) REFERENCES migration_renamed_unique(name))").Error)
					t.Cleanup(func() { _ = db.Migrator().DropTable("migration_unique_reference") })
					require.NoError(t, db.Exec("INSERT INTO migration_unique_reference (name) VALUES (?)", "existing").Error)
					require.Error(t, tableDB.AutoMigrate(&migrationConstraintV1{}), "dependent foreign keys must not be cascaded away")
					for _, name := range []string{"models_model_name_key", `imported "model" name`} {
						assert.True(t, tableDB.Migrator().HasConstraint(&migrationConstraintV1{}, name), "all old constraints must survive rollback")
					}
					var references int64
					require.NoError(t, db.Table("migration_unique_reference").Count(&references).Error)
					assert.EqualValues(t, 1, references)
					require.NoError(t, db.Migrator().DropTable("migration_unique_reference"))
					// Removing column uniqueness must resolve both actual constraint names.
					require.NoError(t, tableDB.AutoMigrate(&migrationConstraintV1{}))
					recorder.reset()
					require.NoError(t, tableDB.AutoMigrate(&migrationConstraintV1{}))
					assert.Empty(t, recorder.schemaMutations())
					require.NoError(t, tableDB.Create(&migrationConstraintV1{Name: "existing"}).Error)
					assert.True(t, tableDB.Migrator().HasConstraint(&migrationConstraintV1{}, "keep_composite"))
					assert.True(t, tableDB.Migrator().HasIndex(&migrationConstraintV1{}, "keep_name_lookup"))
					var rows []migrationConstraintV1
					require.NoError(t, tableDB.Order("id").Find(&rows).Error)
					require.Len(t, rows, 2)
					assert.Equal(t, original, rows[0])
				})
			}

			if dialect == "mysql" {
				t.Run("decimal_default_and_real_changes", func(t *testing.T) {
					const table = "migration_decimal_test"
					t.Cleanup(func() { _ = db.Migrator().DropTable(table) })
					require.NoError(t, db.Table(table).AutoMigrate(&migrationDecimalV1{}))
					require.NoError(t, db.Table(table).Create(&migrationDecimalV1{ID: 1, Price: 12.345678}).Error)
					for _, target := range []any{&migrationDecimalV1{}, &migrationDecimalV2{}, &migrationDecimalV3{}} {
						require.NoError(t, db.Table(table).AutoMigrate(target))
						recorder.reset()
						require.NoError(t, db.Table(table).AutoMigrate(target))
						assert.Empty(t, recorder.schemaMutations())
					}
					columns, err := db.Table(table).Migrator().ColumnTypes(&migrationDecimalV3{})
					require.NoError(t, err)
					for _, column := range columns {
						if column.Name() == "price" {
							precision, scale, ok := column.DecimalSize()
							require.True(t, ok)
							assert.EqualValues(t, 12, precision)
							assert.EqualValues(t, 6, scale)
							nullable, ok := column.Nullable()
							require.True(t, ok)
							assert.False(t, nullable)
						}
					}
					require.NoError(t, db.Table(table).Create(&map[string]any{"id": 2}).Error)
					var prices []float64
					require.NoError(t, db.Table(table).Order("id").Pluck("price", &prices).Error)
					assert.Equal(t, []float64{12.345678, 1.25}, prices)
				})
			}
		})
	}
}
