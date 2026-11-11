package router

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// accessTokenExemptRoutes are /api routes that never reach dashboard
// authentication, so a personal access token has no rule to satisfy there.
var accessTokenExemptRoutes = []string{
	// Anonymous pages and setup.
	"GET /api/setup",
	"POST /api/setup",
	"GET /api/status",
	"GET /api/uptime/status",
	"GET /api/notice",
	"GET /api/user-agreement",
	"GET /api/privacy-policy",
	"GET /api/about",
	"GET /api/home_page_content",
	"GET /api/ratio_config",
	"GET /api/user/groups",

	// Anonymous account entry points.
	"GET /api/verification",
	"GET /api/reset_password",
	"POST /api/user/reset",
	"POST /api/user/register",
	"GET /api/user/login/encryption-key",
	"POST /api/user/login",
	"POST /api/user/login/2fa",
	"POST /api/user/login/verify",
	"POST /api/user/login/passkey/begin",
	"POST /api/user/login/passkey/finish",
	"POST /api/user/passkey/login/begin",
	"POST /api/user/passkey/login/finish",
	"GET /api/oauth/wechat",
	"GET /api/oauth/telegram/login",
	"GET /api/oauth/telegram/bind/:flow_token",

	// Browser session cookie endpoints.
	"POST /api/user/auth/refresh",
	"POST /api/user/auth/logout",

	// Payment callbacks.
	"POST /api/stripe/webhook",
	"POST /api/creem/webhook",
	"POST /api/waffo/webhook",
	"POST /api/waffo-pancake/webhook/:env",
	"GET /api/user/epay/notify",
	"POST /api/user/epay/notify",
	"GET /api/subscription/epay/notify",
	"POST /api/subscription/epay/notify",
	"GET /api/subscription/epay/return",
	"POST /api/subscription/epay/return",

	// API key authentication (TokenAuthReadOnly).
	"GET /api/usage/token/",
	"GET /api/log/token",
}

// accessTokenHelperRoutes are declared through handlePermissionRoute outside
// channelPermissionRoutes.
var accessTokenHelperRoutes = map[string]authz.Permission{
	"GET /api/task_plugin_options": authz.TaskPluginBind,
	"GET /api/audit":               authz.AuditRead,
}

func newAccessTokenScopeTestEngine(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	// A registration declaration duplicated in the static table panics here.
	require.NotPanics(t, func() {
		SetApiRouter(engine)
		SetDashboardRouter(engine)
		SetRelayRouter(engine)
		SetTaskPluginProtocolRouter(engine)
		SetVideoRouter(engine)
		SetTaskRouter(engine)
	})
	return engine
}

func TestAccessTokenRouteRulesCoverEveryDashboardRoute(t *testing.T) {
	engine := newAccessTokenScopeTestEngine(t)
	exempt := map[string]bool{}
	for _, key := range accessTokenExemptRoutes {
		exempt[key] = true
	}
	registered := map[string]bool{}
	panel := map[string]bool{}
	for _, route := range engine.Routes() {
		if !strings.HasPrefix(route.Path, "/api/") && !strings.HasPrefix(route.Path, "/pg/") {
			continue
		}
		key := route.Method + " " + route.Path
		registered[key] = true
		if !exempt[key] {
			panel[key] = true
		}
	}
	for _, key := range accessTokenExemptRoutes {
		assert.True(t, registered[key], "exempt route %s is no longer registered", key)
	}

	declared := map[string]int{}
	for _, key := range middleware.AccessTokenRouteRuleKeys() {
		declared[key]++
	}
	for key := range panel {
		assert.Equal(t, 1, declared[key], "panel route %s must be declared exactly once", key)
	}
	for key := range declared {
		assert.True(t, panel[key], "declared route %s is not a registered panel route", key)
	}

	permissionRoutes := map[string]authz.Permission{}
	for _, route := range channelPermissionRoutes {
		permissionRoutes[route.method+" "+joinPaths("/api/channel", route.path)] = route.permission
	}
	for key, permission := range accessTokenHelperRoutes {
		permissionRoutes[key] = permission
	}
	for key, permission := range permissionRoutes {
		rule, ok := middleware.AccessTokenRouteRule(key)
		require.True(t, ok, key)
		assert.Equal(t, "scope", rule.Kind(), key)
		assert.Equal(t, service.AccessTokenScopeOf(permission), rule.Scope(), key)
	}
	for _, key := range []string{"GET /api/token/context", "GET /api/token/member-candidates", "POST /api/user/self/playground"} {
		rule, ok := middleware.AccessTokenRouteRule(key)
		require.True(t, ok, key)
		assert.Equal(t, "session", rule.Kind(), key)
		assert.Empty(t, rule.Scope(), key)
	}
}

func TestRetiredTokenDeleteRoutesRejectWithoutCoreOrKeyReads(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	connection, err := db.DB()
	require.NoError(t, err)
	connection.SetMaxOpenConns(1)
	previousDB, previousLogDB, previousRedis := model.DB, model.LOG_DB, common.RedisEnabled
	previousSecret, previousDatabase := common.SessionSecret, common.MainDatabaseType()
	model.DB, model.LOG_DB, common.RedisEnabled = db, db, false
	common.SessionSecret = "retired-delete-route-session-secret"
	common.SetMainDatabaseType(common.DatabaseTypeSQLite)
	t.Cleanup(func() {
		model.DB, model.LOG_DB, common.RedisEnabled = previousDB, previousLogDB, previousRedis
		common.SessionSecret = previousSecret
		common.SetMainDatabaseType(previousDatabase)
		require.NoError(t, connection.Close())
	})
	// There is deliberately no Token table: refusal must not query a key.
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.UserSession{}, &model.UserAccessToken{}, &model.AuditLog{}, &model.Option{}))
	user := model.User{Username: "retired-delete-user", Status: common.UserStatusEnabled, Role: common.RoleCommonUser, AuthVersion: 1, Group: "default"}
	require.NoError(t, db.Create(&user).Error)
	session := model.UserSession{SID: "retired-delete-session", UserID: user.Id, Version: 1, UserAuthVersion: 1,
		Status: model.UserSessionStatusActive, RefreshHash: "fixture", LoginMethod: "oidc", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	require.NoError(t, model.CreateUserSession(&session))
	credential, _, err := service.IssueAccessToken(service.AuthIdentity{UserID: user.Id, SessionID: session.SID, UserAuthVersion: 1, SessionVersion: 1})
	require.NoError(t, err)
	var coreCalls atomic.Int64
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		coreCalls.Add(1)
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	defer core.Close()
	secret := filepath.Join(t.TempDir(), "admission")
	require.NoError(t, os.WriteFile(secret, []byte(strings.Repeat("x", 48)), 0600))
	t.Setenv("MODEL_BILLING_INSTANCE_REF", "fixture-gateway")
	t.Setenv("MODEL_BILLING_ADMISSION_KEY_FILE", secret)
	t.Setenv("MODEL_MANAGEMENT_AUTHORIZATION_URL", core.URL+"/v1/internal/models/authorize-management")
	engine := newAccessTokenScopeTestEngine(t)
	for _, test := range []struct{ method, path, body, action string }{
		{http.MethodDelete, "/api/token/3", "", "token.delete"},
		{http.MethodDelete, "/api/token/not-an-id", "", "token.delete"},
		{http.MethodPost, "/api/token/batch", `{"ids":[3,4]}`, "token.delete_batch"},
		{http.MethodPost, "/api/token/batch", `{"ids":`, "token.delete_batch"},
	} {
		request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
		request.Header.Set("Authorization", "Bearer "+credential)
		request.Header.Set("X-SAI-Workspace-Key", "org:fixture")
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		engine.ServeHTTP(response, request)
		require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
		require.Contains(t, response.Body.String(), "KEY_DELETION_NOT_ALLOWED")
		var event model.AuditLog
		require.NoError(t, db.Order("id desc").First(&event).Error)
		require.Equal(t, test.action, event.Action)
		require.False(t, event.Success)
		require.Equal(t, http.StatusForbidden, event.Status)
		require.NotContains(t, event.Other.Op.Params, "name")
		require.NotContains(t, event.Other.Op.Params, "requested_ids")
	}
	require.Zero(t, coreCalls.Load(), "retired operations must never ask Core for authorization")
}

func TestAccessTokenCatalogCoversEveryPermission(t *testing.T) {
	catalog := service.AccessTokenCatalog(1, common.RoleRootUser)
	scopes := map[string]bool{}
	resources := map[string]int{}
	for _, group := range catalog {
		for _, resource := range group.Resources {
			resources[resource.Resource]++
			for _, action := range resource.Actions {
				scopes[resource.Resource+":"+action.Action] = true
			}
		}
	}
	for _, permission := range authz.AllPermissions() {
		assert.True(t, scopes[service.AccessTokenScopeOf(permission)], "root catalog lacks %s", service.AccessTokenScopeOf(permission))
	}
	for resource, count := range resources {
		assert.Equal(t, 1, count, "resource %s appears in more than one catalog entry", resource)
	}
}

func TestAccessTokenVerificationScopesAreAllListed(t *testing.T) {
	files, err := filepath.Glob("../service/*.go")
	require.NoError(t, err)
	fileSet := token.NewFileSet()
	var scopes []string
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, file, nil, 0)
		require.NoError(t, err)
		for _, declaration := range parsed.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.CONST {
				continue
			}
			for _, spec := range general.Specs {
				value := spec.(*ast.ValueSpec)
				for i, name := range value.Names {
					if !strings.HasPrefix(name.Name, "VerificationScope") || i >= len(value.Values) {
						continue
					}
					literal, ok := value.Values[i].(*ast.BasicLit)
					require.True(t, ok, name.Name)
					scope, err := strconv.Unquote(literal.Value)
					require.NoError(t, err)
					scopes = append(scopes, scope)
				}
			}
		}
	}
	require.NotEmpty(t, scopes)
	for _, scope := range scopes {
		_, listed := service.AccessTokenVerificationScope(scope)
		assert.True(t, listed, "verification scope %s has no access token rule", scope)
	}
}
