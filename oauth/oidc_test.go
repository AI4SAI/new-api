package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCProvider_GetName(t *testing.T) {
	settings := system_setting.GetOIDCSettings()
	originalDisplayName := settings.DisplayName
	defer func() { settings.DisplayName = originalDisplayName }()

	p := &OIDCProvider{}

	settings.DisplayName = ""
	assert.Equal(t, "OIDC", p.GetName())

	settings.DisplayName = "  Acme SSO  "
	assert.Equal(t, "Acme SSO", p.GetName())
}

func TestOIDCVerifiedCodeExchange(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	settings := system_setting.GetOIDCSettings()
	previous := *settings
	t.Cleanup(func() { *settings = previous })
	const clientID = "models-rp"
	verifier, nonce := strings.Repeat("v", 43), strings.Repeat("n", 43)
	var issuer, scenario string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
				"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks", "userinfo_endpoint": issuer + "/userinfo",
				"id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"},
				"token_endpoint_auth_methods_supported": []string{"client_secret_basic"}})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
		case "/token":
			require.NoError(t, r.ParseForm())
			assert.Equal(t, verifier, r.Form.Get("code_verifier"))
			id, secret, ok := r.BasicAuth()
			assert.True(t, ok)
			assert.Equal(t, clientID, id)
			assert.Equal(t, "test-secret", secret)
			claims := jwt.MapClaims{"iss": issuer, "sub": "person", "aud": clientID, "nonce": nonce,
				"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix()}
			switch scenario {
			case "nonce":
				claims["nonce"] = "another-flow"
			case "issuer":
				claims["iss"] = issuer + "/other"
			case "audience":
				claims["aud"] = "another-client"
			case "azp":
				claims["aud"], claims["azp"] = []string{clientID, "another-client"}, "another-client"
			case "expired":
				claims["exp"] = time.Now().Add(-time.Hour).Unix()
			case "fresh-auth":
				claims["auth_time"] = time.Now().Unix()
			case "old-auth":
				claims["auth_time"] = time.Now().Add(-time.Hour).Unix()
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "test"
			signed, err := token.SignedString(key)
			require.NoError(t, err)
			if scenario == "signature" {
				signed = signed[:strings.LastIndex(signed, ".")+1] + "invalid"
			}
			if scenario == "missing-id-token" {
				signed = ""
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 60, "id_token": signed})
		case "/userinfo":
			assert.Equal(t, "Bearer access", r.Header.Get("Authorization"))
			subject := "person"
			if scenario == "userinfo" {
				subject = "another-person"
			}
			// A valid person need not disclose an email to this relying party.
			_ = json.NewEncoder(w).Encode(map[string]any{"sub": subject, "name": "Example"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL
	settings.WellKnown, settings.ClientId, settings.ClientSecret = issuer+"/.well-known/openid-configuration", clientID, "test-secret"
	for _, name := range []string{"success", "nonce", "issuer", "audience", "azp", "expired", "signature", "missing-id-token", "userinfo", "fresh-auth", "old-auth"} {
		t.Run(name, func(t *testing.T) {
			scenario = name
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Set("oidc_pkce_verifier", verifier)
			c.Set("oidc_nonce", nonce)
			c.Set("oidc_client_id", clientID)
			c.Set("oidc_issuer", issuer)
			if name == "fresh-auth" || name == "old-auth" {
				c.Set("oidc_auth_after", time.Now().Unix())
			}
			provider := &OIDCProvider{}
			token, err := provider.ExchangeToken(context.Background(), "one-time-code", c)
			if name != "success" && name != "userinfo" && name != "fresh-auth" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			user, err := provider.GetUserInfo(context.Background(), token)
			if name == "userinfo" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, model.OIDCIdentityKey(issuer, "person"), user.ProviderUserID)
			assert.NotEqual(t, model.OIDCIdentityKey(issuer+"/other", "person"), user.ProviderUserID)
		})
	}
}
