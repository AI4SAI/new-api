package oauth

import (
	"context"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
)

func init() {
	Register("oidc", &OIDCProvider{})
}

// OIDCProvider implements OAuth for OIDC
type OIDCProvider struct{}

type oidcUser struct {
	OpenID            string `json:"sub"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Picture           string `json:"picture"`
}

func (p *OIDCProvider) GetName() string {
	return system_setting.GetOIDCSettings().GetEffectiveDisplayName()
}

func (p *OIDCProvider) IsEnabled() bool {
	return system_setting.GetOIDCSettings().Enabled
}

// OIDCDiscovery uses the configured issuer and the maintained protocol engine.
func OIDCDiscovery(ctx context.Context) (*oidc.Provider, context.Context, string, error) {
	settings := system_setting.GetOIDCSettings()
	const suffix = "/.well-known/openid-configuration"
	if !strings.HasSuffix(settings.WellKnown, suffix) {
		return nil, ctx, "", errors.New("OIDC discovery is required")
	}
	issuer := strings.TrimSuffix(settings.WellKnown, suffix)
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || net.ParseIP(parsed.Hostname()).IsLoopback()))) {
		return nil, ctx, "", errors.New("OIDC issuer is invalid")
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	requestContext := oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(requestContext, issuer)
	if err != nil {
		return nil, requestContext, issuer, errors.New("OIDC discovery unavailable")
	}
	var metadata struct {
		Authorization string   `json:"authorization_endpoint"`
		Token         string   `json:"token_endpoint"`
		JWKS          string   `json:"jwks_uri"`
		UserInfo      string   `json:"userinfo_endpoint"`
		PKCE          []string `json:"code_challenge_methods_supported"`
	}
	if provider.Claims(&metadata) != nil || !slices.Contains(metadata.PKCE, "S256") {
		return nil, requestContext, issuer, errors.New("OIDC S256 is required")
	}
	for _, endpoint := range []string{metadata.Authorization, metadata.Token, metadata.JWKS, metadata.UserInfo} {
		u, err := url.Parse(endpoint)
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" ||
			(u.Scheme != "https" && !(parsed.Scheme == "http" && u.Scheme == "http" &&
				(u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()))) {
			return nil, requestContext, issuer, errors.New("OIDC endpoint is invalid")
		}
	}
	return provider, requestContext, issuer, nil
}

func (p *OIDCProvider) ExchangeToken(ctx context.Context, code string, c *gin.Context) (*OAuthToken, error) {
	settings := system_setting.GetOIDCSettings()
	verifier, nonce := c.GetString("oidc_pkce_verifier"), c.GetString("oidc_nonce")
	clientID, expectedIssuer := c.GetString("oidc_client_id"), c.GetString("oidc_issuer")
	if code == "" || len(verifier) != 43 || len(nonce) != 43 || clientID == "" || clientID != settings.ClientId {
		return nil, NewOAuthError(common.NewMessage(msgInvalidCode))
	}
	provider, requestContext, issuer, err := OIDCDiscovery(ctx)
	if err != nil || issuer != expectedIssuer {
		return nil, errors.New("OIDC configuration changed")
	}
	endpoint := provider.Endpoint()
	var methods struct {
		Auth []string `json:"token_endpoint_auth_methods_supported"`
	}
	if provider.Claims(&methods) != nil {
		return nil, errors.New("OIDC token authentication unavailable")
	}
	if len(methods.Auth) == 0 || slices.Contains(methods.Auth, "client_secret_basic") {
		endpoint.AuthStyle = oauth2.AuthStyleInHeader
	} else if slices.Contains(methods.Auth, "client_secret_post") {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	} else {
		return nil, errors.New("OIDC token authentication unavailable")
	}
	config := oauth2.Config{ClientID: clientID, ClientSecret: settings.ClientSecret, Endpoint: endpoint,
		RedirectURL: system_setting.ServerAddress + "/oauth/oidc"}
	token, err := config.Exchange(requestContext, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, errors.New("OIDC code exchange failed")
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, errors.New("OIDC ID token is missing")
	}
	verified, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(requestContext, raw)
	if err != nil || verified.Subject == "" || verified.Nonce != nonce {
		return nil, errors.New("OIDC ID token verification failed")
	}
	var claims struct {
		AuthorizedParty string `json:"azp"`
		AuthTime        int64  `json:"auth_time"`
	}
	if verified.Claims(&claims) != nil || (claims.AuthorizedParty != "" && claims.AuthorizedParty != clientID) ||
		(len(verified.Audience) > 1 && claims.AuthorizedParty != clientID) {
		return nil, errors.New("OIDC audience differs")
	}
	if after := c.GetInt64("oidc_auth_after"); after != 0 && (claims.AuthTime < after-30 || claims.AuthTime > time.Now().Unix()+60) {
		return nil, errors.New("OIDC recent authentication is required")
	}
	if verified.AccessTokenHash != "" && verified.VerifyAccessToken(token.AccessToken) != nil {
		return nil, errors.New("OIDC access token differs")
	}
	return &OAuthToken{AccessToken: token.AccessToken, TokenType: token.TokenType, RefreshToken: token.RefreshToken,
		IDToken: raw, ClientID: clientID, VerifiedSubject: verified.Subject, VerifiedIssuer: issuer}, nil
}

func (p *OIDCProvider) GetUserInfo(ctx context.Context, token *OAuthToken) (*OAuthUser, error) {
	provider, requestContext, issuer, err := OIDCDiscovery(ctx)
	if err != nil || token.VerifiedSubject == "" || token.VerifiedIssuer != issuer || token.ClientID != system_setting.GetOIDCSettings().ClientId {
		return nil, errors.New("OIDC identity is not verified")
	}
	info, err := provider.UserInfo(requestContext, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token.AccessToken, TokenType: token.TokenType}))
	if err != nil || info.Subject != token.VerifiedSubject {
		return nil, errors.New("OIDC UserInfo subject differs")
	}
	var claims oidcUser
	if info.Claims(&claims) != nil {
		return nil, errors.New("OIDC UserInfo is invalid")
	}
	return &OAuthUser{ProviderUserID: model.OIDCIdentityKey(issuer, info.Subject), Username: claims.PreferredUsername, DisplayName: claims.Name, Email: claims.Email}, nil
}

func (p *OIDCProvider) IsUserIDTaken(providerUserID string) bool {
	return model.IsOidcIdAlreadyTaken(providerUserID)
}

func (p *OIDCProvider) FillUserByProviderID(user *model.User, providerUserID string) error {
	user.OidcId = providerUserID
	return user.FillUserByOidcId()
}

func (p *OIDCProvider) SetProviderUserID(user *model.User, providerUserID string) {
	user.OidcId = providerUserID
}

func (p *OIDCProvider) GetProviderPrefix() string {
	return "oidc_"
}

// ProviderUserIDColumn returns the users-table column storing this provider's user ID.
func (p *OIDCProvider) ProviderUserIDColumn() string {
	return "oidc_id"
}
