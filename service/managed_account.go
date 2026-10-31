package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const ManagedWorkspaceHeader = "X-SAI-Workspace-Key"

type ManagementRequest struct {
	SchemaVersion int    `json:"schema_version"`
	Instance      string `json:"gateway_instance_ref"`
	ActorID       int    `json:"native_actor_id"`
	SessionID     string `json:"session_id"`
	WorkspaceKey  string `json:"workspace_key"`
	Operation     string `json:"operation"`
	RequestID     string `json:"request_id"`
	Method        string `json:"request_method"`
	Path          string `json:"request_path"`
	SHA256        string `json:"request_sha256"`
}

type ManagedAccount struct {
	ManagementRequest
	ActorRef string `json:"actor_ref"`
	OwnerID  int    `json:"native_owner_id"`
	Label    string `json:"account_label"`
	Kind     string `json:"account_kind"`
}

var ErrManagedAccountDenied = errors.New("managed account access denied")

func ManagementAccount(c *gin.Context) *ManagedAccount {
	value, _ := c.Get("managed_account")
	account, _ := value.(*ManagedAccount)
	return account
}

func ManagementOwnerID(c *gin.Context) int {
	if account := ManagementAccount(c); account != nil {
		return account.OwnerID
	}
	return c.GetInt("id")
}

// AuthorizeManagedAccount keeps the authenticated actor intact. Each operation
// obtains a fresh capability from the authority; the browser never supplies one.
func AuthorizeManagedAccount(c *gin.Context, operation string) error {
	workspace := c.GetHeader(ManagedWorkspaceHeader)
	if workspace == "" {
		return nil
	}
	if c.GetBool("use_access_token") || c.GetInt("id") <= 0 || c.GetString("session_id") == "" {
		return ErrManagedAccountDenied
	}
	endpoint, err := url.Parse(os.Getenv("MODEL_MANAGEMENT_AUTHORIZATION_URL"))
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		(endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && (endpoint.Hostname() == "localhost" || net.ParseIP(endpoint.Hostname()).IsLoopback()))) {
		return errors.New("managed account authorization unavailable")
	}
	var body []byte
	if c.Request.Body != nil {
		body, err = io.ReadAll(io.LimitReader(c.Request.Body, 1<<20+1))
	}
	if err != nil || len(body) > 1<<20 {
		return ErrManagedAccountDenied
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	digest := sha256.Sum256(append([]byte(c.Request.Method+"\n"+c.Request.URL.RequestURI()+"\n"), body...))
	request := ManagementRequest{SchemaVersion: 1, Instance: os.Getenv("MODEL_BILLING_INSTANCE_REF"),
		ActorID: c.GetInt("id"), SessionID: c.GetString("session_id"), WorkspaceKey: workspace,
		Operation: operation, RequestID: common.GetUUID(), Method: c.Request.Method,
		Path: c.Request.URL.Path, SHA256: hex.EncodeToString(digest[:])}
	key, err := os.ReadFile(os.Getenv("MODEL_BILLING_ADMISSION_KEY_FILE"))
	secret := strings.TrimSpace(string(key))
	if err != nil || len(secret) < 32 || len(secret) > 512 || request.Instance == "" {
		return errors.New("managed account authorization unavailable")
	}
	payload, err := common.Marshal(request)
	if err != nil {
		return err
	}
	httpRequest, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+secret)
	response, err := managedAdmissionClient.Do(httpRequest)
	if err != nil {
		return errors.New("managed account authorization unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusUnauthorized {
		return ErrManagedAccountDenied
	}
	if response.StatusCode != http.StatusOK {
		return errors.New("managed account authorization unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return errors.New("invalid managed account authorization")
	}
	var result struct {
		SchemaVersion int    `json:"schema_version"`
		Capability    string `json:"capability"`
	}
	var responseFields map[string]any
	if common.Unmarshal(raw, &result) != nil || common.Unmarshal(raw, &responseFields) != nil || len(responseFields) != 2 || result.SchemaVersion != 1 || result.Capability == "" {
		return errors.New("invalid managed account authorization")
	}
	account, err := verifyManagementCapability(result.Capability, request)
	if err != nil {
		return err
	}
	c.Set("managed_account", account)
	c.Header("Cache-Control", "no-store")
	return nil
}

func verifyManagementCapability(raw string, request ManagementRequest) (*ManagedAccount, error) {
	keyData, err := os.ReadFile(os.Getenv("MODEL_MANAGEMENT_AUTHZ_KEYS_FILE"))
	if err != nil {
		return nil, err
	}
	var keyDocument struct {
		SchemaVersion string            `json:"schema_version"`
		Keys          map[string]string `json:"keys"`
	}
	var keyFields map[string]any
	if common.Unmarshal(keyData, &keyDocument) != nil || common.Unmarshal(keyData, &keyFields) != nil || len(keyFields) != 2 || keyDocument.SchemaVersion != "sai-authz-public-keys.v1" || len(keyDocument.Keys) == 0 {
		return nil, ErrManagedAccountDenied
	}
	epoch, err := strconv.ParseInt(os.Getenv("MODEL_MANAGEMENT_AUTHZ_POLICY_EPOCH"), 10, 64)
	if err != nil || epoch < 0 || os.Getenv("MODEL_MANAGEMENT_SITE_ID") == "" {
		return nil, ErrManagedAccountDenied
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if len(token.Header) != 3 || token.Header["typ"] != "SAI-CAPABILITY" {
			return nil, ErrManagedAccountDenied
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || keyDocument.Keys[kid] == "" {
			return nil, ErrManagedAccountDenied
		}
		return jwt.ParseEdPublicKeyFromPEM([]byte(keyDocument.Keys[kid]))
	}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer("sai-portal"), jwt.WithAudience("sai-model-governance"), jwt.WithExpirationRequired(), jwt.WithJSONNumber())
	version, versionOK := capabilityInteger(claims, "version")
	policyEpoch, epochOK := capabilityInteger(claims, "policy_epoch")
	if err != nil || !token.Valid || len(claims) != 11 || !versionOK || version != 1 || !epochOK ||
		claims["aud"] != "sai-model-governance" || claims["surface"] != "model-governance" ||
		claims["site"] != os.Getenv("MODEL_MANAGEMENT_SITE_ID") || policyEpoch != epoch || claims["jti"] != request.RequestID {
		return nil, ErrManagedAccountDenied
	}
	nbf, nbfOK := capabilityInteger(claims, "nbf")
	exp, expOK := capabilityInteger(claims, "exp")
	operations, ok := claims["operations"].([]any)
	if !nbfOK || !expOK || exp <= nbf || exp-nbf > 15 ||
		nbf > time.Now().Unix() || !ok || len(operations) != 1 || operations[0] != request.Operation {
		return nil, ErrManagedAccountDenied
	}
	grantFields, ok := claims["grant"].(map[string]any)
	if !ok || len(grantFields) != 14 {
		return nil, ErrManagedAccountDenied
	}
	grant, err := common.Marshal(claims["grant"])
	if err != nil {
		return nil, err
	}
	var account ManagedAccount
	if common.Unmarshal(grant, &account) != nil || account.ManagementRequest != request || account.OwnerID <= 0 ||
		account.ActorRef == "" || account.Label == "" || (account.Kind != "org" && account.Kind != "project") {
		return nil, ErrManagedAccountDenied
	}
	return &account, nil
}

func capabilityInteger(claims jwt.MapClaims, key string) (int64, bool) {
	value, ok := claims[key].(json.Number)
	if !ok {
		return 0, false
	}
	number, err := value.Int64()
	return number, err == nil
}
