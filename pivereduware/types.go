package pivereduware

import (
	"encoding/json"
	"net/http"

	"connectrpc.com/connect"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// ContextKeyUser is used to store the authenticated user's claims in context.
	ContextKeyUser = "UserClaimsKey"
)

// UserAuthClaims represents the JWT claims structure
type UserAuthClaims struct {
	Exp               int64          `json:"exp"`
	Iat               int64          `json:"iat"`
	Jti               string         `json:"jti"`
	Iss               string         `json:"iss"`
	Aud               []string       `json:"aud"`
	Id                string         `json:"sub"`
	Typ               string         `json:"typ"`
	Azp               string         `json:"azp"`
	Sid               string         `json:"sid"`
	Acr               string         `json:"acr"`
	AllowedOrigins    []string       `json:"allowed-origins"`
	RealmAccess       RealmAccess    `json:"realm_access"`
	ResourceAccess    ResourceAccess `json:"resource_access"`
	Scope             string         `json:"scope"`
	EmailVerified     bool           `json:"email_verified"`
	Organization      []string       `json:"organization"`
	Name              string         `json:"name"`
	PreferredUsername string         `json:"preferred_username"`
	GivenName         string         `json:"given_name"`
	FamilyName        string         `json:"family_name"`
	Email             string         `json:"email"`
	jwt.RegisteredClaims
}

// RealmAccess defines roles at the realm level
type RealmAccess struct {
	Roles []string `json:"roles"`
}

// ResourceAccess defines roles at the resource level
type ResourceAccess struct {
	Account AccountRoles `json:"account"`
}

// AccountRoles defines roles within the "account" resource
type AccountRoles struct {
	Roles []string `json:"roles"`
}

func (u *UserAuthClaims) String() string {
	jb, _ := json.Marshal(u)
	return string(jb)
}

type Middleware interface {
	EnableHealthProbe(...string) (string, http.Handler)
	EnableRpcReflection(mux *http.ServeMux, services ...string)
	EnableCors(h http.Handler, allowedOrigins, allowedHeaders, allowedMethods []string) http.Handler
}

type ConnectInterceptors interface {
	UnaryLoggingInterceptor() connect.UnaryInterceptorFunc
	TenantPresentHeaderInterceptor(string) connect.UnaryInterceptorFunc
	UnaryAuthTokenValidatorInterceptor([]string) connect.UnaryInterceptorFunc
}

type Authenticator interface {
	GetVerifier() *oidc.IDTokenVerifier
	ExtractHeaderToken(request connect.AnyRequest) (string, error)
}
