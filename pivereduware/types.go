package pivereduware

import (
	"context"
	"encoding/json"
	"net/http"

	"connectrpc.com/connect"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
)

const (
	// ContextKeyUser is used to store the authenticated user's claims in context.
	ContextKeyUser = "UserClaimsKey"
	// XTenantKey is the metadata key for the company Id header
	XTenantKey = "x-tenant-id"
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

type ContextHelper interface {
	GetTenant(connect.AnyRequest) (string, error)
	GetUserClaims(context.Context) *UserAuthClaims
}

type PiverwareMiddleware interface {
	HealthProbe(...string) (string, http.Handler)
	CorsMiddleware(h http.Handler, allowedOrigins, allowedHeaders, allowedMethods []string) http.Handler
	LoggingUnaryInterceptor() connect.UnaryInterceptorFunc
	UnaryTenantPresentHeaderInterceptor(PiverwareAuthenticator) connect.UnaryFunc
	UnaryAuthTokenValidatorInterceptor(PiverwareAuthenticator, []string) connect.UnaryInterceptorFunc
	EnableConnectRpcReflection(mux *http.ServeMux, services ...string)
	StreamingTokenInterceptor(authenticator PiverwareAuthenticator, routes []string) connect.StreamingHandlerFunc
}

type PiverwareAuthenticator interface {
	ExtractHeaderToken(connect.AnyRequest) (string, error)
	ExtractToken(ctx context.Context) (string, error)
	GetVerifier() *oidc.IDTokenVerifier
	ValidateTokenMiddleware(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error)
}
