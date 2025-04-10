package pivereduware

import (
	"connectrpc.com/connect"
	"context"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// keycloakAuthenticator handles OpenID Connect token validation.
type keycloakAuthenticator struct {
	verifier *oidc.IDTokenVerifier
}

func (authenticator *keycloakAuthenticator) ExtractHeaderToken(request connect.AnyRequest) (string, error) {
	// Look for the authorization header.
	authHeader := request.Header().Get("Authorization")
	if authHeader == "" {
		return "", status.Error(codes.Unauthenticated, "missing authorization header")
	}

	// The authorization header should be in the form "Bearer <token>".
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", status.Error(codes.Unauthenticated, "invalid authorization header")
	}

	return parts[1], nil
}

func (authenticator *keycloakAuthenticator) GetVerifier() *oidc.IDTokenVerifier {
	return authenticator.verifier
}

// NewAuthenticator NewMiddleware creates a new OIDC authenticator using the given issuer URL and client configuration.
func NewAuthenticator(transportConfig *http.Transport) Authenticator {
	clientId := os.Getenv("AUTH.CLIENT_ID")
	issuerUrl := os.Getenv("AUTH.URL")
	url := fmt.Sprintf("%s/realms/%s", issuerUrl, os.Getenv("AUTH.REALM"))

	client := &http.Client{
		Timeout:   time.Duration(2) * time.Minute,
		Transport: transportConfig,
	}

	c := oidc.ClientContext(context.Background(), client)
	provider, err := oidc.NewProvider(c, url)
	if err != nil {
		log.Println("error creating oidc provider:", err)
		os.Exit(1)
	}

	oidcConfig := &oidc.Config{
		ClientID: clientId,
	}

	verifier := provider.Verifier(oidcConfig)

	return &keycloakAuthenticator{
		verifier: verifier,
	}
}
