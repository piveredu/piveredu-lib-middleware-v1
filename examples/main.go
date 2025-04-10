package main

import (
	"connectrpc.com/connect"
	"crypto/tls"
	"github.com/piveredu/piveredu-lib-middleware-v1/pivereduware"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // IMPORTANT!
		},
	}

	silverwareAuthenticator := pivereduware.NewAuthenticator(transport)
	silverwareMiddleware := pivereduware.NewMiddleware(silverwareAuthenticator)
	silverwareInterceptors := pivereduware.NewInterceptors(silverwareAuthenticator)

	// Replace and use the service name from the generated proto file
	silverwareMiddleware.EnableRpcReflection(mux, "")
	silverwareMiddleware.EnableHealthProbe()
	//silverwareMiddleware.EnableCors()

	// Interceptors should be attached to the service handler
	_ = connect.WithInterceptors(
		silverwareInterceptors.UnaryLoggingInterceptor(),
		silverwareInterceptors.UnaryAuthTokenValidatorInterceptor([]string{}),
		silverwareInterceptors.TenantPresentHeaderInterceptor("x-tenant-id"),
	)
}
