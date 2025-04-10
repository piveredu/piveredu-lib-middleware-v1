package pivereduware

import (
	connectcors "connectrpc.com/cors"
	"connectrpc.com/grpchealth"
	"connectrpc.com/grpcreflect"
	"github.com/rs/cors"
	"net/http"
)

type grpcAuthMiddleware struct {
	authenticator Authenticator
}

func (middleware *grpcAuthMiddleware) EnableRpcReflection(mux *http.ServeMux, services ...string) {
	reflector := grpcreflect.NewStaticReflector(services...)
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))
}

func (middleware *grpcAuthMiddleware) EnableHealthProbe(services ...string) (string, http.Handler) {
	checker := grpchealth.NewStaticChecker(services...)
	return grpchealth.NewHandler(checker)
}

func (middleware *grpcAuthMiddleware) EnableCors(h http.Handler, allowedOrigins, allowedHeaders, allowedMethods []string) http.Handler {
	methods := connectcors.AllowedMethods()
	defaultHeaders := connectcors.AllowedHeaders()

	combinedMethods := append(methods, allowedMethods...)
	combinedHeaders := append(defaultHeaders, allowedHeaders...)

	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: combinedMethods,
		AllowedHeaders: combinedHeaders,
		ExposedHeaders: connectcors.ExposedHeaders(),
	})

	return corsMiddleware.Handler(h)
}

func NewMiddleware(authenticator Authenticator) Middleware {
	return &grpcAuthMiddleware{authenticator: authenticator}
}
