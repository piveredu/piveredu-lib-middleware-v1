package pivereduware

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"time"

	"connectrpc.com/connect"
	connectcors "connectrpc.com/cors"
	"connectrpc.com/grpchealth"
	"connectrpc.com/grpcreflect"
	"github.com/rs/cors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type grpcAuthMiddleware struct{}

func (middleware *grpcAuthMiddleware) StreamingTokenInterceptor(authenticator PiverwareAuthenticator, publicRoutes []string) connect.StreamingHandlerFunc {
	panic("streaming token interceptor not yet implemented")
}

func (middleware *grpcAuthMiddleware) EnableConnectRpcReflection(mux *http.ServeMux, services ...string) {
	reflector := grpcreflect.NewStaticReflector(services...)
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))
}

func (middleware *grpcAuthMiddleware) HealthProbe(services ...string) (string, http.Handler) {
	checker := grpchealth.NewStaticChecker(services...)
	return grpchealth.NewHandler(checker)
}

func (middleware *grpcAuthMiddleware) CorsMiddleware(h http.Handler, allowedOrigins, allowedHeaders, allowedMethods []string) http.Handler {
	methods := connectcors.AllowedMethods()
	defaultHeaders := connectcors.AllowedHeaders()

	combinedMethods := append(methods, allowedMethods...)
	combinedOrigins := append([]string{"*"}, allowedOrigins...)
	combinedHeaders := append(defaultHeaders, allowedHeaders...)

	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins: combinedOrigins,
		AllowedMethods: combinedMethods,
		AllowedHeaders: combinedHeaders,
		ExposedHeaders: connectcors.ExposedHeaders(),
	})

	return corsMiddleware.Handler(h)
}

func (middleware *grpcAuthMiddleware) UnaryAuthTokenValidatorInterceptor(authenticator PiverwareAuthenticator, publicRoutes []string) connect.UnaryInterceptorFunc {
	interceptor := func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			// Extract the full method name from the request
			fullMethod := req.Spec().Procedure
			// If the method is public, skip authentication
			if slices.Contains(publicRoutes, fullMethod) {
				return next(ctx, req)
			}

			// Otherwise, apply the authentication middleware
			token, err := authenticator.ExtractHeaderToken(req)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New(fmt.Sprintf("missing or invalid token: %v", err)))
			}

			// Validate the token
			idToken, err := authenticator.GetVerifier().Verify(ctx, token)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New(fmt.Sprintf("invalid token: %v", err)))
			}

			// Add user info to context
			claims := new(UserAuthClaims)
			if err := idToken.Claims(claims); err != nil {
				return nil, status.Error(codes.Internal, fmt.Sprintf("failed to parse token claims: %v", err))
			}

			// Add the claims to the context
			newCtx := context.WithValue(ctx, ContextKeyUser, claims)

			// Proceed with the handler
			return next(newCtx, req)
		}
	}
	return interceptor
}

func (middleware *grpcAuthMiddleware) UnaryTenantPresentHeaderInterceptor(authenticator PiverwareAuthenticator) connect.UnaryFunc {
	panic("not yet implemented!")
}

func (middleware *grpcAuthMiddleware) LoggingUnaryInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			start := time.Now()
			fullMethod := req.Spec().Procedure
			// Sanitize the request to remove any sensitive datasource
			log.Printf("gRPC Method: %s, Request: %+v", fullMethod, req)
			resp, err := next(ctx, req)
			duration := time.Since(start)
			if err != nil {
				log.Printf("gRPC Method: %s, Error: %v, Duration: %s", fullMethod, err, duration)
			} else {
				log.Printf("gRPC Method: %s, Response: %+v, Duration: %s", fullMethod, resp, duration)
			}

			return resp, err
		}
	}
}

func New() PiverwareMiddleware {
	return &grpcAuthMiddleware{}
}
