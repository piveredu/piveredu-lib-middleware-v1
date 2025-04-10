package pivereduware

import (
	"connectrpc.com/connect"
	"context"
	"fmt"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
	"slices"
	"time"
)

type connectInterceptors struct {
	authenticator Authenticator
}

func (interceptor *connectInterceptors) UnaryLoggingInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
			start := time.Now()
			fullMethod := request.Spec().Procedure
			log.Printf("gRPC Method: %s, Request: %+v", fullMethod, request)
			resp, err := next(ctx, request)
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

func (interceptor *connectInterceptors) TenantPresentHeaderInterceptor(tenantKey string) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
			tenantId := request.Header().Get(tenantKey)
			if tenantId == "" {
				return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing '%s' key within header", tenantKey))
			}

			if _, err := uuid.Parse(tenantId); err != nil {
				return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid '%s' key within header", tenantKey))
			}

			return next(ctx, request)
		}
	}
}

func (interceptor *connectInterceptors) UnaryAuthTokenValidatorInterceptor(publicRoutes []string) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			// Extract the full method name from the request
			fullMethod := req.Spec().Procedure

			// If the method is public, skip authentication
			if slices.Contains(publicRoutes, fullMethod) {
				return next(ctx, req)
			}

			// Otherwise, apply the authentication middleware
			token, err := interceptor.authenticator.ExtractHeaderToken(req)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing or invalid token: %v", err))
			}

			// Validate the token
			idToken, err := interceptor.authenticator.GetVerifier().Verify(ctx, token)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid token: %v", err))
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
}

func NewInterceptors(authenticator Authenticator) ConnectInterceptors {
	return &connectInterceptors{authenticator: authenticator}
}
