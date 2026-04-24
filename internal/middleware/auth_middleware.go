package middleware

import (
	"context"
	"my-auth-api/internal/repository"
	"my-auth-api/pkg/jwtutils"
	"net/http"
	"strings"
)

type contextKey string

const (
	UserIDKey      contextKey = "user_id"
	AccessTokenKey contextKey = "access_token"
)

func AuthMiddleware(jwtSecret string, tokenRepo repository.TokenRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
				return
			}

			token := parts[1]

			// Check blacklist
			blacklisted, err := tokenRepo.IsTokenBlacklisted(token)
			if err != nil || blacklisted {
				http.Error(w, "Token is invalid or logged out", http.StatusUnauthorized)
				return
			}

			claims, err := jwtutils.ValidateToken(token, jwtSecret)
			if err != nil {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, AccessTokenKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
