package main

import (
	"fmt"
	"log"
	"my-auth-api/internal/config"
	"my-auth-api/internal/handler"
	"my-auth-api/internal/middleware"
	"my-auth-api/internal/models"
	"my-auth-api/internal/repository"
	"my-auth-api/internal/service"
	"net/http"
	"time"

	"github.com/glebarez/sqlite"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
)

func main() {
	// 1. Load config
	cfg := config.Load()

	// 2. Initialize DB
	db, err := gorm.Open(sqlite.Open(cfg.DBPath), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Auto migrate
	if err := db.AutoMigrate(&models.User{}, &models.RefreshToken{}, &models.BlacklistedToken{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// 3. Initialize layers
	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(db)
	emailSvc := service.NewMockEmailService()
	authService := service.NewAuthService(userRepo, tokenRepo, emailSvc, cfg.JWTSecret)
	authHandler := handler.NewAuthHandler(authService)

	// 4. Setup Middlewares
	limiter := middleware.NewIPRateLimiter(rate.Every(time.Second), 5) // 5 requests per second
	authMW := middleware.AuthMiddleware(cfg.JWTSecret, tokenRepo)
	rateMW := middleware.RateLimitMiddleware(limiter)

	// 5. Setup Router (Go 1.22+ style)
	mux := http.NewServeMux()

	// Public routes (Rate limited)
	mux.Handle("POST /register", rateMW(http.HandlerFunc(authHandler.Register)))
	mux.Handle("POST /login", rateMW(http.HandlerFunc(authHandler.Login)))
	mux.Handle("POST /forgot-password", rateMW(http.HandlerFunc(authHandler.ForgotPassword)))
	
	// Public routes (Non-rate limited)
	mux.HandleFunc("GET /verify-email", authHandler.VerifyEmail)
	mux.HandleFunc("POST /reset-password", authHandler.ResetPassword)
	mux.HandleFunc("POST /refresh", authHandler.Refresh)

	// Protected routes
	mux.Handle("GET /profile", authMW(http.HandlerFunc(authHandler.GetProfile)))
	mux.Handle("PUT /profile", authMW(http.HandlerFunc(authHandler.UpdateProfile)))
	mux.Handle("POST /logout", authMW(http.HandlerFunc(authHandler.Logout)))
	mux.Handle("GET /protected", authMW(http.HandlerFunc(authHandler.Protected)))

	// 6. Token Cleanup (Background)
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			tokenRepo.CleanupExpiredTokens()
		}
	}()

	// 7. Start Server
	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("Server starting on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
