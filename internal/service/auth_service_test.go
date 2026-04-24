package service

import (
	"my-auth-api/internal/models"
	"my-auth-api/internal/repository"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) (*gorm.DB, func()) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}

	db.AutoMigrate(&models.User{}, &models.RefreshToken{}, &models.BlacklistedToken{})

	return db, func() {
		// No file to remove for memory DB
	}
}

func TestAuthService(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(db)
	emailSvc := NewMockEmailService()
	svc := NewAuthService(userRepo, tokenRepo, emailSvc, "secret")

	email := "test@example.com"
	password := "Password123" // Must meet complexity

	// 1. Test Register
	err := svc.Register(email, password, "John", "Doe")
	if err != nil {
		t.Errorf("Register failed: %v", err)
	}

	// 2. Try Login (should fail - not verified)
	_, err = svc.Login(email, password)
	if err != ErrUserNotVerified {
		t.Errorf("Expected ErrUserNotVerified, got %v", err)
	}

	// 3. Verify Email
	user, _ := userRepo.FindByEmail(email)
	err = svc.VerifyEmail(user.VerificationToken)
	if err != nil {
		t.Errorf("VerifyEmail failed: %v", err)
	}

	// 4. Login (should succeed)
	tokens, err := svc.Login(email, password)
	if err != nil {
		t.Errorf("Login failed: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Error("Expected token pair, got empty strings")
	}

	// 5. Test Logout
	err = svc.Logout(tokens.AccessToken, tokens.RefreshToken)
	if err != nil {
		t.Errorf("Logout failed: %v", err)
	}

	// Verify blacklist
	blacklisted, _ := tokenRepo.IsTokenBlacklisted(tokens.AccessToken)
	if !blacklisted {
		t.Error("Expected access token to be blacklisted after logout")
	}
}
