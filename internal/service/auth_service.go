package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"my-auth-api/internal/models"
	"my-auth-api/internal/repository"
	"my-auth-api/pkg/hash"
	"my-auth-api/pkg/jwtutils"
	"time"
)

var (
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotVerified    = errors.New("email not verified")
	ErrInvalidToken       = errors.New("invalid token")
	ErrExpiredToken       = errors.New("token expired")
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type AuthService interface {
	Register(email, password, firstName, lastName string) error
	Login(email, password string) (*TokenResponse, error)
	Refresh(refreshToken string) (*TokenResponse, error)
	VerifyEmail(token string) error
	ForgotPassword(email string) error
	ResetPassword(token, newPassword string) error
	Logout(accessToken, refreshToken string) error
	GetProfile(userID uint) (*models.User, error)
	UpdateProfile(userID uint, firstName, lastName string) error
}

type authService struct {
	userRepo  repository.UserRepository
	tokenRepo repository.TokenRepository
	emailSvc  EmailService
	jwtSecret string
}

func NewAuthService(userRepo repository.UserRepository, tokenRepo repository.TokenRepository, emailSvc EmailService, jwtSecret string) AuthService {
	return &authService{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		emailSvc:  emailSvc,
		jwtSecret: jwtSecret,
	}
}

func (s *authService) Register(email, password, firstName, lastName string) error {
	if err := hash.ValidatePassword(password); err != nil {
		return err
	}

	_, err := s.userRepo.FindByEmail(email)
	if err == nil {
		return ErrUserAlreadyExists
	}

	hashedPassword, err := hash.HashPassword(password)
	if err != nil {
		return err
	}

	verificationToken := s.generateRandomToken()

	user := &models.User{
		Email:             email,
		Password:          hashedPassword,
		FirstName:         firstName,
		LastName:          lastName,
		VerificationToken: verificationToken,
	}

	if err := s.userRepo.Create(user); err != nil {
		return err
	}

	return s.emailSvc.SendVerificationEmail(email, verificationToken)
}

func (s *authService) Login(email, password string) (*TokenResponse, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if !hash.CheckPasswordHash(password, user.Password) {
		return nil, ErrInvalidCredentials
	}

	if !user.IsVerified {
		return nil, ErrUserNotVerified
	}

	return s.generateTokenPair(user.ID)
}

func (s *authService) Refresh(refreshToken string) (*TokenResponse, error) {
	rt, err := s.tokenRepo.FindRefreshToken(refreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Delete old refresh token (rotate)
	s.tokenRepo.DeleteRefreshToken(refreshToken)

	return s.generateTokenPair(rt.UserID)
}

func (s *authService) VerifyEmail(token string) error {
	user, err := s.userRepo.FindByVerificationToken(token)
	if err != nil {
		return ErrInvalidToken
	}

	user.IsVerified = true
	user.VerificationToken = ""
	return s.userRepo.Update(user)
}

func (s *authService) ForgotPassword(email string) error {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return nil // Return nil to avoid email enumeration
	}

	token := s.generateRandomToken()
	expires := time.Now().Add(1 * time.Hour)

	user.ResetToken = token
	user.ResetTokenExpiresAt = &expires

	if err := s.userRepo.Update(user); err != nil {
		return err
	}

	return s.emailSvc.SendPasswordResetEmail(email, token)
}

func (s *authService) ResetPassword(token, newPassword string) error {
	if err := hash.ValidatePassword(newPassword); err != nil {
		return err
	}

	user, err := s.userRepo.FindByResetToken(token)
	if err != nil {
		return ErrInvalidToken
	}

	if user.ResetTokenExpiresAt == nil || user.ResetTokenExpiresAt.Before(time.Now()) {
		return ErrExpiredToken
	}

	hashedPassword, err := hash.HashPassword(newPassword)
	if err != nil {
		return err
	}

	user.Password = hashedPassword
	user.ResetToken = ""
	user.ResetTokenExpiresAt = nil

	// Invalidate all existing sessions for safety
	s.tokenRepo.DeleteUserRefreshTokens(user.ID)

	return s.userRepo.Update(user)
}

func (s *authService) Logout(accessToken, refreshToken string) error {
	// 1. Blacklist access token
	claims, err := jwtutils.ValidateToken(accessToken, s.jwtSecret)
	if err == nil {
		s.tokenRepo.BlacklistToken(&models.BlacklistedToken{
			Token:     accessToken,
			ExpiresAt: claims.ExpiresAt.Time,
		})
	}

	// 2. Delete refresh token
	if refreshToken != "" {
		s.tokenRepo.DeleteRefreshToken(refreshToken)
	}

	return nil
}

func (s *authService) GetProfile(userID uint) (*models.User, error) {
	return s.userRepo.FindByID(userID)
}

func (s *authService) UpdateProfile(userID uint, firstName, lastName string) error {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return err
	}

	user.FirstName = firstName
	user.LastName = lastName
	return s.userRepo.Update(user)
}

// Helpers

func (s *authService) generateTokenPair(userID uint) (*TokenResponse, error) {
	accessToken, err := jwtutils.GenerateAccessToken(userID, s.jwtSecret)
	if err != nil {
		return nil, err
	}

	refreshString := s.generateRandomToken()
	err = s.tokenRepo.CreateRefreshToken(&models.RefreshToken{
		UserID:    userID,
		Token:     refreshString,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshString,
	}, nil
}

func (s *authService) generateRandomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
