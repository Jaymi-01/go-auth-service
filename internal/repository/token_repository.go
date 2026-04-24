package repository

import (
	"my-auth-api/internal/models"
	"time"

	"gorm.io/gorm"
)

type TokenRepository interface {
	CreateRefreshToken(token *models.RefreshToken) error
	FindRefreshToken(token string) (*models.RefreshToken, error)
	DeleteRefreshToken(token string) error
	DeleteUserRefreshTokens(userID uint) error
	
	BlacklistToken(token *models.BlacklistedToken) error
	IsTokenBlacklisted(token string) (bool, error)
	CleanupExpiredTokens() error
}

type tokenRepository struct {
	db *gorm.DB
}

func NewTokenRepository(db *gorm.DB) TokenRepository {
	return &tokenRepository{db: db}
}

func (r *tokenRepository) CreateRefreshToken(token *models.RefreshToken) error {
	return r.db.Create(token).Error
}

func (r *tokenRepository) FindRefreshToken(token string) (*models.RefreshToken, error) {
	var rt models.RefreshToken
	if err := r.db.Where("token = ? AND expires_at > ?", token, time.Now()).First(&rt).Error; err != nil {
		return nil, err
	}
	return &rt, nil
}

func (r *tokenRepository) DeleteRefreshToken(token string) error {
	return r.db.Where("token = ?", token).Delete(&models.RefreshToken{}).Error
}

func (r *tokenRepository) DeleteUserRefreshTokens(userID uint) error {
	return r.db.Where("user_id = ?", userID).Delete(&models.RefreshToken{}).Error
}

func (r *tokenRepository) BlacklistToken(token *models.BlacklistedToken) error {
	return r.db.Create(token).Error
}

func (r *tokenRepository) IsTokenBlacklisted(token string) (bool, error) {
	var count int64
	err := r.db.Model(&models.BlacklistedToken{}).Where("token = ?", token).Count(&count).Error
	return count > 0, err
}

func (r *tokenRepository) CleanupExpiredTokens() error {
	now := time.Now()
	r.db.Where("expires_at < ?", now).Delete(&models.RefreshToken{})
	r.db.Where("expires_at < ?", now).Delete(&models.BlacklistedToken{})
	return nil
}
