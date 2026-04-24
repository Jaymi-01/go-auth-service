package models

import (
	"time"

	"gorm.io/gorm"
)

type RefreshToken struct {
	ID        uint           `gorm:"primaryKey"`
	UserID    uint           `gorm:"not null"`
	Token     string         `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time      `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

type BlacklistedToken struct {
	ID        uint      `gorm:"primaryKey"`
	Token     string    `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
}
