package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID                   uint           `gorm:"primaryKey" json:"id"`
	Email                string         `gorm:"uniqueIndex;not null" json:"email"`
	Password             string         `gorm:"not null" json:"-"`
	FirstName            string         `json:"first_name"`
	LastName             string         `json:"last_name"`
	IsVerified           bool           `gorm:"default:false" json:"is_verified"`
	VerificationToken    string         `json:"-"`
	ResetToken           string         `json:"-"`
	ResetTokenExpiresAt  *time.Time     `json:"-"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
	DeletedAt            gorm.DeletedAt `gorm:"index" json:"-"`
}
