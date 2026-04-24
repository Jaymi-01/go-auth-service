package hash

import (
	"errors"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

var ErrPasswordTooWeak = errors.New("password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number")

// ValidatePassword checks if a password meets complexity requirements
func ValidatePassword(password string) error {
	var (
		hasMinLen  = len(password) >= 8
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		}
	}

	if hasMinLen && hasUpper && hasLower && hasNumber {
		return nil
	}
	return ErrPasswordTooWeak
}

// HashPassword generates a bcrypt hash of the password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash compares a password with a hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
