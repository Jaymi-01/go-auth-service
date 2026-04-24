package service

import (
	"log"
)

type EmailService interface {
	SendVerificationEmail(email, token string) error
	SendPasswordResetEmail(email, token string) error
}

type mockEmailService struct{}

func NewMockEmailService() EmailService {
	return &mockEmailService{}
}

func (s *mockEmailService) SendVerificationEmail(email, token string) error {
	log.Printf("[EMAIL MOCK] To: %s | Subject: Verify Your Email | Link: http://localhost:8080/verify-email?token=%s", email, token)
	return nil
}

func (s *mockEmailService) SendPasswordResetEmail(email, token string) error {
	log.Printf("[EMAIL MOCK] To: %s | Subject: Reset Your Password | Link: http://localhost:8080/reset-password?token=%s", email, token)
	return nil
}
