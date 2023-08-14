package email

import (
	"context"
	"fmt"
	"net/smtp"

	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/logger"
)

// Service ...
type Service struct {
	addr string
	auth smtp.Auth
	from string
}

func NewEmailService(host string, port int, username, password, from string) *Service {
	auth := smtp.PlainAuth("", username, password, host)
	addr := fmt.Sprintf("%s:%d", host, port)
	return &Service{addr, auth, from}
}

func (s *Service) SendForgotPasswordEmail(ctx context.Context, to string, link string) {
	mime := "Content-Type: text/plain; charset=\"UTF-8\";"
	subject := "BIR Payment Platform Password Reset"
	body := "Click the following link to reset your password \n\n " + link

	err := s.send([]string{to}, subject, body, mime)
	if err != nil {
		logger.WithField(ctx, "bir.email.error", err)
	}
}

func (s *Service) SendActivationEmail(ctx context.Context, to string, link string) {
	mime := "Content-Type: text/plain; charset=\"UTF-8\";"
	subject := "Verify BIR Payment Platform Account"
	body := "Here's your verification link \n\n " + link

	err := s.send([]string{to}, subject, body, mime)
	if err != nil {
		logger.WithField(ctx, "bir.email.error", err)
	}
}

func (s *Service) send(to []string, subject string, body string, mime string) error {
	emailSubject := "Subject: " + subject + "\n"
	emailMime := "MIME-version: 1.0;\n" + mime + "\n\n"
	msg := []byte(emailSubject + emailMime + body)

	if err := smtp.SendMail(s.addr, s.auth, s.from, to, msg); err != nil {
		return err
	}
	return nil
}
