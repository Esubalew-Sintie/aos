// Package mailer delivers messages to people.
package mailer

import (
	"context"

	"github.com/flash-softeware/aos/platform/logger"
)

// Email is a message ready to send.
type Email struct {
	To      string
	Subject string
	Body    string
}

// Sender delivers one email. An error means "try again later".
type Sender interface {
	Send(ctx context.Context, e Email) error
}

// LogSender writes each email to the log instead of sending it.
//
// DEVELOPMENT ONLY. An email can carry a sign-in or reset link, which
// must never reach a log in production. The initiator refuses to use
// this sender outside development.
type LogSender struct {
	log logger.Logger
}

func NewLogSender(log logger.Logger) *LogSender {
	return &LogSender{log: log}
}

func (s *LogSender) Send(ctx context.Context, e Email) error {
	s.log.Info(ctx, "email (development: written to the log, not sent)",
		"to", e.To, "subject", e.Subject, "body", e.Body)
	return nil
}
