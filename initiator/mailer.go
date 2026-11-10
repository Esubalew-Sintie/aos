package initiator

import (
	"errors"

	"github.com/flash-software-technology/aos/platform/config"
	"github.com/flash-software-technology/aos/platform/logger"
	"github.com/flash-software-technology/aos/platform/mailer"
	"github.com/flash-software-technology/aos/platform/secret"
)

// InitMailer picks how email is sent.
//
// With SMTP settings, email goes through that server. Without them, a
// development engine writes each email to its log. A production engine
// refuses to start: an email carries sign-in and reset links, and those
// must never reach a log.
func InitMailer(cfg config.Config, log logger.Logger) (mailer.Sender, error) {
	if cfg.SMTPAddr != "" {
		if cfg.MailFrom == "" {
			return nil, errors.New("AOS_MAIL_FROM is not set (the address emails are sent from)")
		}
		return mailer.NewSMTPSender(cfg.SMTPAddr, cfg.SMTPUsername, cfg.SMTPPassword, cfg.MailFrom)
	}
	if cfg.Development() {
		log.Warnf("no SMTP server is configured: emails are written to this log and kept at /dev/mail, not sent")
		return mailer.NewInbox(log.Named("mailer"), 200), nil
	}
	return nil, errors.New("no way to send email is configured: set AOS_SMTP_ADDR and AOS_MAIL_FROM")
}

// InitBreachChecker picks how leaked passwords are recognised. The
// built-in list always applies. AOS_BREACH_CHECK=hibp adds the Have I
// Been Pwned range API, which sees only five characters of a hash.
func InitBreachChecker(cfg config.Config, log logger.Logger) secret.BreachChecker {
	local := secret.NewLocalBreachList()
	if cfg.BreachCheck != "hibp" {
		return local
	}
	return secret.NewBreachChain(func(err error) {
		log.Warnf("breached-password service unavailable: %v", err)
	}, local, secret.NewHIBPChecker())
}
