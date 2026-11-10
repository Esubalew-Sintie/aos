package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/flash-software-technology/aos/platform/secret"
)

// SMTPSender sends email through an SMTP server.
type SMTPSender struct {
	addr string
	host string
	from *mail.Address
	auth smtp.Auth
}

// NewSMTPSender prepares a sender. addr is "host:port". username and
// password may be empty for a server that needs none.
func NewSMTPSender(addr, username, password, from string) (*SMTPSender, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("mailer: the SMTP address must look like host:port: %w", err)
	}
	fromAddr, err := mail.ParseAddress(from)
	if err != nil {
		return nil, fmt.Errorf("mailer: the from address is not valid: %w", err)
	}
	s := &SMTPSender{addr: addr, host: host, from: fromAddr}
	if username != "" {
		// PlainAuth refuses to send the password over a connection that
		// is not encrypted, unless the server is on this machine.
		s.auth = smtp.PlainAuth("", username, password, host)
	}
	return s, nil
}

func (s *SMTPSender) Send(ctx context.Context, e Email) error {
	// A line break in a header would let the text after it become a
	// header of its own. Refuse it.
	if strings.ContainsAny(e.To, "\r\n") || strings.ContainsAny(e.Subject, "\r\n") {
		return errors.New("mailer: a line break in the recipient or the subject")
	}
	to, err := mail.ParseAddress(e.To)
	if err != nil {
		return fmt.Errorf("mailer: the recipient address is not valid: %w", err)
	}

	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("mailer: connect: %w", err)
	}
	// One deadline for the whole exchange, so a stalled server cannot
	// hold the delivery worker.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("mailer: greeting: %w", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("mailer: start TLS: %w", err)
		}
	}
	if s.auth != nil {
		if err := client.Auth(s.auth); err != nil {
			return fmt.Errorf("mailer: sign in to the SMTP server: %w", err)
		}
	}
	if err := client.Mail(s.from.Address); err != nil {
		return fmt.Errorf("mailer: sender refused: %w", err)
	}
	if err := client.Rcpt(to.Address); err != nil {
		return fmt.Errorf("mailer: recipient refused: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("mailer: send: %w", err)
	}
	if _, err := w.Write(s.message(to, e)); err != nil {
		return fmt.Errorf("mailer: send: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mailer: send: %w", err)
	}
	return client.Quit()
}

// message builds a plain-text email.
func (s *SMTPSender) message(to *mail.Address, e Email) []byte {
	domain := s.from.Address[strings.LastIndex(s.from.Address, "@")+1:]
	var b strings.Builder
	header := func(name, value string) { b.WriteString(name + ": " + value + "\r\n") }
	header("From", s.from.String())
	header("To", to.String())
	header("Subject", mime.QEncoding.Encode("utf-8", e.Subject))
	header("Date", time.Now().UTC().Format(time.RFC1123Z))
	header("Message-ID", "<"+secret.HexID(16)+"@"+domain+">")
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "8bit")
	b.WriteString("\r\n")
	// Mail uses CRLF line ends.
	body := strings.ReplaceAll(strings.ReplaceAll(e.Body, "\r\n", "\n"), "\n", "\r\n")
	b.WriteString(body)
	return []byte(b.String())
}
