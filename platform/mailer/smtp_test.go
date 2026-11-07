package mailer

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeSMTP is a tiny mail server on this machine. It accepts one message
// per connection and hands back what it received.
type fakeSMTP struct {
	addr     string
	received chan string
}

func startFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &fakeSMTP{addr: ln.Addr().String(), received: make(chan string, 4)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *fakeSMTP) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	say := func(line string) { conn.Write([]byte(line + "\r\n")) }

	say("220 fake ready")
	var transcript strings.Builder
	inData := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		transcript.WriteString(line)
		if inData {
			if line == ".\r\n" {
				inData = false
				say("250 queued")
				s.received <- transcript.String()
			}
			continue
		}
		switch command := strings.ToUpper(strings.TrimSpace(line)); {
		case strings.HasPrefix(command, "EHLO"), strings.HasPrefix(command, "HELO"):
			say("250 fake")
		case strings.HasPrefix(command, "MAIL FROM"), strings.HasPrefix(command, "RCPT TO"):
			say("250 ok")
		case command == "DATA":
			inData = true
			say("354 go ahead")
		case command == "QUIT":
			say("221 bye")
			return
		default:
			say("502 not implemented")
		}
	}
}

func TestSMTPSenderDeliversAMessage(t *testing.T) {
	server := startFakeSMTP(t)
	sender, err := NewSMTPSender(server.addr, "", "", "AOS <no-reply@example.com>")
	if err != nil {
		t.Fatal(err)
	}

	err = sender.Send(context.Background(), Email{
		To: "hana@example.com", Subject: "Confirm your email — ሰላም", Body: "Line one\nLine two\n",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case got := <-server.received:
		for _, want := range []string{
			"MAIL FROM:<no-reply@example.com>",
			"RCPT TO:<hana@example.com>",
			"To: <hana@example.com>",
			"Content-Type: text/plain; charset=utf-8",
			"Line one\r\nLine two\r\n",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("the message lacks %q:\n%s", want, got)
			}
		}
		// A subject with non-ASCII letters is encoded, not sent raw.
		if strings.Contains(got, "Subject: Confirm your email — ሰላም") || !strings.Contains(got, "Subject: =?utf-8?") {
			t.Errorf("the subject was not encoded:\n%s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server received nothing")
	}
}

// A line break in a header would let an attacker add headers of their own.
func TestSMTPSenderRefusesHeaderInjection(t *testing.T) {
	server := startFakeSMTP(t)
	sender, _ := NewSMTPSender(server.addr, "", "", "no-reply@example.com")
	for name, e := range map[string]Email{
		"line break in the recipient": {To: "hana@example.com\r\nBcc: spy@evil.test", Subject: "x", Body: "x"},
		"line break in the subject":   {To: "hana@example.com", Subject: "x\r\nBcc: spy@evil.test", Body: "x"},
		"not an address":              {To: "not an address", Subject: "x", Body: "x"},
	} {
		if err := sender.Send(context.Background(), e); err == nil {
			t.Errorf("%s: the message was sent", name)
		}
	}
	select {
	case got := <-server.received:
		t.Fatalf("a refused message reached the server:\n%s", got)
	default:
	}
}

func TestSMTPSenderReportsAServerThatIsDown(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens here any more

	sender, _ := NewSMTPSender(addr, "", "", "no-reply@example.com")
	if err := sender.Send(context.Background(), Email{To: "hana@example.com", Subject: "x", Body: "x"}); err == nil {
		t.Fatal("sending to a server that is down reported success")
	}
}

func TestSMTPSenderSettingsAreChecked(t *testing.T) {
	if _, err := NewSMTPSender("no-port", "", "", "no-reply@example.com"); err == nil {
		t.Error("an address with no port was accepted")
	}
	if _, err := NewSMTPSender("localhost:25", "", "", "not an address"); err == nil {
		t.Error("a bad from address was accepted")
	}
}
