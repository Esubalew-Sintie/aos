package mailer

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flash-softeware/aos/platform/logger"
)

// Inbox keeps the last emails a development engine "sent", so a developer
// can read them at /dev/mail instead of digging through the log.
//
// DEVELOPMENT ONLY, like LogSender: the emails hold sign-in and reset
// links.
type Inbox struct {
	log  *LogSender
	mu   sync.Mutex
	next int
	mail []InboxEmail
	max  int
}

// InboxEmail is one kept email, with the links and token found in it.
type InboxEmail struct {
	ID      string    `json:"id"`
	At      time.Time `json:"at"`
	To      string    `json:"to"`
	Subject string    `json:"subject"`
	Body    string    `json:"body"`
	Links   []string  `json:"links"`
	// Token is the first token in a link, or the code in a sign-in email.
	Token string `json:"token,omitempty"`
	Code  string `json:"code,omitempty"`
}

func NewInbox(log logger.Logger, max int) *Inbox {
	if max <= 0 {
		max = 200
	}
	return &Inbox{log: NewLogSender(log), max: max}
}

var (
	linkPattern  = regexp.MustCompile(`https?://[^\s]+`)
	tokenPattern = regexp.MustCompile(`[?&]token=([A-Za-z0-9_\-%]+)`)
	codePattern  = regexp.MustCompile(`(?m)^\s*(\d{6})\s*$`)
	plainToken   = regexp.MustCompile(`(?:code|Code): ([A-Za-z0-9_\-]{16,})`)
)

func (i *Inbox) Send(ctx context.Context, e Email) error {
	_ = i.log.Send(ctx, e)
	kept := InboxEmail{At: time.Now().UTC(), To: e.To, Subject: e.Subject, Body: e.Body, Links: linkPattern.FindAllString(e.Body, -1)}
	if kept.Links == nil {
		kept.Links = []string{}
	}
	if m := tokenPattern.FindStringSubmatch(e.Body); m != nil {
		kept.Token = m[1]
	} else if m := plainToken.FindStringSubmatch(e.Body); m != nil {
		kept.Token = m[1]
	}
	if m := codePattern.FindStringSubmatch(e.Body); m != nil {
		kept.Code = m[1]
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.next++
	kept.ID = strconv.Itoa(i.next)
	i.mail = append(i.mail, kept)
	if len(i.mail) > i.max {
		i.mail = i.mail[len(i.mail)-i.max:]
	}
	return nil
}

// List returns the kept emails, newest first, optionally only to one address.
func (i *Inbox) List(to string) []InboxEmail {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := []InboxEmail{}
	for n := len(i.mail) - 1; n >= 0; n-- {
		if to == "" || strings.EqualFold(i.mail[n].To, to) {
			out = append(out, i.mail[n])
		}
	}
	return out
}

func (i *Inbox) Clear() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.mail = nil
}
