package mailer

import (
	"context"
	"testing"

	"github.com/flash-software-technology/aos/platform/logger"
)

func TestInboxKeepsLinksTokensAndCodes(t *testing.T) {
	in := NewInbox(logger.NewDiscard(), 2)
	_ = in.Send(context.Background(), Email{To: "a@x.test", Subject: "Confirm", Body: "Open:\nhttp://localhost:3000/auth/verify-email?token=AbC_12-3\n"})
	_ = in.Send(context.Background(), Email{To: "b@x.test", Subject: "Code", Body: "Your code is:\n\n123456\n"})
	_ = in.Send(context.Background(), Email{To: "a@x.test", Subject: "Third", Body: "Verification code: abcdefghijklmnopqrstuvwxyz"})
	all := in.List("")
	if len(all) != 2 || all[0].Subject != "Third" {
		t.Fatalf("only the newest are kept, newest first: %+v", all)
	}
	if all[0].Token != "abcdefghijklmnopqrstuvwxyz" || all[1].Code != "123456" {
		t.Fatalf("token or code not found: %+v", all)
	}
	in2 := NewInbox(logger.NewDiscard(), 0)
	_ = in2.Send(context.Background(), Email{To: "a@x.test", Body: "http://localhost:3000/auth/verify-email?token=AbC_12-3"})
	if got := in2.List("A@X.TEST"); len(got) != 1 || got[0].Token != "AbC_12-3" || len(got[0].Links) != 1 {
		t.Fatalf("link token: %+v", got)
	}
	in2.Clear()
	if len(in2.List("")) != 0 {
		t.Fatal("clear")
	}
}
