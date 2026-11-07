package tests

import (
	"context"
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/module/auth/core"
)

// authenticator plays the app on the person's phone.
type authenticator struct {
	e      *env
	secret []byte
}

func (a *authenticator) code() string {
	return core.TOTPCode(a.secret, core.TOTPStep(a.e.clock.Now()))
}

// enrollTOTP sets an authenticator app up for a session and returns the
// app and the recovery codes.
func enrollTOTP(t *testing.T, tn *tenant, session string) (*authenticator, []string) {
	t.Helper()
	r := tn.front("POST", "/v1/me/totp", nil, session)
	if r.Status != 200 {
		t.Fatalf("enroll: %d %s", r.Status, r.Raw)
	}
	var enrollment struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}
	r.data(&enrollment)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	app := &authenticator{e: tn.e, secret: secret}
	r = tn.front("POST", "/v1/me/totp/confirm", obj{"code": app.code()}, session)
	if r.Status != 200 {
		t.Fatalf("confirm: %d %s", r.Status, r.Raw)
	}
	var codes struct {
		Codes []string `json:"codes"`
	}
	r.data(&codes)
	// The code used to confirm is spent. The next step brings a new one.
	tn.e.clock.advance(31 * time.Second)
	return app, codes.Codes
}

type pendingData struct {
	SecondFactorRequired bool     `json:"second_factor_required"`
	PendingToken         string   `json:"pending_token"`
	Methods              []string `json:"methods"`
	SessionToken         string   `json:"session_token"`
}

func TestSecondFactorWithAnAuthenticatorApp(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	_, session := tn.user("hana@example.com", "some-password")

	// Setting up: the wrong code is refused, the right one turns it on.
	r := tn.front("POST", "/v1/me/totp", nil, session)
	var enrollment struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}
	r.data(&enrollment)
	if !strings.HasPrefix(enrollment.URI, "otpauth://totp/App%20shop:hana@example.com?") {
		t.Fatalf("uri: %s", enrollment.URI)
	}
	if r := tn.front("POST", "/v1/me/totp/confirm", obj{"code": "000000"}, session); r.code() != "wrong_code" {
		t.Fatalf("confirm with a wrong code: %d %s", r.Status, r.Raw)
	}
	app, codes := enrollTOTP(t, tn, session)
	if len(codes) != constant.RecoveryCodeCount {
		t.Fatalf("recovery codes: %v", codes)
	}
	e.deliver()
	if !e.mail.has("hana@example.com", "Two-step sign-in is on") {
		t.Fatal("no notice that the factor was turned on")
	}
	var factors struct {
		TOTP              bool   `json:"totp"`
		RecoveryCodesLeft int    `json:"recovery_codes_left"`
		SecondFactorAt    string `json:"second_factor_at"`
	}
	tn.front("GET", "/v1/me/factors", nil, session).data(&factors)
	if !factors.TOTP || factors.RecoveryCodesLeft != 10 || factors.SecondFactorAt == "" {
		t.Fatalf("factors: %+v", factors)
	}
	// The secret is stored encrypted, never in clear.
	if n := tn.count(`SELECT count(*) FROM aos.totp_factors WHERE secret_encrypted = $1`, app.secret); n != 0 {
		t.Fatal("the secret is stored in clear")
	}

	// Signing in now stops after the password: no session, a pending token.
	r = tn.signIn("hana@example.com", "some-password")
	if r.Status != 200 {
		t.Fatalf("sign in: %d %s", r.Status, r.Raw)
	}
	var pending pendingData
	r.data(&pending)
	if !pending.SecondFactorRequired || pending.PendingToken == "" || pending.SessionToken != "" || strings.Join(pending.Methods, ",") != "totp,recovery_code" {
		t.Fatalf("pending: %+v", pending)
	}
	if r.Header.Get("Set-Cookie") != "" && strings.Contains(r.Header.Get("Set-Cookie"), constant.SessionCookie) {
		t.Fatal("a session cookie was set before the second factor")
	}
	// Five wrong codes cancel it.
	for i := 0; i < 5; i++ {
		if r := tn.front("POST", "/v1/second-factor", obj{"pending_token": pending.PendingToken, "method": "totp", "code": "000000"}, ""); r.code() != "wrong_code" {
			t.Fatalf("wrong code %d: %d %s", i, r.Status, r.Raw)
		}
	}
	if r := tn.front("POST", "/v1/second-factor", obj{"pending_token": pending.PendingToken, "method": "totp", "code": app.code()}, ""); r.code() != "signin_expired" {
		t.Fatalf("after five wrong codes: %d %s", r.Status, r.Raw)
	}
	// Again, with the right code.
	tn.signIn("hana@example.com", "some-password").data(&pending)
	code := app.code()
	r = tn.front("POST", "/v1/second-factor", obj{"pending_token": pending.PendingToken, "method": "totp", "code": code}, "")
	if r.Status != 200 {
		t.Fatalf("second factor: %d %s", r.Status, r.Raw)
	}
	var signedIn struct {
		SessionToken string `json:"session_token"`
		Session      struct {
			SecondFactorAt string `json:"second_factor_at"`
		} `json:"session"`
	}
	r.data(&signedIn)
	if signedIn.SessionToken == "" || signedIn.Session.SecondFactorAt == "" {
		t.Fatalf("signed in: %s", r.Raw)
	}
	// The same code cannot be used twice.
	tn.signIn("hana@example.com", "some-password").data(&pending)
	if r := tn.front("POST", "/v1/second-factor", obj{"pending_token": pending.PendingToken, "method": "totp", "code": code}, ""); r.code() != "wrong_code" {
		t.Fatalf("replayed code: %d %s", r.Status, r.Raw)
	}
	// The pending sign-in expires.
	e.clock.advance(constant.PendingSignInTTL + time.Second)
	if r := tn.front("POST", "/v1/second-factor", obj{"pending_token": pending.PendingToken, "method": "totp", "code": app.code()}, ""); r.code() != "signin_expired" {
		t.Fatalf("expired pending sign-in: %d %s", r.Status, r.Raw)
	}
	// The session records both methods.
	var sessions []struct {
		AuthMethods []string `json:"auth_methods"`
	}
	tn.front("GET", "/v1/sessions", nil, signedIn.SessionToken).data(&sessions)
	found := false
	for _, s := range sessions {
		if strings.Join(s.AuthMethods, ",") == "password,totp" {
			found = true
		}
	}
	if !found {
		t.Fatalf("sessions: %+v", sessions)
	}

	// A recovery code works once, and the person hears of it.
	tn.signIn("hana@example.com", "some-password").data(&pending)
	r = tn.front("POST", "/v1/second-factor", obj{"pending_token": pending.PendingToken, "method": "recovery_code", "code": strings.ToUpper(codes[0])}, "")
	if r.Status != 200 {
		t.Fatalf("recovery code: %d %s", r.Status, r.Raw)
	}
	e.deliver()
	if !e.mail.has("hana@example.com", "recovery code was used") {
		t.Fatal("no notice of the used recovery code")
	}
	tn.signIn("hana@example.com", "some-password").data(&pending)
	if r := tn.front("POST", "/v1/second-factor", obj{"pending_token": pending.PendingToken, "method": "recovery_code", "code": codes[0]}, ""); r.code() != "wrong_code" {
		t.Fatalf("reused recovery code: %d %s", r.Status, r.Raw)
	}
	// New codes need a code; the old ones stop.
	r = tn.front("POST", "/v1/me/recovery-codes", obj{"code": app.code()}, signedIn.SessionToken)
	if r.Status != 200 {
		t.Fatalf("regenerate: %d %s", r.Status, r.Raw)
	}
	var fresh struct {
		Codes []string `json:"codes"`
	}
	r.data(&fresh)
	tn.front("GET", "/v1/me/factors", nil, signedIn.SessionToken).data(&factors)
	if factors.RecoveryCodesLeft != 10 || fresh.Codes[0] == codes[1] {
		t.Fatalf("after regenerate: %+v", factors)
	}
	// Turning it off needs a code too. Then sign-in is one step again.
	if r := tn.front("POST", "/v1/me/totp/disable", obj{"code": "123456"}, signedIn.SessionToken); r.code() != "wrong_code" {
		t.Fatalf("disable with a wrong code: %d %s", r.Status, r.Raw)
	}
	e.clock.advance(31 * time.Second)
	if r := tn.front("POST", "/v1/me/totp/disable", obj{"code": app.code()}, signedIn.SessionToken); r.Status != 200 {
		t.Fatalf("disable: %d %s", r.Status, r.Raw)
	}
	r = tn.signIn("hana@example.com", "some-password")
	pending = pendingData{}
	r.data(&pending)
	if pending.SecondFactorRequired || pending.SessionToken == "" {
		t.Fatalf("sign in after disabling: %s", r.Raw)
	}
}

func TestStepUpForASensitiveAction(t *testing.T) {
	w := newWorld(t)
	tn := w.tn
	// Refunds need a second factor no older than five minutes.
	w.ok(tn.back("PUT", "/v1/permissions", obj{"name": "payment.refund", "step_up_seconds": 300}))

	// Sara has Finance at Merchant A, which covers refunds. Without a
	// session the check cannot pass.
	r := tn.back("POST", "/v1/can", obj{"principal_id": w.sara, "permission": "payment.refund", "resource": obj{"type": "branch", "id": "branch-1"}})
	var can struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	r.data(&can)
	if can.Allowed || can.Reason != "step_up_required" {
		t.Fatalf("without a session: %+v", can)
	}
	// Reading payments needs no step-up.
	if ok, _ := w.can(w.sara, "payment.read", "branch", "branch-1"); !ok {
		t.Fatal("step-up leaked onto another permission")
	}
	// Sara signs in with her authenticator. The session is fresh.
	_, plain := tn.signInSession("sara@example.com", "some-password")
	app, _ := enrollTOTP(t, tn, plain)
	var pending pendingData
	tn.signIn("sara@example.com", "some-password").data(&pending)
	r = tn.front("POST", "/v1/second-factor", obj{"pending_token": pending.PendingToken, "method": "totp", "code": app.code()}, "")
	var signedIn struct {
		SessionToken string `json:"session_token"`
		Session      struct {
			ID string `json:"id"`
		} `json:"session"`
	}
	r.data(&signedIn)
	ask := func() (bool, string) {
		t.Helper()
		tn.back("POST", "/v1/can", obj{"principal_id": w.sara, "permission": "payment.refund", "resource": obj{"type": "branch", "id": "branch-1"}, "session_id": signedIn.Session.ID}).data(&can)
		return can.Allowed, can.Reason
	}
	if ok, reason := ask(); !ok {
		t.Fatalf("fresh session: %s", reason)
	}
	// Six minutes later the factor is stale. A step-up makes it fresh again.
	w.e.clock.advance(6 * time.Minute)
	if ok, reason := ask(); ok || reason != "step_up_required" {
		t.Fatalf("stale session: %v %s", ok, reason)
	}
	if r := tn.front("GET", "/v1/session", nil, signedIn.SessionToken); r.Status != 200 {
		t.Fatal("the person was signed out by a stale factor")
	}
	if r := tn.front("POST", "/v1/step-up", obj{"code": app.code()}, signedIn.SessionToken); r.Status != 200 {
		t.Fatalf("step up: %d %s", r.Status, r.Raw)
	}
	if ok, reason := ask(); !ok {
		t.Fatalf("after step-up: %s", reason)
	}
	// Hana has no authenticator: she cannot step up, and the deny says why.
	_, hana := tn.signInSession("hana@example.com", "some-password")
	if r := tn.front("POST", "/v1/step-up", obj{"code": "123456"}, hana); r.code() != "no_second_factor" {
		t.Fatalf("step up without a factor: %d %s", r.Status, r.Raw)
	}
	// Explain and batch carry the same reason.
	var batch struct {
		Results []struct {
			Reason string `json:"reason"`
		} `json:"results"`
	}
	tn.back("POST", "/v1/can/batch", obj{"checks": []obj{{"principal_id": w.hana, "permission": "payment.refund", "resource": obj{"type": "branch", "id": "branch-1"}}}}).data(&batch)
	if batch.Results[0].Reason != "step_up_required" {
		t.Fatalf("batch: %+v", batch)
	}
}

func TestApplicationCanRequireASecondFactor(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("bank")
	if err := e.app.DB.Platform(context.Background(), func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE aos.tenants SET mfa_policy = 'required' WHERE id = $1`, tn.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, session := tn.user("hana@example.com", "some-password")
	// Signed in, but only to set a factor up.
	r := tn.signIn("hana@example.com", "some-password")
	var signedIn struct {
		SessionToken              string `json:"session_token"`
		SecondFactorSetupRequired bool   `json:"second_factor_setup_required"`
	}
	r.data(&signedIn)
	if !signedIn.SecondFactorSetupRequired || signedIn.SessionToken == "" {
		t.Fatalf("sign in under the policy: %s", r.Raw)
	}
	if r := tn.front("GET", "/v1/organizations", nil, session); r.code() != "second_factor_setup_required" {
		t.Fatalf("a route before setup: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("GET", "/v1/me/factors", nil, session); r.Status != 200 {
		t.Fatalf("factors before setup: %d %s", r.Status, r.Raw)
	}
	app, _ := enrollTOTP(t, tn, session)
	if r := tn.front("GET", "/v1/organizations", nil, session); r.Status != 200 {
		t.Fatalf("a route after setup: %d %s", r.Status, r.Raw)
	}
	// The factor cannot be removed while the application requires one.
	if r := tn.front("POST", "/v1/me/totp/disable", obj{"code": app.code()}, session); r.code() != "second_factor_required" {
		t.Fatalf("disable under the policy: %d %s", r.Status, r.Raw)
	}
	// A guest is not asked for one.
	if r := tn.front("POST", "/v1/guest", nil, ""); r.Status != 200 {
		t.Fatalf("guest under the policy: %d %s", r.Status, r.Raw)
	}
}

func TestOneTimeCodeAndMagicLink(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	tn.user("hana@example.com", "some-password")

	// An unknown address gets the same answer and no email.
	if r := tn.front("POST", "/v1/code/send", obj{"email": "nobody@example.com"}, ""); r.Status != 202 {
		t.Fatalf("send to unknown: %d", r.Status)
	}
	e.deliver()
	if len(e.mail.to("nobody@example.com")) != 0 {
		t.Fatal("an email went to an unknown address")
	}
	if r := tn.front("POST", "/v1/code/send", obj{"email": "hana@example.com"}, ""); r.Status != 202 {
		t.Fatalf("send: %d", r.Status)
	}
	e.deliver()
	mails := e.mail.to("hana@example.com")
	body := mails[len(mails)-1].Body
	code := strings.TrimSpace(strings.Split(strings.Split(body, "is:\n\n")[1], "\n")[0])
	link := e.mail.token("hana@example.com")
	if len(code) != 6 || link == "" {
		t.Fatalf("email: %s", body)
	}
	// Five wrong guesses spend the code.
	for i := 0; i < 5; i++ {
		if r := tn.front("POST", "/v1/code/verify", obj{"email": "hana@example.com", "code": "000000"}, ""); r.code() != "wrong_code" {
			t.Fatalf("wrong guess %d: %d %s", i, r.Status, r.Raw)
		}
	}
	if r := tn.front("POST", "/v1/code/verify", obj{"email": "hana@example.com", "code": code}, ""); r.code() != "wrong_code" {
		t.Fatalf("the right code after five wrong ones: %d %s", r.Status, r.Raw)
	}
	// The link from that email still works, and signs the browser in.
	r := tn.front("POST", "/v1/magic-link", obj{"token": link}, "")
	if r.Status != 200 {
		t.Fatalf("magic link: %d %s", r.Status, r.Raw)
	}
	var signedIn authData
	r.data(&signedIn)
	if signedIn.SessionToken == "" {
		t.Fatal("no session from the magic link")
	}
	if r := tn.front("POST", "/v1/magic-link", obj{"token": link}, ""); r.Status == 200 {
		t.Fatal("a magic link worked twice")
	}
	// A new code; the right guess signs in and voids the link.
	tn.front("POST", "/v1/code/send", obj{"email": "hana@example.com"}, "")
	e.deliver()
	mails = e.mail.to("hana@example.com")
	body = mails[len(mails)-1].Body
	code = strings.TrimSpace(strings.Split(strings.Split(body, "is:\n\n")[1], "\n")[0])
	link = e.mail.token("hana@example.com")
	r = tn.front("POST", "/v1/code/verify", obj{"email": "hana@example.com", "code": " " + code[:3] + " " + code[3:]}, "")
	if r.Status != 200 {
		t.Fatalf("verify: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("POST", "/v1/magic-link", obj{"token": link}, ""); r.Status == 200 {
		t.Fatal("the link survived the code")
	}
	// The code is one factor. With an authenticator, the second is asked for.
	app, _ := enrollTOTP(t, tn, signedIn.SessionToken)
	tn.front("POST", "/v1/code/send", obj{"email": "hana@example.com"}, "")
	e.deliver()
	mails = e.mail.to("hana@example.com")
	body = mails[len(mails)-1].Body
	code = strings.TrimSpace(strings.Split(strings.Split(body, "is:\n\n")[1], "\n")[0])
	var pending pendingData
	tn.front("POST", "/v1/code/verify", obj{"email": "hana@example.com", "code": code}, "").data(&pending)
	if !pending.SecondFactorRequired {
		t.Fatal("a code skipped the second factor")
	}
	if r := tn.front("POST", "/v1/second-factor", obj{"pending_token": pending.PendingToken, "method": "totp", "code": app.code()}, ""); r.Status != 200 {
		t.Fatalf("second factor after a code: %d %s", r.Status, r.Raw)
	}
}

func TestNewDeviceIsAnnounced(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	tn.user("hana@example.com", "some-password")
	e.deliver()
	before := len(e.mail.to("hana@example.com"))

	// The first sign-in from a browser with no device id: a new device.
	r := tn.front("POST", "/v1/sign-in", obj{"email": "hana@example.com", "password": "some-password"}, "",
		"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0")
	if r.Status != 200 {
		t.Fatalf("sign in: %d %s", r.Status, r.Raw)
	}
	var device string
	for _, c := range r.Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, constant.DeviceCookie+"=") {
			device = strings.SplitN(strings.TrimPrefix(c, constant.DeviceCookie+"="), ";", 2)[0]
		}
	}
	if device == "" {
		t.Fatal("no device cookie was set")
	}
	e.deliver()
	mails := e.mail.to("hana@example.com")
	if len(mails) != before+1 || !strings.Contains(mails[len(mails)-1].Subject, "New sign-in") || !strings.Contains(mails[len(mails)-1].Body, "Firefox on Linux") {
		t.Fatalf("new device email: %d mails, last %q", len(mails), mails[len(mails)-1].Subject)
	}
	// The same browser again: known, no email, no new cookie.
	r = tn.front("POST", "/v1/sign-in", obj{"email": "hana@example.com", "password": "some-password"}, "",
		"Cookie", constant.DeviceCookie+"="+device)
	if r.Status != 200 {
		t.Fatalf("sign in again: %d %s", r.Status, r.Raw)
	}
	e.deliver()
	if len(e.mail.to("hana@example.com")) != before+1 {
		t.Fatal("a known device was announced")
	}
	for _, c := range r.Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, constant.DeviceCookie+"=") {
			t.Fatal("a known device got a new id")
		}
	}
	if n := tn.count(`SELECT count(*) FROM aos.devices`); n != 2 {
		t.Fatalf("devices: %d", n)
	}
}

func TestGuestsBecomeUsers(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	tn.back("PUT", "/v1/roles", obj{"name": "Shopper", "permissions": []string{"cart.*"}})

	r := tn.front("POST", "/v1/guest", obj{"name": "Visitor"}, "")
	if r.Status != 200 {
		t.Fatalf("guest: %d %s", r.Status, r.Raw)
	}
	var guest struct {
		User struct {
			ID    string `json:"id"`
			Guest bool   `json:"guest"`
		} `json:"user"`
		SessionToken string `json:"session_token"`
	}
	r.data(&guest)
	if !guest.User.Guest || guest.SessionToken == "" {
		t.Fatalf("guest: %s", r.Raw)
	}
	var me struct {
		User struct {
			ID    string `json:"id"`
			Guest bool   `json:"guest"`
			Email string `json:"email"`
		} `json:"user"`
	}
	tn.front("GET", "/v1/session", nil, guest.SessionToken).data(&me)
	if !me.User.Guest || me.User.ID != guest.User.ID || me.User.Email != "" {
		t.Fatalf("guest session: %+v", me)
	}
	// A guest can hold grants like anyone else.
	if ok, _ := can(t, tn, guest.User.ID, "cart.add", "tenant", "root"); ok {
		t.Fatal("a guest holds a permission nobody gave")
	}
	tn.back("POST", "/v1/grants", obj{"principal_id": guest.User.ID, "role": "Shopper", "resource": obj{"type": "tenant", "id": "root"}})
	if ok, _ := can(t, tn, guest.User.ID, "cart.add", "tenant", "root"); !ok {
		t.Fatal("the guest's grant does not hold")
	}
	// Upgrading keeps the principal, and so the grants.
	if r := tn.front("POST", "/v1/guest/upgrade", obj{"email": "guest@example.com", "password": "some-password", "name": "Dana"}, guest.SessionToken); r.Status != 202 {
		t.Fatalf("upgrade: %d %s", r.Status, r.Raw)
	}
	e.deliver()
	r = tn.front("POST", "/v1/verify-email", obj{"token": e.mail.token("guest@example.com")}, "")
	if r.Status != 200 {
		t.Fatalf("verify: %d %s", r.Status, r.Raw)
	}
	var user authData
	r.data(&user)
	if user.User.ID != guest.User.ID || !user.User.EmailVerified {
		t.Fatalf("upgraded: %+v", user.User)
	}
	me.User.Guest = false
	me.User.Email = ""
	tn.front("GET", "/v1/session", nil, user.SessionToken).data(&me)
	if me.User.Guest || me.User.Email != "guest@example.com" {
		t.Fatalf("after upgrade: %+v", me)
	}
	if ok, _ := can(t, tn, user.User.ID, "cart.add", "tenant", "root"); !ok {
		t.Fatal("the grant was lost in the upgrade")
	}
	if r := tn.signIn("guest@example.com", "some-password"); r.Status != 200 {
		t.Fatalf("sign in as the former guest: %d %s", r.Status, r.Raw)
	}
	// A user cannot upgrade; a guest with a taken address learns nothing.
	if r := tn.front("POST", "/v1/guest/upgrade", obj{"email": "x@example.com", "password": "some-password"}, user.SessionToken); r.code() != "not_a_guest" {
		t.Fatalf("user upgrades: %d %s", r.Status, r.Raw)
	}
	tn.front("POST", "/v1/guest", nil, "").data(&guest)
	if r := tn.front("POST", "/v1/guest/upgrade", obj{"email": "guest@example.com", "password": "some-password"}, guest.SessionToken); r.Status != 202 {
		t.Fatalf("upgrade with a taken address: %d %s", r.Status, r.Raw)
	}
	e.deliver()
	mails := e.mail.to("guest@example.com")
	if !strings.Contains(mails[len(mails)-1].Subject, "Sign-up attempt") {
		t.Fatal("the account's owner was not told")
	}
	if n := tn.count(`SELECT count(*) FROM aos.users WHERE email = 'guest@example.com'`); n != 1 {
		t.Fatalf("users with the address: %d", n)
	}
}

func TestAdminResetsASecondFactor(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	id, session := tn.user("hana@example.com", "some-password")
	enrollTOTP(t, tn, session)
	if r := tn.back("POST", "/v1/users/"+id+"/second-factor/reset", nil); r.Status != 200 {
		t.Fatalf("reset: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("GET", "/v1/session", nil, session); r.Status != 401 {
		t.Fatal("sessions survived the reset")
	}
	var pending pendingData
	r := tn.signIn("hana@example.com", "some-password")
	r.data(&pending)
	if pending.SecondFactorRequired || pending.SessionToken == "" {
		t.Fatalf("sign in after reset: %s", r.Raw)
	}
	e.deliver()
	told := false
	for _, m := range e.mail.to("hana@example.com") {
		if strings.Contains(m.Body, "An administrator did this") {
			told = true
		}
	}
	if !told {
		t.Fatal("no notice of the reset")
	}
}
