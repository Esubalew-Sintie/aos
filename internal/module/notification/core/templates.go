// Package core holds the message templates.
package core

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/flash-softeware/aos/internal/constant"
)

// Each template is plain text and English only. Translations come with
// milestone M4. A template may use:
//
//	{{.app}}    the application's name
//	{{.link}}   a link that carries the token, when the tenant has an address
//	{{.token}}  the raw token, for a tenant with no address set
type entry struct {
	subject string
	body    string
}

var templates = map[string]entry{
	constant.TemplateVerifyEmail: {
		subject: "Confirm your email address for {{.app}}",
		body: `Someone signed up for {{.app}} with this email address.

To finish signing up, confirm your address:
{{if .link}}{{.link}}{{else}}Verification code: {{.token}}{{end}}

This works once and expires in 24 hours.
If this was not you, ignore this email. No account is created unless the address is confirmed.
`,
	},
	constant.TemplateExistingAccount: {
		subject: "Sign-up attempt for {{.app}}",
		body: `Someone tried to sign up for {{.app}} with this email address.

You already have an account. Sign in, or reset your password if you have forgotten it.
If this was not you, you do not need to do anything.
`,
	},
	constant.TemplatePasswordReset: {
		subject: "Reset your password for {{.app}}",
		body: `A password reset was requested for your {{.app}} account.

Choose a new password:
{{if .link}}{{.link}}{{else}}Reset code: {{.token}}{{end}}

This works once and expires in 30 minutes.
If this was not you, ignore this email. Your password stays as it is.
`,
	},
	constant.TemplatePasswordChanged: {
		subject: "Your {{.app}} password was changed",
		body: `The password of your {{.app}} account was just changed, and you were signed out everywhere.

If this was not you, reset your password now and contact support.
`,
	},
	constant.TemplateAccountSetup: {
		subject: "Set up your {{.app}} account",
		body: `An account was created for you in {{.app}}.

Choose your password here:
{{if .link}}{{.link}}{{else}}Setup code: {{.token}}{{end}}

This works once and expires in 1 hour. Nobody else has seen or set a password for you.
If you were not expecting this, ignore this email.
`,
	},
	constant.TemplateEmailChange: {
		subject: "Confirm your new email address for {{.app}}",
		body: `Someone asked to move a {{.app}} account to this email address.

To confirm, open this link:
{{if .link}}{{.link}}{{else}}Confirmation code: {{.token}}{{end}}

This works once and expires in 24 hours.
If this was not you, ignore this email. Nothing changes unless the link is opened.
`,
	},
	constant.TemplateEmailChangeNote: {
		subject: "A change of email was requested for your {{.app}} account",
		body: `Someone signed in to your {{.app}} account asked to change its email address to {{.new_email}}.

Nothing changes until the new address is confirmed.
If this was not you, sign in now and change your password. That cancels the request and signs out every other device.
`,
	},
	constant.TemplateSecondFactorEnabled: {
		subject: "Two-step sign-in is on for your {{.app}} account",
		body: `An authenticator app was added to your {{.app}} account. From now on, signing in needs a code from it.

Keep your recovery codes somewhere safe. They are the way back in if you lose the app.
If this was not you, sign in, end every session, and change your password.
`,
	},
	constant.TemplateSecondFactorDisabled: {
		subject: "Two-step sign-in is off for your {{.app}} account",
		body: `The authenticator app was removed from your {{.app}} account.{{if .by_admin}} An administrator did this.{{end}}

If this was not you, sign in, end every session, and change your password.
`,
	},
	constant.TemplateRecoveryCodeUsed: {
		subject: "A recovery code was used on your {{.app}} account",
		body: `One of your recovery codes was used to sign in to {{.app}}. You have {{.left}} left.

If this was you, consider creating new codes from your account settings.
If this was not you, sign in, end every session, and change your password.
`,
	},
	constant.TemplateSignInCode: {
		subject: "Your {{.app}} sign-in code: {{.code}}",
		body: `Your sign-in code for {{.app}} is:

{{.code}}
{{if .link}}
Or open this link in the browser you are signing in from:
{{.link}}
{{end}}
It works once and expires in 10 minutes. If you did not ask for it, ignore this email.
`,
	},
	constant.TemplateNewDevice: {
		subject: "New sign-in to your {{.app}} account",
		body: `Your {{.app}} account was just used to sign in from a new device.

When:    {{.when}}
Browser: {{.browser}}
Address: {{.address}}

If this was you, there is nothing to do.
If this was not you, sign in, end every session, and change your password.{{if .link}} You can start here:
{{.link}}{{end}}
`,
	},
	constant.TemplateTokenReused: {
		subject: "Your {{.app}} app was signed out for safety",
		body: `A sign-in token for your {{.app}} account was used twice, which means a copy of it may exist. To be safe, that sign-in was ended everywhere it was in use.

Sign in again in the app. If you did not expect this, change your password too.
`,
	},
	constant.TemplateApprovalRequested: {
		subject: "{{.agent}} asks your approval: {{.permission}}",
		body: `The agent {{.agent}} wants to do something that needs your approval in {{.app}}.

Action:   {{.permission}}
Where:    {{.resource}}
Details:  {{.details}}

It waits for one hour. Approve or decline it in the application.{{if .link}}
{{.link}}{{end}}
If you do not know this agent, decline it and tell an administrator.
`,
	},
	constant.TemplateInvitation: {
		subject: "{{.inviter}} invited you to {{.organization}} on {{.app}}",
		body: `{{.inviter}} invited you to join {{.organization}} on {{.app}} as {{.role}}.

To accept, open this link:
{{if .link}}{{.link}}{{else}}Invitation code: {{.token}}{{end}}

It is for this email address only and expires in 7 days.
If you do not know {{.organization}}, ignore this email.
`,
	},
	constant.TemplateAccountLocked: {
		subject: "Your {{.app}} account is temporarily locked",
		body: `There were too many failed attempts to sign in to your {{.app}} account, so sign-in is paused for 15 minutes.

If this was you, wait and try again, or reset your password.
If this was not you, your password was not guessed. You may still want to choose a new one.
`,
	},
}

var parsed = func() map[string][2]*template.Template {
	out := map[string][2]*template.Template{}
	for name, e := range templates {
		out[name] = [2]*template.Template{
			template.Must(template.New(name + ".subject").Option("missingkey=zero").Parse(e.subject)),
			template.Must(template.New(name + ".body").Option("missingkey=zero").Parse(e.body)),
		}
	}
	return out
}()

// Register adds a template. An extension calls it from an init function,
// for messages only it sends. A name that exists already is replaced.
func Register(name, subject, body string) {
	parsed[name] = [2]*template.Template{
		template.Must(template.New(name + ".subject").Option("missingkey=zero").Parse(subject)),
		template.Must(template.New(name + ".body").Option("missingkey=zero").Parse(body)),
	}
}

// Render fills a template. data must hold "app"; "link" and "token" are optional.
func Render(name string, data map[string]string) (subject, body string, err error) {
	t, ok := parsed[name]
	if !ok {
		return "", "", fmt.Errorf("notification: unknown template %q", name)
	}
	var s, b bytes.Buffer
	if err := t[0].Execute(&s, data); err != nil {
		return "", "", fmt.Errorf("notification: render %s: %w", name, err)
	}
	if err := t[1].Execute(&b, data); err != nil {
		return "", "", fmt.Errorf("notification: render %s: %w", name, err)
	}
	return s.String(), b.String(), nil
}
