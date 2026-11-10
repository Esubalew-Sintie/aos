# AOS identity engine

The server that does sign-up, sign-in and permissions for your app: sessions, second factors, passkeys,
social and enterprise sign-in, organizations, roles and grants, webhooks and an audit log. It is written in
Go and stores everything in Postgres.

Part of **AOS**, an identity and access platform. This repository is the engine; the SDKs and the CLI talk to it.

## Where it fits

| Piece | What it is | Install |
| --- | --- | --- |
| **Engine** (this repo) | The server, and a Go package you can run inside your own backend | see [Get it](#get-it) |
| [`aosctl`](https://github.com/flash-software-technology/aos-cli) | Developer CLI: starter projects, `aosctl dev`, seed data, dev inbox | `go install github.com/flash-software-technology/aos-cli/cmd/aosctl@latest` |
| [`aos-go`](https://github.com/flash-software-technology/aos-go) | Go SDK: check tokens and permissions, manage users | `go get github.com/flash-software-technology/aos-go` |
| [`@aos-auth/js`, `@aos-auth/react`, `@aos-auth/node`](https://github.com/flash-software-technology/aos-js) | Browser, React and Node SDKs | `npm i @aos-auth/react` (etc.) |
| [`aos-auth`](https://github.com/flash-software-technology/aos-python) | Python SDK (PyPI release coming) | `pip install "aos-auth @ git+https://github.com/flash-software-technology/aos-python@v0.4.0"` |

How an app uses the engine:

- **While developing:** `aosctl dev` starts Postgres in Docker and the engine, creates your app, and writes the keys to `.env`.
- **In your own server, with your own database:** a Go backend imports [`embed`](#use-it-in-a-go-app-embed).
  Node (`startLocal()`) and Python (`start_local()`) download the engine release and run it as a child process
  with [`aos app`](#one-apps-engine-aos-app). You do not deploy a separate auth server.

A hosted AOS service is coming; it is built on this engine.

Two kinds of key: the **publishable key** `pk_...` is safe in a browser; the **secret key** `sk_...` stays on your
server. The browser gets a short-lived signed token (a JWT, valid 60 seconds) and sends it to your backend, which
checks it against the engine's public keys.

## What it does

| Area | What is built |
| --- | --- |
| Apps (tenants) | Many apps in one engine, each fully separate (Postgres row-level security); a publishable and a secret key each |
| Sign-up | Email and password with confirmation link, sign-up policy (open, allowed domains, invitation only), default role, leaked-password check, guest accounts that become users |
| Sign-in | Password (with growing delays, lockout, rate limits), one-time email codes, magic links, passkeys, social sign-in via OpenID Connect (Google, Apple, any OIDC issuer) |
| Second factor | Authenticator apps with recovery codes, passkey as second factor, step-up for sensitive permissions, app-wide requirement, admin reset |
| Sessions | Server-side sessions in a `__Host-` cookie, idle and absolute timeouts, device list, sign out everywhere, 60-second signed tokens; token sessions with rotating refresh tokens for mobile apps |
| Account | Forgotten password, change password or email, export, delete with a grace period |
| Users (admin) | Create with a setup link, list, suspend, reinstate, delete, bulk import (Argon2id, bcrypt, scrypt, PBKDF2 hashes) |
| Permissions | Permissions, roles with wildcards (`invoice.*`, `*`), a resource tree, grants with allow/deny/expiry and conditions, groups; `Can`, `CanBatch`, `Explain`, `Filter`, "who may", "what if I remove this grant" |
| Organizations | Create, switch, members and roles, last-owner rule, invitations by email |
| Machines and agents | Service accounts and AI agents with an owner, API keys with scopes and expiry, delegation from a person to an agent, human approval for sensitive agent actions, a kill switch |
| OAuth provider | Your app as an OAuth 2.1 / OpenID Connect provider: PKCE, consent, refresh, client credentials, device flow, token exchange, MCP clients |
| Enterprise | Per-organization OIDC single sign-on set up by the customer's IT admin through a link, DNS-verified domains, SCIM 2.0 directory sync, organization policies, audit export |
| Records | Hash-chained audit log, signed webhooks with retries, before-hooks (e.g. `user.before_create`) that fail closed, encrypted email outbox, encrypted whole-tenant export and import, access reviews |
| Developers | OpenAPI 3.1 document of every route ([`api/openapi.json`](api/openapi.json)), a development inbox at `/dev/mail` |

**Not built yet:** custom domains, sign-in by phone number, GitHub and other OAuth2-only social providers,
SAML sign-in (connections are stored but cannot sign anyone in; use OIDC), scheduled access reviews (start
one from a cron job with `POST /v1/admin/access-reviews`).

## Get it

You need Postgres 15 or newer. To build from source, Go 1.26.3 or newer.

**Release download.** Every `v*` tag publishes binaries on the
[releases page](https://github.com/flash-software-technology/aos/releases) for Linux, macOS and Windows on amd64
and arm64: `aos_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows), plus `checksums.txt` (SHA-256).

```sh
curl -LO https://github.com/flash-software-technology/aos/releases/download/v0.5.0/aos_v0.5.0_linux_amd64.tar.gz
curl -LO https://github.com/flash-software-technology/aos/releases/download/v0.5.0/checksums.txt
sha256sum --ignore-missing -c checksums.txt
tar -xzf aos_v0.5.0_linux_amd64.tar.gz      # aos, LICENSE, README.md
./aos version                                # aos v0.5.0
```

**With `aosctl`.** `aosctl engine install [--version V]` downloads a release into aosctl's cache and checks it.
`aosctl dev` (and the Node and Python SDKs) do this by themselves when no engine is installed.

**Docker.** `ghcr.io/flash-software-technology/aos:<version>` (and `:latest`). A static binary on a distroless
base, running as non-root, listening on `:8080`, command `serve`.

```sh
docker run --rm -p 8080:8080 \
  -e AOS_DATABASE_URL='postgres://user:password@db:5432/aos?sslmode=disable' \
  -e AOS_MASTER_KEY='...' -e AOS_ENV=development \
  ghcr.io/flash-software-technology/aos:v0.5.0
```

**Go package.**

```sh
go get github.com/flash-software-technology/aos@v0.5.0
```

**From source.** `make build` writes `bin/aos`.

## Quick start

The fastest way to see AOS work in an app is the CLI starter (needs Go 1.24+, Docker and Node 22.9+):

```sh
go install github.com/flash-software-technology/aos-cli/cmd/aosctl@latest
aosctl init my-app --frontend react-vite --backend node --published
cd my-app
aosctl dev                                # Postgres + engine; writes .env
```

To run the engine yourself against a Postgres you already have:

```sh
export AOS_DATABASE_URL='postgres://user:password@localhost:5432/aos?sslmode=disable'
export AOS_MASTER_KEY="$(aos keygen)"     # keep this safe: it unlocks every app's keys
export AOS_ENV=development                # emails go to the dev inbox, not SMTP

aos migrate
aos tenant create --slug demo --name "Demo App" --kind multi \
    --app-url http://localhost:3000 --origin http://localhost:3000
aos serve                                 # listens on :8080
```

`tenant create` prints the app's keys. The secret key is shown only once:

```
Tenant created.

  tenant id        ...
  slug             demo
  publishable key  pk_test_...
  secret key       sk_test_...

The secret key is shown only this once. Only its hash is stored.
```

Check it is up: `curl localhost:8080/healthz` (process) and `curl localhost:8080/readyz` (database answers).

## Use it in a Go app: `embed`

`embed` runs the engine **inside your own Go backend**, with its tables in your app's Postgres (in its own
schemas, `aos` and `aos_platform`). There is no separate auth server. On first start it creates the schema and
your app's tenant; after a restart it finds them again.

**Fastest start:** `aosctl init shop --mode embedded --backend go --published` writes a working app (Go backend with the engine inside, React frontend) and `aosctl dev` prepares its database. See the [aosctl README](https://github.com/flash-software-technology/aos-cli#embedded-mode-auth-inside-your-own-backend).

The returned `*embed.Auth` implements the Go SDK's `aos.Auth` interface (`Middleware`, `RequirePermission`,
`Can`, `CreateUser`, ...), answered in-process. Code written against `aos.Auth` works the same with a remote
engine; only the constructor changes.

```sh
go get github.com/flash-software-technology/aos@v0.5.0 github.com/flash-software-technology/aos-go
```

```go
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	aos "github.com/flash-software-technology/aos-go"
	"github.com/flash-software-technology/aos/embed"
)

func main() {
	ctx := context.Background()

	auth, err := embed.New(ctx, embed.Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),         // your app's own Postgres
		MasterKey:   os.Getenv("AOS_MASTER_KEY"),       // make one with: aos keygen
		AppURL:      "http://localhost:3000",           // where your app is reached; email links point here
		Origins:     []string{"http://localhost:5173"}, // other browser origins, e.g. a Vite dev server
		Development: true,                              // emails go to <Path>/dev/mail
	})
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()

	// Declare your permissions and roles. Safe to run on every start.
	if _, err := auth.PutPermission(ctx, aos.Permission{Name: "invoice.read"}); err != nil {
		log.Fatal(err)
	}
	if _, err := auth.PutRole(ctx, aos.Role{Name: "Billing", Permissions: []string{"invoice.*"}}); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// 1. The sign-in routes the browser SDK calls, mounted at /aos.
	mux.Handle(auth.Path()+"/", auth.Handler())

	// 2. Any signed-in person (401 without a valid token).
	mux.Handle("GET /api/me", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := aos.ClaimsFrom(r.Context())
		json.NewEncoder(w).Encode(map[string]string{"user_id": claims.UserID, "org": claims.Organization})
	})))

	// 3. Only people who hold invoice.read in their active organization (403 otherwise).
	invoices := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`[]`)) })
	mux.Handle("GET /api/invoices", auth.Middleware(
		auth.RequirePermission("invoice.read", aos.ActiveOrganization)(invoices)))

	// 4. Ask the question yourself when the resource comes from the request.
	mux.Handle("POST /api/invoices/{id}/refund", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := aos.ClaimsFrom(r.Context())
		res, err := auth.Can(r.Context(), aos.CanRequest{
			PrincipalID: claims.UserID,
			Permission:  "invoice.refund",
			Resource:    aos.Resource{Type: "invoice", ID: r.PathValue("id")},
			SessionID:   claims.SessionID,
		})
		if err != nil {
			http.Error(w, "permission check failed", http.StatusServiceUnavailable)
			return
		}
		if !res.Allowed {
			http.Error(w, res.Reason, http.StatusForbidden) // e.g. no_matching_grant
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))

	// 5. Answers <Protect> in @aos-auth/react.
	mux.Handle("POST /api/aos/can", auth.CanHandler())

	log.Printf("publishable key for the browser: %s", auth.PublishableKey())
	log.Fatal(http.ListenAndServe(":3000", mux))
}
```

In the browser, point `@aos-auth/js` or `@aos-auth/react` at `<AppURL>/aos` (here `http://localhost:3000/aos`).
On your app's own origin the publishable key may be left out; `auth.PublishableKey()` gives it if you need it.
A deny from `Can` is an answer (`Allowed: false` with a `Reason` such as `no_matching_grant`,
`denied_by_grant`, `step_up_required`), not an error.

**`embed.Config`**

| Field | Meaning |
| --- | --- |
| `DatabaseURL` | Your Postgres. Required. |
| `MasterKey` | Base64 of 32 random bytes (`aos keygen` or `engine.NewMasterKey()`). Required. Keep it out of the database and out of git. |
| `AppURL` | Your app's address. Required. Its origin may call the routes from a browser. |
| `Path` | Where `Handler()` is mounted. Default `/aos`. |
| `Origins` | More browser origins allowed, such as a dev server. |
| `Slug`, `Name` | Your app's tenant. Default `app` and `App`. |
| `Kind` | `multi` (with organizations, the default) or `single`. |
| `Development` | Keep email in a dev inbox at `<Path>/dev/mail` when no SMTP is set, and hand sessions to the browser in a header. |
| `Sender` or `SMTPAddr`, `SMTPUsername`, `SMTPPassword`, `MailFrom` | How email is sent. |
| `TrustedProxies` | Networks whose `X-Forwarded-For` is believed. |
| `Logger` | Receives the engine's log. Nil means a default one. |

Other methods on `*embed.Auth`: `Path()`, `Slug()`, `PublishableKey()`, `Engine()` (the engine underneath),
`Close()`. See the [`aos-go` README](https://github.com/flash-software-technology/aos-go) for every SDK method.

### Lower level: `engine`

`engine` is the whole multi-tenant engine as a Go value; the `aos` program and `embed` are built on it.

```go
eng, err := engine.New(ctx, engine.Config{DatabaseURL: dbURL, MasterKey: key, PublicURL: "https://auth.example.com"})
defer eng.Close()
go eng.Run(ctx)                    // delivers email and webhooks
keys, err := eng.CreateTenant(ctx, engine.TenantSpec{Slug: "shop", Name: "Shop", Kind: "multi",
	Environment: "production", AppURL: "https://shop.example.com", Origins: []string{"https://shop.example.com"}})
http.ListenAndServe(":8080", eng.Handler()) // every route: /v1/..., /t/{slug}/..., /scim/v2/...
```

Also: `eng.PublishableKey(ctx, slug)` (returns `engine.ErrNoTenant` if missing), `eng.Transport(slug)` (an
`http.RoundTripper` that calls a tenant's backend routes in-process, no secret key needed), and
`eng.TenantHandler(slug)`.

## One app's engine: `aos app`

`aos app` runs the engine for a single app, started by that app's backend. This is what `startLocal()` in
`@aos-auth/node` and `start_local()` in `aos_auth.local` run for you. It creates or finds the app's tenant, listens
on a local port and prints one line of JSON when ready:

```json
{"url": "http://127.0.0.1:41234", "path": "/aos", "publishable_key": "pk_...", "version": "v0.5.0"}
```

Requests under `--path` come from the browser (your app proxies them). Other requests carrying
`Authorization: Bearer $AOS_LOCAL_TOKEN` are your backend's calls. The parent picks that token: `sk_local_`
followed by at least 32 random characters.

| Flag | Meaning |
| --- | --- |
| `--database-url URL` | Postgres (default `$AOS_DATABASE_URL`) |
| `--app-url URL` | Your app's address; email links point there (required) |
| `--origin URL` | Another browser origin allowed; repeat for several |
| `--path PATH` | Where the browser routes are mounted (default `/aos`) |
| `--listen ADDR` | Default `127.0.0.1:0` (any free port) |
| `--slug`, `--name`, `--kind` | The app's tenant (default `app`, `App`, `multi`) |
| `--development` | Dev inbox for email; hand sessions to the browser |
| `--exit-with-stdin` | Stop when standard input closes (the parent is gone) |

Environment: `AOS_MASTER_KEY` and `AOS_LOCAL_TOKEN` (both required), `AOS_SMTP_*` and `AOS_MAIL_FROM` for email.

## Commands

`aos help` prints this list. With no command, `aos` runs `serve`.

| Command | What it does |
| --- | --- |
| `aos serve` | Run the HTTP API (applies pending migrations first) |
| `aos migrate` | Create or upgrade the database schema. Needs no master key. |
| `aos tenant create --slug S --name N [--kind single\|multi] [--env development\|staging\|production] [--app-url URL] [--origin URL]...` | Create an app (tenant) and print its keys. `--kind` defaults to `single`, `--env` to `development`. |
| `aos owner create --tenant S --email E [--name N]` | Create a tenant's first admin. They get a setup link by email (printed to the terminal in development). |
| `aos keygen` | Print a new master key for `AOS_MASTER_KEY` |
| `aos version` | Print the release this program was built from |
| `aos app ...` | Run the engine for one app (see above; `aos app -h`) |
| `aos doctor` | Check configuration, database, schema, database roles, and that the master key opens every tenant's keys |
| `aos openapi` | Print the OpenAPI document |
| `aos permissions sync --tenant S --file permissions.json` | Apply the permissions and roles an app declares |
| `aos export --tenant S --out FILE` | Write an encrypted archive of a tenant (passphrase from `AOS_ARCHIVE_PASSPHRASE`) |
| `aos import --tenant S --in FILE` | Fill an empty tenant from an archive |

A `permissions.json` file:

```json
{"permissions": [{"name": "payment.refund", "step_up_seconds": 300}],
 "roles": [{"name": "Finance", "permissions": ["payment.*"]}]}
```

## Configuration

Used by `aos serve` and the other commands (`embed` and `aos app` take their settings as shown above).

| Variable | Default | Meaning |
| --- | --- | --- |
| `AOS_DATABASE_URL` | — | Postgres connection string. Required. |
| `AOS_MASTER_KEY` | — | Wraps every tenant's keys. Required except for `migrate`. **Losing it makes every tenant's secrets unreadable.** |
| `AOS_ENV` | `production` | `production` or `development` |
| `AOS_LISTEN_ADDR` | `:8080` | Where the API listens |
| `AOS_PUBLIC_URL` | `http://localhost:8080` | The address the engine is reached at (OAuth issuer, SCIM). `aos doctor` wants `https://` in production. |
| `AOS_TRUSTED_PROXIES` | empty | Comma-separated networks whose `X-Forwarded-For` is believed, e.g. `10.0.0.0/8` |
| `AOS_SMTP_ADDR` | — | `host:port` of the SMTP server. In production the engine refuses to start without it. |
| `AOS_SMTP_USERNAME`, `AOS_SMTP_PASSWORD` | — | SMTP login |
| `AOS_MAIL_FROM` | — | The address emails are sent from |
| `AOS_BREACH_CHECK` | `local` | `local` (built-in leaked-password list) or `hibp` (also asks Have I Been Pwned) |
| `AOS_ARCHIVE_PASSPHRASE` | — | Passphrase for `aos export` / `aos import` |

**Development inbox.** With `AOS_ENV=development` and no SMTP, no email is sent. The engine keeps the last 200
in memory: `GET /dev/mail?to=<address>` lists them newest first with the link, token and code pulled out, and
`DELETE /dev/mail` empties it. Only callers on the same machine are answered, and the route does not exist in
production. `aosctl mail` reads it.

**Database roles.** The role the engine connects as must be a member of `aos_app` and `aos_platform`. The role
that runs `aos migrate` becomes one automatically.

## The API

Full reference: [`api/openapi.json`](api/openapi.json) (156 paths; also `aos openapi`). Every JSON answer has the
same envelope: `{"status", "message", "data", "error"}`.

There are three kinds of caller:

- **Frontend routes**: from a browser or mobile app. Send the publishable key in `X-AOS-Publishable-Key`. The
  session is the `__Host-aos_session` cookie (a development tenant may also use the `X-AOS-Session` header; a
  token session sends `Authorization: Bearer <token>`).
- **Backend routes**: from your server. Send the secret key as `Authorization: Bearer sk_...`. Any request with
  an `Origin` header (i.e. from a browser) is refused.
- **Public protocol routes**: OAuth/OIDC (`/t/{slug}/...`) and SCIM (`/scim/v2/...`), which answer in their
  protocol's own format.

| Group | Routes | Caller |
| --- | --- | --- |
| Sign-up and sign-in | `/v1/sign-up`, `/v1/verify-email`, `/v1/sign-in`, `/v1/sign-out`, `/v1/sign-out-all`, `/v1/code/send`, `/v1/code/verify`, `/v1/magic-link`, `/v1/passkey/*`, `/v1/oauth/{provider}/start\|finish`, `/v1/guest`, `/v1/guest/upgrade`, `/v1/second-factor`, `/v1/step-up` | frontend |
| Session | `/v1/session`, `/v1/session/token` (the 60-second token for your backend), `/v1/sessions`, `/v1/token/refresh`, `/v1/jwks.json` | frontend |
| Account | `/v1/password/*`, `/v1/email/change\|confirm`, `/v1/account/setup`, `/v1/me`, `/v1/me/export`, `/v1/me/factors`, `/v1/me/totp/*`, `/v1/me/recovery-codes`, `/v1/me/passkeys/*`, `/v1/me/identities/*`, `/v1/me/consents/*` | frontend |
| Organizations | `/v1/organizations/*` (members, roles, invitations, switch, policies), `/v1/invitations/*` | frontend; `/v1/admin/organizations/*` from the backend |
| Permission questions | `/v1/can`, `/v1/can/batch`, `/v1/explain`, `/v1/filter`, `/v1/principals`, `/v1/simulate` | backend |
| Permission setup | `/v1/permissions`, `/v1/roles`, `/v1/resources`, `/v1/grants`, `/v1/groups/*` | backend |
| Users | `/v1/users`, `/v1/users/{id}`, `…/suspend`, `…/reinstate`, `…/second-factor/reset`, `/v1/import/users` | backend |
| Machines and agents | `/v1/service-accounts`, `/v1/agents`, `/v1/machines/{id}/*`, `/v1/api-keys/*`, `/v1/approvals/{id}`; people's own: `/v1/me/api-keys`, `/v1/me/delegations`, `/v1/me/approvals` | backend / frontend |
| Integrations | `/v1/webhooks`, `/v1/oauth-providers` (social sign-in), `/v1/oauth-clients` (apps that sign in with yours) | backend |
| OAuth provider | `/t/{slug}/.well-known/openid-configuration`, `/t/{slug}/oauth/authorize\|token\|device\|userinfo\|introspect\|revoke\|jwks.json`; consent pages use `/v1/oauth/requests/{id}`, `/v1/oauth/consent`, `/v1/oauth/device/approve` | public |
| Enterprise SSO | `/v1/sso/connections/*` (or `/v1/admin/sso/*`), `/v1/sso/setup/{token}/*` (IT admin's setup page), `/v1/sso/start`, `/v1/sso/finish` | frontend / backend / setup link |
| Directory sync | `/scim/v2/Users`, `/scim/v2/Groups` with the sync token | public (SCIM) |
| Moving and reviewing | `/v1/export`, `/v1/import/archive`, `/v1/access-reviews/*` (or `/v1/admin/access-reviews/*`) | backend / frontend |
| Operations | `/healthz`, `/readyz`, `/dev/mail` (development only, same machine only) | anyone |

The top of every tenant's resource tree is `{"type": "tenant", "id": "root"}`. Organization actions in the
frontend routes check AOS's own permissions, such as `aos.member.invite` and `aos.grant.manage`, which the
`Owner` role holds through `*`.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `aos: AOS_DATABASE_URL is not set` / `AOS_MASTER_KEY is not set` | Export them. Make a master key with `aos keygen` and keep it; a new one cannot read existing tenants. |
| `aos app: AOS_LOCAL_TOKEN must be sk_local_ followed by at least 32 random characters` | Set `AOS_LOCAL_TOKEN` (the SDKs do this for you). |
| Engine refuses to start in production, about email | Set `AOS_SMTP_ADDR` and `AOS_MAIL_FROM`, or use `AOS_ENV=development` locally. |
| `401 invalid_key` | The key is missing or wrong, or the wrong kind: frontend routes want `pk_...` in `X-AOS-Publishable-Key`; backend routes want `sk_...` as a bearer token. |
| `403 origin_not_allowed` | The browser's origin is not allowed. Add it with `--origin` on `tenant create`, `Origins` in `embed.Config`, or `--origin` on `aos app`. A secret key sent from a browser also gets this. |
| `401` vs `403` from your own backend | `401 unauthenticated`: no valid token (not signed in, or it expired; tokens live 60 seconds). `403`: signed in but the permission was denied; the reason (e.g. `no_matching_grant`, `step_up_required`) says why. |
| No emails arrive in development | They are in the dev inbox: `aosctl mail`, or `GET /dev/mail?to=you@example.com` (with `embed`, `<Path>/dev/mail`) from the same machine. |
| Anything else | Run `aos doctor`. |

## Developing the engine

The folders follow the layered layout used across our Go backends:

```
cmd/              the aos program (main.go, app.go for `aos app`)
engine/  embed/   the public Go packages
initiator/        wiring: config, database, modules, routes, CLI commands, extensions
internal/
  constant/       request/response DTOs, errors, models
  glue/routing/   which URL goes to which handler (also feeds the OpenAPI document)
  handler/        middleware and HTTP handlers
  module/         business logic per area (tenant, auth, iam, notification, ...)
  storage/        repositories and SQL
platform/         config, logger, postgres, secret, jwt, mailer, testdb
schema/           SQL migrations
api/openapi.json  saved OpenAPI document
scripts/          test.sh, release.sh
tests/            tests that drive the engine through its HTTP routes
```

A request goes `handler` → `module` → `storage`. Handlers never touch the database. Repositories never pick the
tenant: the module opens a transaction through `platform/postgres`, which scopes it to one tenant.

```sh
make build        # bin/aos
make test         # all tests against a throwaway Postgres in Docker (no volume, random port), then removes it
make vet          # go vet
make fmt          # gofmt
make image        # docker build -t aos:local .
scripts/release.sh v0.5.0   # the release archives and checksums.txt, into dist/
```

`go test ./...` on its own runs only the tests that need no database and skips the rest. With
`AOS_TEST_DATABASE_URL` set, each test creates and drops its own randomly named database; **never point it at a
server holding real data.** After changing routes, refresh the saved spec with
`go run ./cmd openapi > api/openapi.json` (a test fails if they disagree). CI (`.github/workflows/ci.yml`) runs
`gofmt`, `go vet` and the tests; `release.yml` publishes binaries and the image on each `v*` tag.

A local `go.work` (not committed) may point `aos-go` at a checkout next to this one; while it is in use, don't run
`go mod tidy` here.

**Extensions.** A build can add files that call `initiator.RegisterExtension` from an `init` function to add
routes, `aos` subcommands, a usage meter (counting and limiting what tenants do), and migrations numbered from
10000 (run after the engine's own). The hosted service is built this way. Without an extension the engine has no
usage limits and only the routes above.

## Licence

The engine is under the [Business Source License 1.1](LICENSE). You may use it in production for your own
applications, including ones you provide to your customers. You may not offer it to other companies as a hosted
identity, authentication or authorization service. Each version becomes Apache-2.0 four years after its release.
The SDKs and the CLI are Apache-2.0.
