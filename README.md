# AOS identity engine

The hosted AOS service, written in Go: sign-in and fine-grained permissions in one engine, for many applications at once. Each application is a tenant and shares nothing with the others.

It runs as the `aos` server, or inside a Go program (`engine`, `embed`). The hosted AOS service is built on it in a separate, private repository that adds its own routes and limits through an extension point (see "Extensions" below).

## What works today

| Area | What is built | Flows |
| --- | --- | --- |
| Tenants | Create a tenant with its keys, find the tenant behind a key, two doors (publishable key and secret key) | SYS-1 to SYS-3, HOST-3 |
| Sign-up | Email and password, confirmation link, the same answer whether or not the account exists, sign-up policy (open, domains, invitation only), default role, leaked-password check, `user.before_create` hook | REG-1 to REG-4 |
| Sign-in | Password sign-in, growing delays and lockout, rate limits per address; one-time codes and magic links by email; passkeys bound to the application's domain, with no email typed; social sign-in through OpenID Connect with account linking by verified address; guest accounts that become users | SIGN-1, SIGN-3 to SIGN-5, SIGN-10, REG-5, REG-8 |
| Second factor | Authenticator apps with recovery codes, a pending sign-in that applies to every method, a passkey as the second factor, step-up for permissions that need a fresh factor, an application-wide requirement, an admin reset | SIGN-2, SIGN-9 |
| Sessions | Server-side sessions, host-locked cookie, idle and absolute timeouts, sign-out, the device list, sign out everywhere, the 60-second signed token (with the active organization) and its public keys; token sessions for mobile apps with refresh families and reuse detection; a remembered device and an email for a new one | SYS-4, SIGN-6 to SIGN-8, SIGN-11 |
| Account | Forgotten password and reset, change password, change email with confirmation, export, delete with a grace period | ACC-1 to ACC-5 |
| Users (admin) | Create a user with a setup link, list, get, suspend, reinstate, delete | ADM-1 to ADM-3 |
| Permissions | Permissions, roles with wildcards, the resource tree, grants with allow, deny and expiry, groups, the `Can` check and its decision log | PERM-1, PERM-2, PERM-8 to PERM-12 |
| Questions | `CanBatch`, `Explain`, `Filter`, `ListPrincipals`, `Simulate` | PERM-3 to PERM-7 |
| Organizations | Create (self-service, admin only, or by the application), list, switch, delete; members, role changes, the last-owner rule, "nobody gives more than they hold"; invitations bound to one address, with sign-up or sign-in at the other end | ORG-1 to ORG-11, WHO-1 to WHO-4 |
| Machines | Service accounts and agents with an owner and a purpose; API keys with a readable prefix, scopes that only narrow, expiry, revocation and a per-key rate limit; one call that identifies a key and answers its permission question; delegations from a person to an agent (the person must hold it, the delegation must cover it, and it must not have expired); human approval for an agent's sensitive actions, bound to the exact values and usable once; the agent's own audit trail and a single kill switch | MACH-1 to MACH-4, MACH-8 to MACH-10 |
| OAuth provider | The tenant as an OAuth 2.1 and OpenID Connect provider under `/t/{slug}`: discovery, registered clients (confidential and public), the authorization code grant with PKCE and the application's own consent page, identity and access tokens signed with the tenant's keys, rotating refresh tokens with reuse detection, userinfo, introspection, revocation, remembered consents the person can withdraw, client credentials for service accounts, the device flow, token exchange for an agent's delegation, and MCP clients that identify with a Client ID Metadata Document | MACH-5 to MACH-8 |
| Enterprise | Per-organization OpenID Connect connections to a company's identity provider, set up by its IT admin through a link with no account (settings, group-to-role mappings, a test sign-in, activation); DNS-verified domains, one owner each; sign-in by work email with accounts made or linked only in verified domains and roles following the company's groups; SCIM 2.0 directory sync of users and groups; organization policies (second factor, session length, sign-in methods, address allow-list on every request, required enterprise sign-in with a break-glass owner); per-organization audit export | ENT-1 to ENT-8 |
| Conditions | Grant conditions in a small CEL-like language read from the check's `context`; a conditional deny applies when it holds | PERM-9 |
| Moving people | Bulk user import with Argon2id, bcrypt, scrypt or PBKDF2 hashes (replaced by Argon2id at first sign-in) and roles; an encrypted, passphrase-sealed archive of a whole tenant (permissions, roles, tree, organizations and policies, people with password hashes, authenticator seeds, recovery codes and passkeys, groups, grants) that fills an empty tenant elsewhere, with the new audit chain naming the old head | SET-4, HOST-6 |
| Access reviews | A snapshot of every grant in an organization; each line kept or removed by a reviewer; the review completes when every line is decided | ADM-6 |
| Records | Hash-chained audit log, events written with each change, encrypted email outbox with retries, signed webhooks with retries, before-hooks that fail closed | ADM-4, ADM-5, SET-5 |
| Isolation | Every query runs inside one tenant's scope, enforced by Postgres row-level security | HOST-5 |
| Developers | An OpenAPI 3.1 document of every route (`aos openapi`, kept in `api/openapi.json` and checked by a test); a development inbox at `/dev/mail` that keeps the emails a development engine would send; sign-in for the developer CLI through the device flow; read routes for the permission catalog | SDK, CLI |

The SDKs (`@aos-auth/js`, `@aos-auth/react`, `@aos-auth/node`, `aos-go`, `aos-auth` for Python) are in [../sdk/](../sdk/README.md); the developer CLI `aosctl` and its starter projects are in [../cli/](../cli/README.md).

## What is not built yet

Nothing below is exposed as a route. It is simply absent.

- Custom domains for the API and for email (HOST-4), and billing (HOST-7 beyond limits and counts).
- Sign-in with a phone number (REG-6), GitHub and other OAuth2-only providers (social sign-in is OpenID Connect: Google, Apple and any `oidc` issuer). Organization policies are enforced at sign-in through enterprise connections and when switching in, not yet on every sign-in method (SIGN-12).
- SAML connections are stored but cannot sign anyone in yet; use OpenID Connect.
- Scheduled access reviews: a review is started by a call, so a schedule is a cron job that calls `POST /v1/admin/access-reviews`.
- The container image is described (`Dockerfile`) but its final stage has not been built here, because this machine could not reach the base image registry.

## Get it

Each `v*` tag publishes the engine on the [releases page](https://github.com/flash-software-technology/aos/releases): `aos_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) for Linux, macOS and Windows on amd64 and arm64, with `checksums.txt`; and the image `ghcr.io/flash-software-technology/aos:<version>`. `scripts/release.sh v0.5.0` builds the same archives locally. `aos version` prints the release a program was built from.

`aosctl dev` and the Node and Python SDKs download the release they are tested with when no engine is installed, and check it against `checksums.txt`.

## One application's engine: `aos app`

`aos app` runs the engine for a single application, started by that application's backend; the Node and Python SDKs do this (`startLocal`, `start_local`). It makes or finds the application's tenant, listens on a local address, and prints one line of JSON when ready (`url`, `path`, `publishable_key`, `version`). Requests under `--path` (default `/aos`) are the browser's, which the application proxies. Other requests that carry `Authorization: Bearer $AOS_LOCAL_TOKEN` are the application's backend calls; the parent chooses that token (`sk_local_` and at least 32 random characters) and nothing else knows it. With `--exit-with-stdin` it stops when the parent goes away. `aos app -h` lists the flags.

## Use it as a Go package

The engine can also run inside a Go program instead of as the `aos` server.

- **`engine`** is the whole engine, many tenants: `engine.New(ctx, engine.Config{DatabaseURL, MasterKey, PublicURL, ...})`, then `Handler()` for every route, `Run(ctx)` for email and webhook delivery, `CreateTenant`, `PublishableKey`, and `Transport(slug)`, which serves a tenant's backend routes inside the process. The `aos` program and the hosted service are built on it.
- **`embed`** puts the engine inside one application's own backend, with its users in the application's Postgres:

```go
auth, err := embed.New(ctx, embed.Config{
    DatabaseURL: os.Getenv("DATABASE_URL"),
    MasterKey:   os.Getenv("AOS_MASTER_KEY"),   // engine.NewMasterKey() makes one
    AppURL:      "https://shop.example.com",
})
defer auth.Close()
mux.Handle("/aos/", auth.Handler())               // the browser SDK points at https://shop.example.com/aos
mux.Handle("GET /api/invoices", auth.Middleware(auth.RequirePermission("invoice.read", aos.ActiveOrganization)(invoices)))
```

  The application's tenant is made on first start and found again after a restart. `Auth` has every method of the Go SDK's client (`aos.Auth`: `Middleware`, `RequirePermission`, `Can`, `CreateUser`, `CanHandler`, ...), answered inside the process, so code written for the hosted service needs only a different constructor. A browser on the application's own origin may leave the publishable key out; `auth.PublishableKey()` gives it for the SDK's configuration.

The backend routes accept an in-process call (a marker in the request's context, which no network request can carry) in place of the secret key. From the network they still require the secret key.

`embed` uses the Go SDK (`github.com/flash-software-technology/aos-go`) for its types. Until that module is published, `go.work` in this folder points at `../sdk/go`. `go.work` is for this machine only and stays out of the engine's repository; while it is needed, do not run `go mod tidy` here, and the Docker and CI builds cannot work outside this checkout.

## Extensions

A build may add files to the engine's packages that register an extension (`initiator.RegisterExtension`): a usage meter that counts and limits what tenants do, extra routes, extra `aos` subcommands, and migrations numbered from 10000 (they run after every engine migration). The hosted service is built this way. Without an extension, the engine has no usage limits and only the routes listed here. The `aos_platform` database role is the engine's own: it manages tenants as accounts and cannot read inside them.

## Layout

The folders follow the same layers as `IDASS/backend`.

```
cmd/main.go                 starts the program
initiator/                  wires everything: config, database, storage, modules, handlers, routes
internal/
  constant/                 shared constants
    dto/request/            what the API accepts, and its validation
    dto/response/           what the API sends back
    errors/                 the error model
    model/                  plain data passed between storage and modules
  glue/routing/             which URL goes to which handler
  handler/
    middleware/             tenant keys, request id, recovery, access log
    rest/                   handler interfaces
    rest/http/<area>/       handler implementations
  module/                   business logic: tenant, auth, iam, notification
    <area>/core/            small pure rules of that area
  storage/                  repository interfaces, and the SQL per area
platform/                   shared infrastructure
  config/  logger/  postgres/  secret/  jwt/  mailer/  utils/  testdb/
schema/                     the database migrations, as SQL
scripts/test.sh             runs the tests against a throwaway Postgres
tests/                      tests that drive the engine through its HTTP routes
```

A request goes `handler` → `module` → `storage`. A handler never touches the database. A repository never decides which tenant it reads: the module opens the transaction through `platform/postgres`, which scopes it to one tenant.

## Run it

You need Go 1.26.3 or newer and Postgres 15 or newer.

```bash
make build

export AOS_DATABASE_URL='postgres://user:password@localhost:5432/aos?sslmode=disable'
export AOS_MASTER_KEY="$(bin/aos keygen)"   # keep this: it unlocks every tenant's keys
export AOS_ENV=development                   # emails are kept in the development inbox

bin/aos migrate
bin/aos tenant create --slug demo --name "Demo App" --kind multi \
    --app-url http://localhost:3000 --origin http://localhost:3000
bin/aos serve
```

`tenant create` prints a publishable key and a secret key. The secret key is shown once.

For an application's own development, `aosctl dev` (in [../cli/](../cli/README.md)) does all of this in one step, with Postgres in Docker, and writes the keys to `.env`.

**Development inbox.** With `AOS_ENV=development` and no SMTP settings, the engine sends no email. It keeps the last 200 in memory, and `GET /dev/mail?to=<address>` lists them newest first with the links, token and code pulled out. `DELETE /dev/mail` empties it. Both answer only callers on this machine (loopback), and neither exists in production. `aosctl mail` reads it.

The database role the engine connects as must be a member of `aos_app` and `aos_platform`. The role that runs `aos migrate` becomes one automatically.

### Settings


| Variable | Meaning |
| --- | --- |
| `AOS_DATABASE_URL` | Postgres connection string. Required. |
| `AOS_MASTER_KEY` | Wraps every tenant's keys. Required, except for `migrate`. Losing it makes every tenant's secrets unreadable. |
| `AOS_ENV` | `production` (the default) or `development` |
| `AOS_LISTEN_ADDR` | Default `:8080` |
| `AOS_TRUSTED_PROXIES` | Networks whose `X-Forwarded-For` is believed, such as `10.0.0.0/8`. Empty means none. |
| `AOS_SMTP_ADDR`, `AOS_SMTP_USERNAME`, `AOS_SMTP_PASSWORD`, `AOS_MAIL_FROM` | How email is sent. In production the engine refuses to start without them. |

## The API

Every answer has the same envelope: `{"status", "message", "data", "error"}`.

**Frontend routes.** Called from a browser or a mobile app. Send the publishable key in `X-AOS-Publishable-Key`. The session travels in the `__Host-aos_session` cookie. A development tenant also receives it in the answer and may send it back in `X-AOS-Session`.

| Route | Purpose |
| --- | --- |
| `POST /v1/sign-up` | `{email, password, name}`. Always answers 202. |
| `POST /v1/verify-email` | `{token}`. Confirms the address and signs in. |
| `POST /v1/sign-in` | `{email, password}` |
| `POST /v1/sign-out`, `POST /v1/sign-out-all` | End this session, or every session |
| `GET /v1/session` | Who is signed in, and the active organization |
| `POST /v1/session/token` | A signed token, valid 60 seconds, for the application's own backend. Carries `org` when an organization is active. |
| `GET /v1/sessions`, `DELETE /v1/sessions/{id}` | The device list |
| `POST /v1/password/forgot`, `POST /v1/password/reset`, `POST /v1/password/change` | Password reset and change |
| `POST /v1/email/change`, `POST /v1/email/confirm` | Change the email address |
| `POST /v1/account/setup` | `{token, password}`. Finishes an account made by an admin. |
| `POST /v1/me/export`, `DELETE /v1/me` | `{password}`. Export and delete the account. |
| `POST /v1/organizations`, `GET /v1/organizations`, `GET /v1/organizations/{id}`, `DELETE /v1/organizations/{id}` | The person's organizations |
| `POST /v1/organizations/{id}/switch` | Work in this organization |
| `GET /v1/organizations/{id}/members` | Members and their roles |
| `PUT /v1/organizations/{id}/members/{principal_id}/role` | `{role}`. Change a member's role. |
| `DELETE /v1/organizations/{id}/members/{principal_id}` | Remove a member, or leave |
| `POST /v1/organizations/{id}/invitations`, `GET …/invitations`, `DELETE …/invitations/{invitation_id}` | `{email, role, resource?}`. Invite, list, withdraw. |
| `GET /v1/invitations/{token}` | What an invitation is for, and whether the address has an account |
| `POST /v1/invitations/accept`, `POST /v1/invitations/decline` | `{token}`. Accept needs a session with the invited address. |
| `POST /v1/invitations/sign-up` | `{token, password, name}`. Creates the account and joins. |
| `POST /v1/second-factor` | `{pending_token, method, code}` or `{pending_token, method: "passkey", challenge_id, credential}`. Finishes a sign-in that stopped after the first factor. |
| `GET /v1/me/factors`, `POST /v1/me/totp`, `POST /v1/me/totp/confirm`, `POST /v1/me/totp/disable`, `POST /v1/me/recovery-codes` | Authenticator app and recovery codes. Confirm, disable and new codes take `{code}`. |
| `POST /v1/step-up` | `{code}`. Makes the session's second factor fresh for a permission that needs one. |
| `POST /v1/code/send`, `POST /v1/code/verify`, `POST /v1/magic-link` | `{email}`, `{email, code}`, `{token}`. Sign-in by email without a password. |
| `POST /v1/me/passkeys/options`, `POST /v1/me/passkeys`, `GET /v1/me/passkeys`, `DELETE /v1/me/passkeys/{id}` | Add, list and remove passkeys. The add step takes `{challenge_id, name, credential}`. |
| `POST /v1/passkey/options`, `POST /v1/passkey/sign-in` | Sign in with a passkey: `{challenge_id, credential}`. No email is typed. |
| `POST /v1/oauth/{provider}/start`, `POST /v1/oauth/{provider}/finish` | `{redirect_uri}` gives the provider's address; `{state, code}` finishes. With a session, the provider is linked instead. |
| `GET /v1/me/identities`, `DELETE /v1/me/identities/{provider}` | Linked provider accounts |
| `POST /v1/token/refresh` | `{refresh_token}`. A new pair for a token session. Sign in with `"session_kind": "token"` to get one. |
| `POST /v1/guest`, `POST /v1/guest/upgrade` | A guest session; then `{email, password, name}` to become a user |
| `POST`, `GET /v1/me/api-keys`, `DELETE /v1/me/api-keys/{id}` | A person's own keys |
| `POST`, `GET /v1/me/delegations`, `DELETE /v1/me/delegations/{id}` | `{agent_id, scopes, resource, hours}`. Let an agent act for you. |
| `GET /v1/me/approvals`, `POST /v1/me/approvals/{id}/approve`, `…/decline` | Decide an agent's request. Approving needs a fresh second factor when you have one. |
| `GET /v1/jwks.json` | The public keys that verify the signed token |

A token session sends its access token as `Authorization: Bearer <token>` on the frontend routes. A permission saved with `step_up_seconds` is denied with the reason `step_up_required` unless the check names a `session_id` whose second factor is fresh enough.

Behind the frontend door a person is bound by their grants. Organization actions check AOS's own permissions, such as `aos.member.invite` and `aos.grant.manage`, which the `Owner` role holds through `*`.

**Backend routes.** Called from the application's own server. Send the secret key as `Authorization: Bearer <key>`. A request that comes from a browser is refused.

| Route | Purpose |
| --- | --- |
| `POST /v1/can` | `{principal_id, permission, resource: {type, id}, session_id, scopes, agent_id, details, approval_id}`. Answers `{allowed, reason}`, plus `approval_id` when an agent must wait for a human. |
| `POST /v1/can/batch` | `{checks: [...]}`. Up to 100 questions at once. |
| `POST /v1/explain` | The same question, with the path that decided it |
| `POST /v1/filter` | `{principal_id, permission, resource_type}`. The ids where the permission holds. |
| `POST /v1/principals` | `{permission, resource}`. Who may. |
| `POST /v1/simulate` | `{grant_id}`. Who would lose what if the grant were removed. |
| `PUT /v1/permissions` | `{name, description, step_up_seconds, needs_approval}` |
| `PUT /v1/roles` | `{name, permissions}`. A permission may be a name, a prefix such as `payment.*`, or `*`. |
| `GET /v1/permissions`, `GET /v1/roles` | The catalog: live permissions, and the tenant-wide roles with what each holds (`source` is `code`, `portal` or `system`) |
| `PUT /v1/resources` | `{type, id, parent: {type, id}}`. `id` is the application's own id. |
| `POST /v1/grants`, `DELETE /v1/grants/{id}` | `{principal_id | group_id, role, resource, effect, expires_at}` |
| `PUT /v1/groups`, `GET /v1/groups`, `DELETE /v1/groups/{id}` | Groups |
| `POST /v1/groups/{id}/members`, `DELETE /v1/groups/{id}/members/{principal_id}` | Group membership |
| `GET /v1/users`, `POST /v1/users`, `GET /v1/users/{id}`, `DELETE /v1/users/{id}` | Accounts. `POST` sends a setup link. |
| `POST /v1/users/{id}/suspend`, `POST /v1/users/{id}/reinstate` | Suspension |
| `POST /v1/users/{id}/second-factor/reset` | Removes every second factor and ends every session, for a person who lost their phone and codes |
| `POST`, `GET /v1/service-accounts`; `POST`, `GET /v1/agents` | `{name, purpose, owner_principal_id}`. An agent needs an owner. |
| `GET /v1/machines/{id}`, `POST …/disable`, `POST …/enable`, `POST …/revoke`, `GET …/audit` | A machine's state. Revoke is the kill switch: keys, delegations, tokens and grants go at once. |
| `POST`, `GET /v1/api-keys`, `DELETE /v1/api-keys/{id}` | `{principal_id, name, scopes, expires_at}`. The key is shown once; keys start with `aos_`. |
| `POST /v1/api-keys/check` | `{key, permission, resource, details, approval_id}`. Who the key is, and the answer within its scopes. |
| `GET /v1/approvals/{id}` | An agent learns whether a human approved |
| `PUT /v1/oauth-providers`, `GET /v1/oauth-providers`, `DELETE /v1/oauth-providers/{provider}` | `{provider: google|apple|oidc, client_id, client_secret, issuer, scopes}`. Social sign-in providers. The secret is stored encrypted. |
| `POST /v1/webhooks`, `GET /v1/webhooks`, `DELETE /v1/webhooks/{id}` | Endpoints for events and before-hooks |
| `/v1/admin/organizations…` | The organization routes above, acting as the application (Root). `POST` may name `owner_principal_id`. |

The top of every tenant's tree is the resource `{"type": "tenant", "id": "root"}`.

**Provider routes.** The tenant as an OAuth and OpenID Connect provider. These are public: other applications and devices call them with no key of ours, and they answer in the protocol's own JSON. The issuer is `AOS_PUBLIC_URL/t/{slug}`.

| Route | Purpose |
| --- | --- |
| `GET /t/{slug}/.well-known/openid-configuration` | Discovery (also at `/.well-known/oauth-authorization-server`) |
| `GET /t/{slug}/oauth/jwks.json` | The keys that verify the tokens |
| `GET /t/{slug}/oauth/authorize` | The authorization request. The browser is sent to the application's `/auth/authorize?request_id=` page to sign in and consent. |
| `POST /t/{slug}/oauth/token` | `authorization_code` (PKCE S256), `refresh_token`, `client_credentials`, the device code grant, and token exchange with `delegation_id` |
| `POST /t/{slug}/oauth/device` | `{client_id, scope}` form. A device code and a user code. |
| `GET /t/{slug}/oauth/userinfo`, `POST …/introspect`, `POST …/revoke` | With a bearer token; with client authentication |

The consent page calls `GET /v1/oauth/requests/{id}` and `POST /v1/oauth/consent {request_id, approve}` with the person's session, and the device page `POST /v1/oauth/device/approve {user_code, approve}`. A person lists and withdraws consents at `GET /v1/me/consents` and `DELETE /v1/me/consents/{client_id}`. Clients are registered at the backend door with `PUT /v1/oauth-clients {client_id, name, kind, redirect_uris, allowed_scopes, grant_types, service_principal_id}`; a confidential client's secret is shown once. An MCP client may use its metadata document's address as `client_id`.

**Enterprise routes.** An organization admin (frontend, needs `aos.sso.manage`) or the application (`/v1/admin…`) creates a connection with `POST /v1/sso/connections {organization_id, protocol, name}` and gets a setup link, shown once. The IT admin's page uses `/v1/sso/setup/{token}`: `GET`, `PUT …/settings {issuer, client_id, client_secret}`, `PUT …/mappings {mappings: [{group, role, resource}], default_role, trust_idp_second_factor}`, `POST …/domains {domain}` and `POST …/domains/{id}/verify` (a TXT record at `_aos-verify.<domain>`), `POST …/test {redirect_uri}`, `POST …/activate`, `POST …/directory {default_role}` for a SCIM token. People sign in with `POST /v1/sso/start {email, redirect_uri}` and `POST /v1/sso/finish {state, code}`. Policies are at `GET`/`PATCH /v1/organizations/{id}/policies`. Directory sync is SCIM 2.0 at `/scim/v2/Users` and `/scim/v2/Groups` with the sync token as a bearer token. An audit export is a webhook with `"kind": "audit_export"` and an `organization_id`.

**Moving and reviewing.** At the backend door: `POST /v1/import/users {users: [{email, name, email_verified, password_hash, roles: [{role, resource}]}]}` (up to 1000), `POST /v1/export {passphrase}` and `POST /v1/import/archive {archive, passphrase}`. Access reviews are at both doors: `POST /v1/access-reviews {organization_id, reviewer_principal_id, due_days}`, `GET /v1/organizations/{id}/access-reviews`, `GET /v1/access-reviews/{id}`, `POST /v1/access-reviews/{id}/items/{item_id} {decision: keep|remove}`; a person needs `aos.grant.manage` in the organization.

## Operating it

| Command | What it does |
| --- | --- |
| `aos openapi` | Prints the OpenAPI document. `api/openapi.json` is its saved copy; a test fails when a route and its description disagree. After changing routes: `go run ./cmd openapi > api/openapi.json`. |
| `aos doctor` | Checks configuration, the database, the schema, the database roles, and that the master key opens every tenant's keys |
| `aos permissions sync --tenant <slug> --file permissions.json` | Applies the permissions and roles an application declares in code |
| `aos export --tenant <slug> --out <file>`, `aos import --tenant <slug> --in <file>` | Moves a tenant. The passphrase is read from `AOS_ARCHIVE_PASSPHRASE`. |
| `make image` | Builds the container image from the `Dockerfile` |

`.github/workflows/ci.yml` runs `gofmt`, `go vet` and the tests against a Postgres service, then builds the image.

## Tests

```bash
make test
```

This starts a new Postgres in Docker with no volume, on a random local port, runs the tests against it, and removes it.

The tests cannot reach any other database. Without `AOS_TEST_DATABASE_URL` they skip. With it, each test creates its own database with a random name, works only inside it, and drops only that one. Never point that variable at a server that holds real data.

`go test ./...` on its own runs the tests that need no database and skips the rest.

## Licence

The engine is under the [Business Source License 1.1](LICENSE). You may use it in production for your own applications, including ones you provide to your customers. You may not offer it to other companies as a hosted identity, authentication or authorization service. Each version becomes Apache-2.0 four years after its release. The SDKs (`aos-go`, `@aos-auth/*`, `aos-auth`) and the CLI (`aos-cli`) are Apache-2.0.
