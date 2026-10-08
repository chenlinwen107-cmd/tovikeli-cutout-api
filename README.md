# Tovikeli Cutout API — Auth V1

Dependency-free Cloudflare Worker for the current Tovikeli Cutout frontend.

## API

- GET /api/auth/me
- POST /api/auth/register
- POST /api/auth/resend-verification
- GET /api/auth/verify-email (confirmation page)
- POST /api/auth/verify-email (confirm verification)
- POST /api/auth/login
- POST /api/auth/logout
- GET /api/health

## D1 binding

The Worker expects a D1 binding named `DB`, pointing to the existing `tovikeli-cutout` database.

## Security

- HttpOnly + Secure + SameSite=Lax session cookie
- No JWT
- No localStorage authentication token
- Passwords use PBKDF2-SHA-256 with a per-user random salt
- Session lifetime: 30 days
- New registrations require email verification before login

## Not included yet

AI cutout, R2, subscriptions, points, usage billing and admin panel are intentionally deferred. Verification-email resend has a dedicated persistent per-email rate limit.


## Email verification (feature branch)

This branch adds a Resend-backed email verification flow.

### Required Worker bindings

- `DB`: existing D1 database.
- `RESEND_API_KEY`: Worker secret with Resend sending access.
- `VERIFY_EMAIL_TEMPLATE_ID`: published Resend template alias (currently `verification-email`).
- `APP_BASE_URL`: HTTPS URL of the Tovikeli Cutout frontend to return to after verification. Planned production URL: `https://cutout.tovikeli.top`. This subdomain has been chosen in advance but is not yet deployed; set this variable to the actual frontend URL when the site is ready. If omitted, the Worker falls back to `https://cutout.tovikeli.top/`.

The `CREDITS_ADDED_TEMPLATE_ID` can be configured now, but the credits-added email is not triggered yet because payment and credit-ledger logic are not implemented.

### Database migration

Before applying migrations, follow [`docs/d1-email-verification-migration-checklist.md`](docs/d1-email-verification-migration-checklist.md) to inspect the real D1 schema and record baseline counts. The checklist is read-only and does not modify D1. Once the schema is confirmed, apply `migrations/0002_email_verification.sql` and then `migrations/0003_email_verification_resend_limits.sql`, each exactly once. Migration 0002 adds `users.email_verified` (existing accounts default to verified) and the token table; migration 0003 adds the hashed-email rate-limit table. Do not deploy this branch until both migrations succeed.

### Registration behavior

New registrations create an unverified account and send a 30-minute verification link. The user is not logged in until verification succeeds. The verification link opens a branded confirmation page and then returns to `APP_BASE_URL`. Expired or invalid links can be replaced by calling `POST /api/auth/resend-verification` with `{ "email": "user@example.com" }`. The endpoint returns a generic response to avoid confirming whether an address has an account, and allows at most one resend per 60 seconds and three sends in a fixed hourly window that begins with the first allowed send per normalized email address. Limits are stored using a SHA-256 email hash in D1. The hourly window/cooldown slot is consumed before sending; a provider failure returns an error and leaves the slot consumed to prevent rapid retries. The endpoint only sends to existing, unverified accounts.


## Local smoke tests

The repository includes initial route-level smoke tests using Node's built-in test runner; no additional test framework is required. Use Node.js 20 or newer:

```sh
npm test
```

These tests cover health/unknown routes and malformed or missing inputs for registration and verification-email resend. They do not replace integration tests against a test D1 database and a mocked Resend API. The tests have been added to the repository but have not yet been executed in this environment.
