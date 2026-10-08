# Tovikeli Cutout API — Auth V1

Dependency-free Cloudflare Worker for the current Tovikeli Cutout frontend.

## API

- GET /api/auth/me
- POST /api/auth/register
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

AI cutout, R2, subscriptions, points, usage billing, admin panel and advanced rate limiting are intentionally deferred.


## Email verification (feature branch)

This branch adds a Resend-backed email verification flow.

### Required Worker bindings

- `DB`: existing D1 database.
- `RESEND_API_KEY`: Worker secret with Resend sending access.
- `VERIFY_EMAIL_TEMPLATE_ID`: published Resend template alias (currently `verification-email`).
- `APP_BASE_URL`: HTTPS URL of the Tovikeli Cutout frontend to return to after verification. Planned production URL: `https://cutout.tovikeli.top`. This subdomain has been chosen in advance but is not yet deployed; set this variable to the actual frontend URL when the site is ready. If omitted, the Worker falls back to `https://cutout.tovikeli.top/`.

The `CREDITS_ADDED_TEMPLATE_ID` can be configured now, but the credits-added email is not triggered yet because payment and credit-ledger logic are not implemented.

### Database migration

Before applying `migrations/0002_email_verification.sql`, follow [`docs/d1-email-verification-migration-checklist.md`](docs/d1-email-verification-migration-checklist.md) to inspect the real D1 schema and record baseline counts. The checklist is read-only and does not modify D1. Once the schema is confirmed, apply the migration exactly once. It adds `users.email_verified` (existing accounts default to verified) and the `email_verification_tokens` table. Do not deploy this branch until the migration succeeds.

### Registration behavior

New registrations create an unverified account and send a 30-minute verification link. The user is not logged in until verification succeeds. The verification link opens a branded confirmation page and then returns to `APP_BASE_URL`. Expired or invalid links currently require support intervention; automatic resend is not implemented yet.
