# Tovikeli Cutout API — Auth V1

Dependency-free Cloudflare Worker for the current Tovikeli Cutout frontend.

## API

- GET /api/auth/me
- POST /api/auth/register
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
- Registration automatically creates a session

## Not included yet

AI cutout, R2, subscriptions, points, usage billing, admin panel and advanced rate limiting are intentionally deferred.


## Email verification (feature branch)

This branch adds a Resend-backed email verification flow.

### Required Worker bindings

- `DB`: existing D1 database.
- `RESEND_API_KEY`: Worker secret with Resend sending access.
- `VERIFY_EMAIL_TEMPLATE_ID`: published Resend template alias (currently `verification-email`).
- `APP_BASE_URL`: HTTPS URL of the actual Tovikeli frontend to return to after verification. Set this to the deployed site URL before testing; if omitted, the Worker falls back to `https://tovikeli.top/`.

The `CREDITS_ADDED_TEMPLATE_ID` can be configured now, but the credits-added email is not triggered yet because payment and credit-ledger logic are not implemented.

### Database migration

Apply `migrations/0002_email_verification.sql` to the existing D1 database before deploying this branch. It adds `users.email_verified` (existing accounts default to verified) and the `email_verification_tokens` table.

### Registration behavior

New registrations create an unverified account and send a 30-minute verification link. The user is not logged in until verification succeeds. The verification link opens a branded confirmation page and then returns to `APP_BASE_URL`.
