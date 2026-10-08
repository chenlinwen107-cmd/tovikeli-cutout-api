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
