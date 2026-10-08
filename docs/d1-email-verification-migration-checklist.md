# D1 migration preflight: email verification

Do **not** apply `0002_email_verification.sql` until these checks pass against the existing production D1 database.

Run each query separately in the Cloudflare D1 SQL console. These are read-only checks.

## 1. Confirm the existing tables

```sql
SELECT name, type
FROM sqlite_master
WHERE type IN ('table', 'index')
ORDER BY type, name;
```

Expected existing tables include `users` and `sessions`.

## 2. Confirm the users schema

```sql
PRAGMA table_info(users);
```

The existing `users` table must contain at least `id`, `email`, `password_hash`, and `created_at`. Check that `email_verified` does not already exist before applying migration 0002. If it already exists, stop and reconcile the migration rather than running it again.

## 3. Confirm the sessions schema

```sql
PRAGMA table_info(sessions);
```

The current Worker expects `sessions.id`, `sessions.user_id`, `sessions.expires_at`, and `sessions.created_at`.

## 4. Check existing user counts

```sql
SELECT COUNT(*) AS users_count FROM users;
SELECT COUNT(*) AS sessions_count FROM sessions;
```

Record the counts before migration so they can be compared afterward. Do not export or share password hashes or session identifiers.

## 5. Apply and verify

Only after the schema checks pass, apply `migrations/0002_email_verification.sql` once. Then run:

```sql
PRAGMA table_info(users);
SELECT name FROM sqlite_master
WHERE type = 'table' AND name = 'email_verification_tokens';
SELECT COUNT(*) AS users_count FROM users;
SELECT COUNT(*) AS sessions_count FROM sessions;
```

Confirm that `users.email_verified` exists, `email_verification_tokens` exists, and the user/session counts have not unexpectedly changed.

## Important

- This checklist does not execute any SQL and does not modify D1.
- Do not deploy the email-verification Worker before the migration is applied successfully; its registration and login queries expect `users.email_verified`.
- Existing users receive `email_verified = 1` through the migration default, while newly registered users are inserted with `email_verified = 0`.
- If the existing schema differs from the assumptions above, stop and update the migration/code to match the real schema before proceeding.


## Registration failure recovery

If the email provider rejects a verification message, the Worker attempts to remove the newly created unverified user and token. If D1 is unavailable during that cleanup, the cleanup itself can fail; inspect Worker logs for `Registration cleanup failed` and reconcile only the affected unverified account after confirming the email was not delivered. Never log or share passwords, raw verification tokens, session IDs, or password hashes.

## Verification-link behavior test matrix

Before deployment, test these cases in a non-production D1 database:

- A valid token opened with GET displays the confirmation page and does not mark the account verified.
- Submitting that page with POST verifies the account and removes the token.
- Reusing the token after successful verification fails as invalid/used.
- An expired token fails and is removed.
- A malformed or missing token returns an invalid-link page.
- A new account cannot log in before verification; it can log in after verification.
- Existing accounts retain access after migration.
- A simulated Resend failure returns an error and attempts to clean up the pending account/token.
- A simulated D1 cleanup failure is logged without exposing secrets in logs.

Do not run destructive tests against production users.
