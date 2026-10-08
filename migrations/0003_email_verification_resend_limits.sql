-- Persistent per-email rate limits for verification-email resend requests.
-- Store only a SHA-256 hash of the normalized email address, never the address itself.
CREATE TABLE IF NOT EXISTS email_verification_resend_limits (
  email_hash TEXT PRIMARY KEY,
  window_started_at TEXT NOT NULL,
  last_sent_at TEXT NOT NULL,
  send_count INTEGER NOT NULL DEFAULT 0 CHECK (send_count >= 0)
);
