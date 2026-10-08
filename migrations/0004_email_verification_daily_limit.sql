-- Add a fixed 24-hour per-email cap in addition to the existing hourly limits.
-- Existing rows start a fresh daily window on their next resend attempt.
ALTER TABLE email_verification_resend_limits
ADD COLUMN daily_window_started_at TEXT;

ALTER TABLE email_verification_resend_limits
ADD COLUMN daily_send_count INTEGER NOT NULL DEFAULT 0
CHECK (daily_send_count >= 0);
