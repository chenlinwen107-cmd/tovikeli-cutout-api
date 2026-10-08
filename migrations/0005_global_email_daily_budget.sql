-- Global rolling 24-hour cap for verification emails.
-- Limit to 80 accepted send attempts per window to leave headroom under a 100/day provider quota.
CREATE TABLE IF NOT EXISTS email_verification_global_daily_budget (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  window_started_at TEXT NOT NULL,
  send_count INTEGER NOT NULL DEFAULT 0 CHECK (send_count >= 0)
);
