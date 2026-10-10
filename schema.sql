
-- External browser Telegram login requests
CREATE TABLE IF NOT EXISTS telegram_login_requests (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    bot_key TEXT NOT NULL,
    telegram_user_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'used', 'expired')),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_at TIMESTAMPTZ,
    used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tg_login_bot_status
    ON telegram_login_requests (bot_key, status);

CREATE INDEX IF NOT EXISTS idx_tg_login_expiry
    ON telegram_login_requests (expires_at);
