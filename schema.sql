
CREATE TABLE IF NOT EXISTS registered_bots (
  bot_key TEXT PRIMARY KEY,
  bot_username TEXT NOT NULL,
  bot_token TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS temporary_registration_ids (
  id_hash TEXT PRIMARY KEY,
  bot_key TEXT NOT NULL REFERENCES registered_bots(bot_key)
    ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_temp_registration_expiry
ON temporary_registration_ids(expires_at);

CREATE INDEX IF NOT EXISTS idx_temp_registration_bot
ON temporary_registration_ids(bot_key);
