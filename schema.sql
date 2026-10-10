
CREATE TABLE IF NOT EXISTS registered_bots (
  bot_key TEXT PRIMARY KEY,
  bot_username TEXT NOT NULL,
  bot_token_enc TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS temporary_registration_ids (
  id_hash TEXT PRIMARY KEY,
  bot_key TEXT NOT NULL REFERENCES registered_bots(bot_key)
    ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS device_registrations (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  bot_key TEXT NOT NULL REFERENCES registered_bots(bot_key)
    ON DELETE CASCADE,
  telegram_user_id TEXT NOT NULL,
  device_hash TEXT NOT NULL,
  platform TEXT NOT NULL,
  username TEXT,
  first_name TEXT,
  status TEXT NOT NULL DEFAULT 'verified',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (bot_key, telegram_user_id),
  UNIQUE (bot_key, device_hash)
);

CREATE TABLE IF NOT EXISTS verification_events (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  bot_key TEXT NOT NULL,
  telegram_user_id TEXT,
  event_type TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ip_risk_cache (
  ip_hash TEXT PRIMARY KEY,
  is_vpn BOOLEAN NOT NULL DEFAULT FALSE,
  is_proxy BOOLEAN NOT NULL DEFAULT FALSE,
  is_tor BOOLEAN NOT NULL DEFAULT FALSE,
  checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ip_risk_cache_expiry_idx
ON ip_risk_cache (expires_at);
