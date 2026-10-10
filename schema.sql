
CREATE TABLE IF NOT EXISTS device_registrations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    bot_key TEXT NOT NULL,
    telegram_user_id TEXT NOT NULL,

    -- Hash of the browser installation identifier.
    device_hash TEXT NOT NULL,

    -- Optional platform attestation identifier, when supported.
    device_key_hash TEXT,

    platform TEXT NOT NULL
        CHECK (platform IN ('android', 'ios')),

    username TEXT,
    first_name TEXT,

    verified BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_bot_telegram_user
        UNIQUE (bot_key, telegram_user_id),

    CONSTRAINT unique_bot_device
        UNIQUE (bot_key, device_hash)
);

CREATE INDEX IF NOT EXISTS idx_registrations_bot
    ON device_registrations (bot_key);

CREATE INDEX IF NOT EXISTS idx_registrations_user
    ON device_registrations (telegram_user_id);

CREATE TABLE IF NOT EXISTS verification_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    bot_key TEXT NOT NULL,
    telegram_user_id TEXT,
    event_type TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_events_bot_created
    ON verification_events (bot_key, created_at DESC);
