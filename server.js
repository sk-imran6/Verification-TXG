
const express = require("express");
const crypto = require("crypto");
const { neon } = require("@neondatabase/serverless");
const path = require("path");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", process.env.TRUST_PROXY === "true");
app.use(express.json({ limit: "16kb" }));

const DATABASE_URL = process.env.DATABASE_URL;
const APP_ORIGIN = process.env.APP_ORIGIN;

if (!DATABASE_URL || !APP_ORIGIN) {
  throw new Error("DATABASE_URL and APP_ORIGIN are required");
}

const sql = neon(DATABASE_URL);
const PORT = process.env.PORT || 3000;

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function randomToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function reply(res, status, title, message, extra = {}) {
  return res.status(status).json({
    status: status < 400 ? "success" : "error",
    title,
    message,
    ...extra
  });
}

function checkOrigin(req, res, next) {
  const origin = req.get("origin");

  if (origin && origin !== APP_ORIGIN) {
    return reply(res, 403, "Forbidden", "Invalid website origin.");
  }

  next();
}

app.use("/api", checkOrigin);

app.get("/health", (req, res) => {
  res.json({ status: "success", message: "TXG backend running" });
});

/*
  Register a bot using a short-lived registration ID.

  IMPORTANT:
  Call this endpoint from a trusted server-side environment.
  Never place a bot token in a browser URL.
*/
app.post("/api/register", async (req, res) => {
  try {
    const { bot_username, bot_token } = req.body || {};

    if (
      typeof bot_username !== "string" ||
      !/^@?[a-zA-Z0-9_]{5,32}$/.test(bot_username) ||
      typeof bot_token !== "string" ||
      !/^\d{5,20}:[A-Za-z0-9_-]{20,}$/.test(bot_token)
    ) {
      return reply(res, 400, "Invalid input", "Check bot username and token.");
    }

    // Validate token with Telegram before accepting it.
    const telegramResponse = await fetch(
      "https://api.telegram.org/bot" + bot_token + "/getMe",
      { signal: AbortSignal.timeout(8000) }
    );

    const telegramData = await telegramResponse.json();

    if (!telegramResponse.ok || !telegramData.ok) {
      return reply(res, 400, "Invalid token", "Telegram rejected this bot token.");
    }

    const actualUsername = telegramData.result.username;

    if (actualUsername.toLowerCase() !== bot_username.replace(/^@/, "").toLowerCase()) {
      return reply(res, 400, "Bot mismatch", "Username does not match the token.");
    }

    // Store a stable bot key, never the bot token in the URL.
    const botKey = hash(bot_token);
    const temporaryId = randomToken();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await sql`
      INSERT INTO registered_bots
        (bot_key, bot_username, bot_token, created_at)
      VALUES
        (${botKey}, ${actualUsername}, ${bot_token}, NOW())
      ON CONFLICT (bot_key)
      DO UPDATE SET
        bot_username = EXCLUDED.bot_username
    `;

    await sql`
      INSERT INTO temporary_registration_ids
        (id_hash, bot_key, expires_at, created_at)
      VALUES
        (${hash(temporaryId)}, ${botKey}, ${expiresAt.toISOString()}, NOW())
    `;

    return reply(res, 200, "Bot registered", "Temporary ID expires in 5 minutes.", {
      registration_id: temporaryId,
      expires_at: expiresAt.toISOString(),
      bot_username: actualUsername
    });
  } catch (error) {
    console.error("Register error:", error.message);
    return reply(res, 500, "Server error", "Could not register bot.");
  }
});

/*
  Read bot information using the temporary ID.
  The ID is single-purpose and expires after 5 minutes.
*/
app.post("/api/registration-info", async (req, res) => {
  try {
    const { registration_id } = req.body || {};

    if (
      typeof registration_id !== "string" ||
      registration_id.length < 30 ||
      registration_id.length > 100
    ) {
      return reply(res, 400, "Invalid ID", "Registration ID is invalid.");
    }

    const idHash = hash(registration_id);

    const rows = await sql`
      SELECT t.bot_key, b.bot_username, t.expires_at
      FROM temporary_registration_ids t
      JOIN registered_bots b ON b.bot_key = t.bot_key
      WHERE t.id_hash = ${idHash}
        AND t.expires_at > NOW()
        AND t.used_at IS NULL
      LIMIT 1
    `;

    if (!rows.length) {
      await sql`
        DELETE FROM temporary_registration_ids
        WHERE id_hash = ${idHash}
           OR expires_at <= NOW()
      `;

      return reply(res, 410, "ID expired", "Register again to receive a new ID.");
    }

    const record = rows[0];

    // Consume the ID once read. This prevents reuse.
    const consumed = await sql`
      UPDATE temporary_registration_ids
      SET used_at = NOW()
      WHERE id_hash = ${idHash}
        AND used_at IS NULL
        AND expires_at > NOW()
      RETURNING id_hash
    `;

    if (!consumed.length) {
      return reply(res, 410, "ID used", "This registration ID has already been used.");
    }

    return reply(res, 200, "Registration found", "Bot information loaded.", {
      bot_username: record.bot_username,
      expires_at: record.expires_at
    });
  } catch (error) {
    console.error("Registration info error:", error.message);
    return reply(res, 500, "Server error", "Could not load registration.");
  }
});

app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, () => {
  console.log("TXG verification backend running on port " + PORT);
});
