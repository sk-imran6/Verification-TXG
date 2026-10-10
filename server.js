
const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { neon } = require("@neondatabase/serverless");

const app = express();
app.disable("x-powered-by");

if (process.env.TRUST_PROXY === "true") {
  app.set("trust proxy", 1);
}

app.use(express.json({ limit: "20kb" }));

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const APP_ORIGIN = process.env.APP_ORIGIN || "";

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL is required");
}

if (!APP_ORIGIN) {
  throw new Error("APP_ORIGIN is required");
}

let BOT_TOKENS;

try {
  BOT_TOKENS = JSON.parse(process.env.BOT_TOKENS_JSON || "{}");
} catch {
  throw new Error("BOT_TOKENS_JSON must be valid JSON");
}

if (!BOT_TOKENS || typeof BOT_TOKENS !== "object" ||
    Array.isArray(BOT_TOKENS) || !Object.keys(BOT_TOKENS).length) {
  throw new Error("Configure BOT_TOKENS_JSON");
}

const sql = neon(DATABASE_URL);
const publicDir = path.join(__dirname, "public");

const limits = new Map();

function error(res, status, message) {
  return res.status(status).json({ ok: false, error: message });
}

function rateLimit(req, res, next) {
  const now = Date.now();
  const key = req.ip || "unknown";
  let item = limits.get(key);

  if (!item || now - item.start >= 60000) {
    item = { start: now, count: 0 };
  }

  item.count++;
  limits.set(key, item);

  if (item.count > 30) {
    return error(res, 429, "Too many requests. Try again later.");
  }

  next();
}

app.use("/api", rateLimit);

function isMobilePlatform(req) {
  const ua = req.get("user-agent") || "";

  // Basic filtering only. User-Agent can be spoofed.
  if (/Windows NT|Macintosh|X11|Linux x86_64|CrOS/i.test(ua)) {
    return null;
  }

  if (/Android/i.test(ua)) {
    return "android";
  }

  if (/iPhone|iPad|iPod/i.test(ua)) {
    return "ios";
  }

  return null;
}

function checkOrigin(req, res, next) {
  if (req.get("origin") !== APP_ORIGIN) {
    return error(res, 403, "Origin not allowed");
  }

  next();
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));

  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function getBotToken(botKey) {
  if (typeof botKey !== "string" ||
      !/^[A-Za-z0-9_]{3,64}$/.test(botKey)) {
    return null;
  }

  const token = BOT_TOKENS[botKey];

  return typeof token === "string" &&
    /^\d+:[A-Za-z0-9_-]+$/.test(token) ? token : null;
}

function validateInitData(initData, token) {
  if (typeof initData !== "string" || initData.length > 16384) {
    return null;
  }

  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");

  if (!receivedHash || !/^[a-f0-9]{64}$/i.test(receivedHash)) {
    return null;
  }

  params.delete("hash");

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secret = crypto
    .createHmac("sha256", "WebAppData")
    .update(token)
    .digest();

  const expectedHash = crypto
    .createHmac("sha256", secret)
    .update(dataCheckString)
    .digest("hex");

  if (!safeEqual(expectedHash, receivedHash.toLowerCase())) {
    return null;
  }

  const authDate = Number(params.get("auth_date"));
  const now = Math.floor(Date.now() / 1000);

  if (!Number.isInteger(authDate) ||
      authDate > now + 30 ||
      now - authDate > 3600) {
    return null;
  }

  let user;

  try {
    user = JSON.parse(params.get("user") || "null");
  } catch {
    return null;
  }

  if (!user ||
      !/^\d+$/.test(String(user.id || ""))) {
    return null;
  }

  return {
    id: String(user.id),
    username: typeof user.username === "string"
      ? user.username.slice(0, 64) : null,
    firstName: typeof user.first_name === "string"
      ? user.first_name.slice(0, 128) : null
  };
}

function parseDeviceId(value) {
  if (typeof value !== "string" ||
      !/^[a-f0-9-]{36}$/i.test(value)) {
    return null;
  }

  return value.toLowerCase();
}

function hashDeviceId(id) {
  return crypto.createHash("sha256").update(id).digest("hex");
}

function authenticate(req) {
  const body = req.body || {};
  const token = getBotToken(body.bot);

  if (!token) {
    return { status: 400, message: "Unknown bot key" };
  }

  const user = validateInitData(body.initData, token);

  if (!user) {
    return { status: 401, message: "Telegram authentication failed" };
  }

  return { bot: body.bot, user };
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

app.post("/api/session", checkOrigin, async (req, res) => {
  const platform = isMobilePlatform(req);

  if (!platform) {
    return error(res, 403, "Only supported mobile devices are allowed");
  }

  const auth = authenticate(req);

  if (auth.message) {
    return error(res, auth.status, auth.message);
  }

  res.set("Cache-Control", "no-store");

  return res.json({
    ok: true,
    platform,
    user: {
      id: auth.user.id,
      username: auth.user.username,
      firstName: auth.user.firstName
    }
  });
});

app.post("/api/verify", checkOrigin, async (req, res) => {
  const platform = isMobilePlatform(req);

  if (!platform) {
    return error(res, 403, "Only supported mobile devices are allowed");
  }

  const auth = authenticate(req);

  if (auth.message) {
    return error(res, auth.status, auth.message);
  }

  const deviceId = parseDeviceId(req.body.deviceId);

  if (!deviceId) {
    return error(res, 400, "Invalid browser installation ID");
  }

  const { bot, user } = auth;
  const deviceHash = hashDeviceId(deviceId);

  try {
    const accountRows = await sql`
      SELECT device_hash, verified
      FROM device_registrations
      WHERE bot_key = ${bot}
        AND telegram_user_id = ${user.id}
      LIMIT 1
    `;

    if (accountRows.length) {
      if (accountRows[0].device_hash !== deviceHash) {
        await sql`
          INSERT INTO verification_events
            (bot_key, telegram_user_id, event_type, details)
          VALUES (
            ${bot}, ${user.id}, 'account_device_mismatch',
            ${JSON.stringify({ platform })}::jsonb
          )
        `;

        return res.status(409).json({
          ok: false,
          status: "account_already_registered",
          error: "This Telegram account is already registered on this bot."
        });
      }

      return res.json({
        ok: true,
        status: "already_verified",
        message: "This browser installation is already verified."
      });
    }

    const deviceRows = await sql`
      SELECT telegram_user_id
      FROM device_registrations
      WHERE bot_key = ${bot}
        AND device_hash = ${deviceHash}
      LIMIT 1
    `;

    if (deviceRows.length) {
      await sql`
        INSERT INTO verification_events
          (bot_key, telegram_user_id, event_type, details)
        VALUES (
          ${bot}, ${user.id}, 'device_account_mismatch',
          ${JSON.stringify({ platform })}::jsonb
        )
      `;

      return res.status(409).json({
        ok: false,
        status: "same_device_detected",
        error: "This browser installation is already registered on this bot."
      });
    }

    const inserted = await sql`
      INSERT INTO device_registrations
        (bot_key, telegram_user_id, device_hash, platform,
         username, first_name, verified)
      VALUES (
        ${bot}, ${user.id}, ${deviceHash}, ${platform},
        ${user.username}, ${user.firstName}, TRUE
      )
      ON CONFLICT DO NOTHING
      RETURNING id
    `;

    if (!inserted.length) {
      return res.status(409).json({
        ok: false,
        status: "duplicate_registration",
        error: "A registration already exists for this bot."
      });
    }

    await sql`
      INSERT INTO verification_events
        (bot_key, telegram_user_id, event_type, details)
      VALUES (
        ${bot}, ${user.id}, 'verification_success',
        ${JSON.stringify({ platform })}::jsonb
      )
    `;

    res.set("Cache-Control", "no-store");

    return res.json({
      ok: true,
      status: "verified",
      message: "Verification successful."
    });
  } catch (err) {
    console.error("Verification database error:", err.message);
    return error(res, 500, "Verification service temporarily unavailable");
  }
});

app.use(express.static(publicDir, { index: "index.html" }));

app.get("*path", (req, res, next) => {
  if (req.path.startsWith("/api/")) {
    return error(res, 404, "API endpoint not found");
  }

  res.sendFile(path.join(publicDir, "index.html"), (err) => {
    if (err) next(err);
  });
});

app.use((err, req, res, next) => {
  console.error("Server error:", err.message);
  if (res.headersSent) return next(err);
  return error(res, 500, "Internal server error");
});

app.listen(PORT, () => {
  console.log(`TXG Verification running on port ${PORT}`);
});
