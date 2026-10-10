
const express = require("express");
const crypto = require("crypto");
const path = require("path");
const net = require("net");
const { neon } = require("@neondatabase/serverless");

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", process.env.TRUST_PROXY === "true");
app.use(express.json({ limit: "20kb" }));

const required = [
  "DATABASE_URL",
  "APP_ORIGIN",
  "TBC_SHARED_SECRET",
  "TOKEN_ENCRYPTION_KEY"
];

for (const key of required) {
  if (!process.env[key]) {
    throw new Error(`Missing environment variable: ${key}`);
  }
}

if (!/^[a-fA-F0-9]{64}$/.test(process.env.TOKEN_ENCRYPTION_KEY)) {
  throw new Error("TOKEN_ENCRYPTION_KEY must be 64 hex characters.");
}

const sql = neon(process.env.DATABASE_URL);
const ORIGIN = process.env.APP_ORIGIN.replace(/\/$/, "");
const encKey = Buffer.from(process.env.TOKEN_ENCRYPTION_KEY, "hex");

const IPDB_KEY = process.env.IPDB_KEY || "";
const IPAPI_KEY = process.env.IPAPI_KEY || "";

function sha(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function randomId() {
  return crypto.randomBytes(32).toString("base64url");
}

function reply(res, code, status, title, message, extra = {}) {
  res.set("Cache-Control", "no-store");
  return res.status(code).json({ status, title, message, ...extra });
}

function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encKey, iv);
  const data = Buffer.concat([
    cipher.update(text, "utf8"),
    cipher.final()
  ]);

  return [
    iv.toString("base64url"),
    cipher.getAuthTag().toString("base64url"),
    data.toString("base64url")
  ].join(".");
}

function decrypt(value) {
  const parts = value.split(".");
  if (parts.length !== 3) throw new Error("Invalid encrypted token");

  const [iv, tag, data] = parts;
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    encKey,
    Buffer.from(iv, "base64url")
  );

  decipher.setAuthTag(Buffer.from(tag, "base64url"));

  return Buffer.concat([
    decipher.update(Buffer.from(data, "base64url")),
    decipher.final()
  ]).toString("utf8");
}

function requireTbc(req, res, next) {
  const supplied = Buffer.from(req.get("x-txg-secret") || "");
  const expected = Buffer.from(process.env.TBC_SHARED_SECRET);

  if (
    supplied.length !== expected.length ||
    !crypto.timingSafeEqual(supplied, expected)
  ) {
    return reply(res, 401, "error", "Unauthorized", "TBC authentication failed.");
  }

  next();
}

function mobilePlatform(req) {
  const ua = req.get("user-agent") || "";

  if (/Android/i.test(ua)) return "android";
  if (/iPhone|iPad|iPod/i.test(ua)) return "ios";

  return null;
}

function telegramInitDataValid(initData, token) {
  try {
    const params = new URLSearchParams(initData);
    const receivedHash = params.get("hash");

    if (!receivedHash || !/^[a-f0-9]{64}$/i.test(receivedHash)) {
      return null;
    }

    params.delete("hash");

    const authDate = Number(params.get("auth_date"));
    const now = Date.now() / 1000;

    if (
      !Number.isFinite(authDate) ||
      authDate > now + 30 ||
      now - authDate > 300
    ) {
      return null;
    }

    const checkString = [...params.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const secretKey = crypto
      .createHmac("sha256", "WebAppData")
      .update(token)
      .digest();

    const expected = crypto
      .createHmac("sha256", secretKey)
      .update(checkString)
      .digest("hex");

    const a = Buffer.from(receivedHash, "hex");
    const b = Buffer.from(expected, "hex");

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return null;
    }

    const userText = params.get("user");
    if (!userText) return null;

    return JSON.parse(userText);
  } catch {
    return null;
  }
}

/* --------------------------------
   TBC WEBHOOK CALLBACK
--------------------------------- */

// Configure this to the exact trusted TBC webhook hostname
// once you confirm the hostname returned by libs.Webhook.getUrlFor().
function validateTbcWebhook(value) {
  try {
    if (typeof value !== "string" || value.length > 2000) return false;

    const url = new URL(value);

    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      !url.hostname ||
      net.isIP(url.hostname) ||
      url.hostname === "localhost" ||
      url.hostname.endsWith(".localhost") ||
      url.hostname.endsWith(".local")
    ) {
      return false;
    }

    // Optional strict allowlist:
    // Set TBC_WEBHOOK_HOST to the exact trusted hostname in Render.
    const allowedHost = process.env.TBC_WEBHOOK_HOST;

    if (allowedHost && url.hostname.toLowerCase() !== allowedHost.toLowerCase()) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

async function sendTbcCallback(webhookUrl, payload) {
  if (!validateTbcWebhook(webhookUrl)) {
    console.error("TBC callback skipped: invalid/untrusted webhook URL");
    return false;
  }

  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(7000),
      redirect: "error"
    });

    if (!response.ok) {
      console.error("TBC callback HTTP status:", response.status);
      return false;
    }

    return true;
  } catch (error) {
    console.error("TBC callback failed:", error.message);
    return false;
  }
}

/* --------------------------------
   IP CHECKING
--------------------------------- */

function getClientIp(req) {
  let ip = req.ip || "";

  if (ip.startsWith("::ffff:")) ip = ip.slice(7);

  return ip;
}

function extractIpDbFlags(data) {
  const networkType = String(data?.networkType || "").toLowerCase();

  const sources = Array.isArray(data?.blacklistSources)
    ? data.blacklistSources.join(" ").toLowerCase()
    : "";

  const dnsbl = Array.isArray(data?.dnsbl)
    ? data.dnsbl.join(" ").toLowerCase()
    : "";

  const combined = `${sources} ${dnsbl}`;

  return {
    vpn: networkType === "vpn" || /\bvpn\b/.test(combined),
    proxy: networkType === "proxy" || /\bproxy\b/.test(combined),
    tor: networkType === "tor" || /tor exit|tor node/.test(combined)
  };
}

async function queryIpDb(ip) {
  if (!IPDB_KEY) throw new Error("IPDB_KEY is not configured");

  const response = await fetch(
    "https://ip-db.com/api/v1/check/" + encodeURIComponent(ip),
    {
      headers: { Key: IPDB_KEY, Accept: "application/json" },
      signal: AbortSignal.timeout(5000)
    }
  );

  if (!response.ok) throw new Error(`IP-DB HTTP ${response.status}`);

  const data = await response.json();

  if (data.error || data.errorCode || data.isPrivate === true) {
    throw new Error("IP-DB returned an invalid result");
  }

  return extractIpDbFlags(data);
}

async function queryIpApi(ip) {
  if (!IPAPI_KEY) throw new Error("IPAPI_KEY is not configured");

  const response = await fetch("https://api.ipapi.is", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json"
    },
    body: JSON.stringify({ q: ip, key: IPAPI_KEY }),
    signal: AbortSignal.timeout(5000)
  });

  if (!response.ok) throw new Error(`ipapi.is HTTP ${response.status}`);

  const data = await response.json();

  if (data.error || data.error_code) {
    throw new Error("ipapi.is returned an API error");
  }

  if (
    typeof data.is_vpn !== "boolean" &&
    typeof data.is_proxy !== "boolean" &&
    typeof data.is_tor !== "boolean"
  ) {
    throw new Error("VPN detection fields are unavailable");
  }

  return {
    vpn: Boolean(data.is_vpn),
    proxy: Boolean(data.is_proxy),
    tor: Boolean(data.is_tor)
  };
}

async function checkIpRisk(ip) {
  const ipHash = sha(ip);

  const cached = await sql`
    SELECT is_vpn, is_proxy, is_tor
    FROM ip_risk_cache
    WHERE ip_hash = ${ipHash}
      AND expires_at > NOW()
    LIMIT 1
  `;

  if (cached.length) {
    return {
      ok: true,
      vpn: cached[0].is_vpn,
      proxy: cached[0].is_proxy,
      tor: cached[0].is_tor,
      source: "cache"
    };
  }

  let flags;

  try {
    flags = await queryIpDb(ip);
  } catch (error) {
    console.warn("IP-DB failed:", error.message);

    try {
      flags = await queryIpApi(ip);
    } catch (fallbackError) {
      console.warn("ipapi.is failed:", fallbackError.message);

      return {
        ok: false,
        vpn: false,
        proxy: false,
        tor: false,
        source: "unavailable"
      };
    }
  }

  await sql`
    INSERT INTO ip_risk_cache (
      ip_hash, is_vpn, is_proxy, is_tor, checked_at, expires_at
    )
    VALUES (
      ${ipHash}, ${flags.vpn}, ${flags.proxy}, ${flags.tor},
      NOW(), NOW() + INTERVAL '24 hours'
    )
    ON CONFLICT (ip_hash)
    DO UPDATE SET
      is_vpn = EXCLUDED.is_vpn,
      is_proxy = EXCLUDED.is_proxy,
      is_tor = EXCLUDED.is_tor,
      checked_at = NOW(),
      expires_at = NOW() + INTERVAL '24 hours'
  `;

  return { ok: true, ...flags, source: "api" };
}

/* --------------------------------
   HEALTH
--------------------------------- */

app.get("/health", (req, res) => {
  return reply(res, 200, "success", "Online", "TXG backend running");
});

/* --------------------------------
   REGISTER BOT + USER CALLBACK
--------------------------------- */

app.post("/api/register", requireTbc, async (req, res) => {
  try {
    const token = req.body?.bot_token;
    const webhookUrl = req.body?.webhook_url;
    const tbcUserId = String(req.body?.tbc_user_id ?? "");

    if (
      typeof token !== "string" ||
      !/^\d{5,20}:[A-Za-z0-9_-]{20,}$/.test(token)
    ) {
      return reply(res, 400, "error", "Invalid token", "Provide a valid bot token.");
    }

    if (!validateTbcWebhook(webhookUrl)) {
      return reply(
        res, 400, "error", "Invalid webhook",
        "A trusted HTTPS TBC webhook URL is required."
      );
    }

    if (!/^\d{1,20}$/.test(tbcUserId)) {
      return reply(res, 400, "error", "Invalid user", "Valid TBC user ID required.");
    }

    const tgResponse = await fetch(
      `https://api.telegram.org/bot${token}/getMe`,
      { signal: AbortSignal.timeout(8000) }
    );

    const tg = await tgResponse.json();

    if (!tgResponse.ok || !tg.ok || !tg.result?.username) {
      return reply(
        res, 400, "error", "Invalid token",
        "Telegram did not validate this bot token."
      );
    }

    const botKey = sha(token);

    await sql`
      INSERT INTO registered_bots (bot_key, bot_username, bot_token_enc)
      VALUES (${botKey}, ${tg.result.username}, ${encrypt(token)})
      ON CONFLICT (bot_key)
      DO UPDATE SET
        bot_username = EXCLUDED.bot_username,
        bot_token_enc = EXCLUDED.bot_token_enc
    `;

    const id = randomId();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    await sql`
      INSERT INTO temporary_registration_ids (
        id_hash, bot_key, expires_at, webhook_url, tbc_user_id
      )
      VALUES (
        ${sha(id)}, ${botKey}, ${expiresAt}, ${webhookUrl}, ${tbcUserId}
      )
    `;

    return reply(
      res, 201, "success", "Bot registered",
      "Temporary registration expires in 5 minutes.",
      {
        registration_id: id,
        expires_at: expiresAt,
        bot_username: tg.result.username,
        webapp_url: `${ORIGIN}/?registration_id=${encodeURIComponent(id)}`
      }
    );
  } catch (error) {
    console.error("register:", error.message);

    return reply(res, 500, "error", "Server error", "Could not register bot.");
  }
});

/* --------------------------------
   REGISTRATION INFO
--------------------------------- */

app.post("/api/registration-info", async (req, res) => {
  try {
    const id = req.body?.registration_id;

    if (typeof id !== "string" || id.length < 30 || id.length > 100) {
      return reply(res, 400, "error", "Invalid ID", "Registration ID is invalid.");
    }

    const rows = await sql`
      SELECT bot_key
      FROM temporary_registration_ids
      WHERE id_hash = ${sha(id)}
        AND used_at IS NULL
        AND expires_at > NOW()
      LIMIT 1
    `;

    if (!rows.length) {
      return reply(
        res, 410, "error", "ID expired or used",
        "Request a new registration link from your bot."
      );
    }

    const bots = await sql`
      SELECT bot_username
      FROM registered_bots
      WHERE bot_key = ${rows[0].bot_key}
      LIMIT 1
    `;

    if (!bots.length) {
      return reply(res, 404, "error", "Bot not found", "Registered bot not found.");
    }

    return reply(
      res, 200, "success", "Registration loaded",
      "Bot information loaded.",
      { bot_username: bots[0].bot_username }
    );
  } catch (error) {
    console.error("registration-info:", error.message);

    return reply(res, 500, "error", "Server error", "Could not load registration.");
  }
});

/* --------------------------------
   VERIFY DEVICE
--------------------------------- */

app.post("/api/verify", async (req, res) => {
  try {
    const id = req.body?.registration_id;
    const initData = req.body?.init_data;
    const deviceId = req.body?.device_id;

    if (
      typeof id !== "string" || id.length < 30 || id.length > 100 ||
      typeof initData !== "string" || initData.length > 10000 ||
      typeof deviceId !== "string" ||
      deviceId.length < 16 || deviceId.length > 200
    ) {
      return reply(
        res, 400, "error", "Missing data",
        "Open the official Telegram Mini App with valid data."
      );
    }

    const platform = mobilePlatform(req);

    if (!platform) {
      return reply(
        res, 403, "error", "Device rejected",
        "Only Android and iOS mobile devices are supported."
      );
    }

    const ip = getClientIp(req);

    if (!ip || net.isIP(ip) === 0) {
      return reply(res, 400, "error", "IP unavailable", "Could not determine connection IP.");
    }

    const risk = await checkIpRisk(ip);

    if (!risk.ok) {
      return reply(
        res, 503, "error", "Security check unavailable",
        "VPN check is temporarily unavailable. Please try again."
      );
    }

    if (risk.vpn || risk.proxy || risk.tor) {
      return reply(
        res, 403, "error", "VPN/proxy detected",
        "Turn off your VPN or proxy and try again."
      );
    }

    const ids = await sql`
      SELECT bot_key, webhook_url, tbc_user_id
      FROM temporary_registration_ids
      WHERE id_hash = ${sha(id)}
        AND used_at IS NULL
        AND expires_at > NOW()
      LIMIT 1
    `;

    if (!ids.length) {
      return reply(
        res, 410, "error", "Registration ID expired",
        "Request a new registration link from your bot."
      );
    }

    const registration = ids[0];
    const botKey = registration.bot_key;

    const botRows = await sql`
      SELECT bot_username, bot_token_enc
      FROM registered_bots
      WHERE bot_key = ${botKey}
      LIMIT 1
    `;

    if (!botRows.length) {
      return reply(res, 404, "error", "Bot not found", "Please register this bot again.");
    }

    const bot = botRows[0];
    const user = telegramInitDataValid(initData, decrypt(bot.bot_token_enc));

    if (!user || !user.id) {
      await sql`
        INSERT INTO verification_events (bot_key, event_type, details)
        VALUES (
          ${botKey},
          'rejected_invalid_telegram_auth',
          ${JSON.stringify({ platform })}::jsonb
        )
      `;

      return reply(
        res, 401, "error", "Telegram verification failed",
        "Open the official Mini App from Telegram."
      );
    }

    const telegramId = String(user.id);

    if (telegramId !== String(registration.tbc_user_id)) {
      await sql`
        INSERT INTO verification_events (
          bot_key, telegram_user_id, event_type, details
        )
        VALUES (
          ${botKey}, ${telegramId}, 'rejected_tbc_user_mismatch',
          ${JSON.stringify({ platform })}::jsonb
        )
      `;

      return reply(
        res, 403, "error", "Wrong Telegram account",
        "Open the verification link from the account that requested it."
      );
    }

    const webhookUrl = registration.webhook_url;
    const deviceHash = sha(`${botKey}:${deviceId}`);

    const existingUser = await sql`
      SELECT device_hash
      FROM device_registrations
      WHERE bot_key = ${botKey}
        AND telegram_user_id = ${telegramId}
      LIMIT 1
    `;

    if (existingUser.length) {
      if (existingUser[0].device_hash === deviceHash) {
        await sql`
          UPDATE temporary_registration_ids
          SET used_at = NOW()
          WHERE id_hash = ${sha(id)} AND used_at IS NULL
        `;

        await sendTbcCallback(webhookUrl, {
          status: "info",
          title: "Already Verified",
          message: "This Telegram account and device are already verified."
        });

        return reply(
          res, 200, "info", "Already Verified",
          "Already verified by this device on this account."
        );
      }

      return reply(
        res, 409, "error", "Account already registered",
        "This Telegram account has already been registered for this bot."
      );
    }

    const existingDevice = await sql`
      SELECT telegram_user_id
      FROM device_registrations
      WHERE bot_key = ${botKey}
        AND device_hash = ${deviceHash}
      LIMIT 1
    `;

    if (existingDevice.length) {
      await sql`
        INSERT INTO verification_events (
          bot_key, telegram_user_id, event_type, details
        )
        VALUES (
          ${botKey}, ${telegramId}, 'rejected_device_in_use',
          ${JSON.stringify({ platform })}::jsonb
        )
      `;

      return reply(
        res, 409, "error", "Device already registered",
        "This device is already registered to another Telegram account for this bot."
      );
    }

    // Unique database constraints remain the final duplicate safeguard.
    await sql`
      INSERT INTO device_registrations (
        bot_key, telegram_user_id, device_hash,
        platform, username, first_name, status
      )
      VALUES (
        ${botKey}, ${telegramId}, ${deviceHash},
        ${platform}, ${user.username || null},
        ${user.first_name || null}, 'verified'
      )
    `;

    await sql`
      UPDATE temporary_registration_ids
      SET used_at = NOW()
      WHERE id_hash = ${sha(id)} AND used_at IS NULL
    `;

    await sql`
      INSERT INTO verification_events (
        bot_key, telegram_user_id, event_type, details
      )
      VALUES (
        ${botKey}, ${telegramId}, 'verified',
        ${JSON.stringify({ platform, risk_source: risk.source })}::jsonb
      )
    `;

    // Callback is best-effort; the database verification is already saved.
    await sendTbcCallback(webhookUrl, {
      status: "success",
      title: "Device Verified",
      message: "Your Telegram account has been verified successfully.",
      telegram_user_id: telegramId,
      username: user.username || "",
      first_name: user.first_name || ""
    });

    return reply(
      res, 200, "success", "Verification successful",
      "Your Telegram account has been verified for this bot.",
      { verified: true, bot_username: bot.bot_username }
    );
  } catch (error) {
    if (error.code === "23505") {
      return reply(
        res, 409, "error", "Duplicate registration",
        "This account or device is already registered for this bot."
      );
    }

    console.error("verify:", error.message);

    return reply(
      res, 500, "error", "Server error",
      "Verification could not be completed."
    );
  }
});

/* --------------------------------
   STATIC WEBSITE + 404
--------------------------------- */

app.use(express.static(
  path.join(__dirname, "public"),
  { index: "index.html", maxAge: "1h" }
));

app.use((req, res) => {
  return reply(res, 404, "error", "Not found", "Endpoint not found.");
});

const port = Number(process.env.PORT || 3000);

app.listen(port, () => {
  console.log(`TXG verification server listening on ${port}`);
});
