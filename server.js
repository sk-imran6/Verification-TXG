const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { neon } = require('@neondatabase/serverless');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY === 'true');
app.use(express.json({ limit: '20kb' }));

const required = ['DATABASE_URL', 'APP_ORIGIN', 'TBC_SHARED_SECRET', 'TOKEN_ENCRYPTION_KEY'];
for (const key of required) if (!process.env[key]) throw new Error(`Missing environment variable: ${key}`);
if (Buffer.from(process.env.TOKEN_ENCRYPTION_KEY, 'hex').length !== 32) throw new Error('TOKEN_ENCRYPTION_KEY must be 64 hex characters (32 bytes).');
const sql = neon(process.env.DATABASE_URL);
const ORIGIN = process.env.APP_ORIGIN.replace(/\/$/, '');
const encKey = Buffer.from(process.env.TOKEN_ENCRYPTION_KEY, 'hex');

function sha(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function randomId() { return crypto.randomBytes(32).toString('base64url'); }
function reply(res, code, status, title, message, extra = {}) {
  res.set('Cache-Control', 'no-store');
  return res.status(code).json({ status, title, message, ...extra });
}
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encKey, iv);
  const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return [iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), data.toString('base64url')].join('.');
}
function decrypt(value) {
  const [iv, tag, data] = value.split('.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encKey, Buffer.from(iv, 'base64url'));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(data, 'base64url')), decipher.final()]).toString('utf8');
}
function requireTbc(req, res, next) {
  const supplied = req.get('x-txg-secret') || '';
  const a = Buffer.from(supplied);
  const b = Buffer.from(process.env.TBC_SHARED_SECRET);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return reply(res, 401, 'error', 'Unauthorized', 'TBC authentication failed.');
  next();
}
function mobilePlatform(req) {
  const ua = req.get('user-agent') || '';
  if (/Android/i.test(ua)) return 'android';
  if (/iPhone|iPad|iPod/i.test(ua)) return 'ios';
  return null;
}
function telegramInitDataValid(initData, token) {
  try {
    const params = new URLSearchParams(initData);
    const receivedHash = params.get('hash');
    if (!receivedHash) return null;
    params.delete('hash');
    const authDate = Number(params.get('auth_date'));
    if (!Number.isFinite(authDate) || Math.abs(Date.now() / 1000 - authDate) > 300) return null;
    const checkString = [...params.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${v}`).join('\n');
    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(token).digest();
    const expected = crypto.createHmac('sha256', secretKey).update(checkString).digest('hex');
    const x = Buffer.from(receivedHash, 'hex'); const y = Buffer.from(expected, 'hex');
    if (x.length !== y.length || !crypto.timingSafeEqual(x, y)) return null;
    const userText = params.get('user');
    if (!userText) return null;
    return JSON.parse(userText);
  } catch { return null; }
}

app.get('/health', (req, res) => res.json({ status: 'success', message: 'TXG backend running' }));

// TBC server-to-server registration. Send JSON body + X-TXG-Secret header; never use query params for tokens.
app.post('/api/register', requireTbc, async (req, res) => {
  try {
    const token = req.body?.bot_token;
    if (typeof token !== 'string' || !/^\d{5,20}:[A-Za-z0-9_-]{20,}$/.test(token)) return reply(res, 400, 'error', 'Invalid token', 'Provide a valid bot token.');
    const tgRes = await fetch(`https://api.telegram.org/bot${token}/getMe`, { signal: AbortSignal.timeout(8000) });
    const tg = await tgRes.json();
    if (!tgRes.ok || !tg.ok || !tg.result?.username) return reply(res, 400, 'error', 'Invalid token', 'Telegram did not validate this bot token.');
    const botKey = sha(token);
    await sql`INSERT INTO registered_bots (bot_key, bot_username, bot_token_enc) VALUES (${botKey}, ${tg.result.username}, ${encrypt(token)}) ON CONFLICT (bot_key) DO UPDATE SET bot_username = EXCLUDED.bot_username, bot_token_enc = EXCLUDED.bot_token_enc`;
    const id = randomId();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    await sql`INSERT INTO temporary_registration_ids (id_hash, bot_key, expires_at) VALUES (${sha(id)}, ${botKey}, ${expiresAt})`;
    return reply(res, 201, 'success', 'Bot registered', 'Temporary ID expires in 5 minutes.', { registration_id: id, expires_at: expiresAt, bot_username: tg.result.username, webapp_url: `${ORIGIN}/?registration_id=${encodeURIComponent(id)}` });
  } catch (e) {
    console.error('register:', e.message);
    return reply(res, 500, 'error', 'Server error', 'Could not register bot.');
  }
});

// Consume temporary ID once, and return only non-secret bot metadata.
app.post('/api/registration-info', async (req, res) => {
  try {
    const id = req.body?.registration_id;
    if (typeof id !== 'string' || id.length < 30 || id.length > 100) return reply(res, 400, 'error', 'Invalid ID', 'Registration ID is invalid.');
    const rows = await sql`SELECT bot_key FROM temporary_registration_ids WHERE id_hash = ${sha(id)} AND used_at IS NULL AND expires_at > NOW() LIMIT 1`;
    if (!rows.length) return reply(res, 410, 'error', 'ID expired or used', 'Request a new registration link from your bot.');
    const bots = await sql`SELECT bot_username FROM registered_bots WHERE bot_key = ${rows[0].bot_key} LIMIT 1`;
    if (!bots.length) return reply(res, 404, 'error', 'Bot not found', 'Registered bot no longer exists.');
    return reply(res, 200, 'success', 'Registration loaded', 'Bot information loaded.', { bot_username: bots[0].bot_username });
  } catch (e) {
    console.error('registration-info:', e.message);
    return reply(res, 500, 'error', 'Server error', 'Could not load registration.');
  }
});

// Actual Telegram Mini App verification. Requires the bot's valid initData and registration ID.
app.post('/api/verify', async (req, res) => {
  try {
    const id = req.body?.registration_id;
    const initData = req.body?.init_data;
    const deviceId = req.body?.device_id;
    if (typeof id !== 'string' || typeof initData !== 'string' || typeof deviceId !== 'string' || deviceId.length < 16 || deviceId.length > 200) return reply(res, 400, 'error', 'Missing data', 'Open this page from the Telegram Mini App with a valid registration ID.');
    const platform = mobilePlatform(req);
    if (!platform) return reply(res, 403, 'error', 'Device rejected', 'Only Android and iOS mobile devices are supported.');

    const ids = await sql`SELECT bot_key FROM temporary_registration_ids WHERE id_hash = ${sha(id)} AND used_at IS NULL AND expires_at > NOW() LIMIT 1`;
    if (!ids.length) return reply(res, 410, 'error', 'Registration ID expired', 'Request a new registration link from your bot.');
    const botRows = await sql`SELECT bot_username, bot_token_enc FROM registered_bots WHERE bot_key = ${ids[0].bot_key} LIMIT 1`;
    if (!botRows.length) return reply(res, 404, 'error', 'Bot not found', 'Please register this bot again.');
    const user = telegramInitDataValid(initData, decrypt(botRows[0].bot_token_enc));
    if (!user || !user.id) {
      await sql`INSERT INTO verification_events (bot_key, event_type, details) VALUES (${ids[0].bot_key}, 'rejected_invalid_telegram_auth', ${JSON.stringify({ platform })}::jsonb)`;
      return reply(res, 401, 'error', 'Telegram verification failed', 'Telegram identity could not be verified. Open the official Mini App from Telegram.');
    }
    const deviceHash = sha(`${ids[0].bot_key}:${deviceId}`);
    const existingUser = await sql`SELECT device_hash FROM device_registrations WHERE bot_key = ${ids[0].bot_key} AND telegram_user_id = ${String(user.id)} LIMIT 1`;
    if (existingUser.length) {
      if (existingUser[0].device_hash === deviceHash) return reply(res, 200, 'success', 'Already verified', 'This Telegram account is already registered on this browser installation.');
      return reply(res, 409, 'error', 'Account already registered', 'This Telegram account has already been registered for this bot.');
    }
    const existingDevice = await sql`SELECT telegram_user_id FROM device_registrations WHERE bot_key = ${ids[0].bot_key} AND device_hash = ${deviceHash} LIMIT 1`;
    if (existingDevice.length) {
      await sql`INSERT INTO verification_events (bot_key, telegram_user_id, event_type, details) VALUES (${ids[0].bot_key}, ${String(user.id)}, 'rejected_device_in_use', ${JSON.stringify({ platform })}::jsonb)`;
      return reply(res, 409, 'error', 'Device already registered', 'This browser installation is already registered to another Telegram account for this bot.');
    }
    await sql`INSERT INTO device_registrations (bot_key, telegram_user_id, device_hash, platform, username, first_name, status) VALUES (${ids[0].bot_key}, ${String(user.id)}, ${deviceHash}, ${platform}, ${user.username || null}, ${user.first_name || null}, 'verified')`;
    await sql`UPDATE temporary_registration_ids SET used_at = NOW() WHERE id_hash = ${sha(id)} AND used_at IS NULL`;
    await sql`INSERT INTO verification_events (bot_key, telegram_user_id, event_type, details) VALUES (${ids[0].bot_key}, ${String(user.id)}, 'verified', ${JSON.stringify({ platform })}::jsonb)`;
    return reply(res, 200, 'success', 'Verification successful', 'Your Telegram account has been verified for this bot.', { verified: true, bot_username: botRows[0].bot_username });
  } catch (e) {
    if (e.code === '23505') return reply(res, 409, 'error', 'Duplicate registration', 'This account or device is already registered for this bot.');
    console.error('verify:', e.message);
    return reply(res, 500, 'error', 'Server error', 'Verification could not be completed.');
  }
});

// Clean up expired temporary IDs opportunistically. Records expire regardless of cleanup timing.
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', maxAge: '1h' }));
app.use((req, res) => reply(res, 404, 'error', 'Not found', 'Endpoint not found.'));

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`TXG verification server listening on ${port}`));
