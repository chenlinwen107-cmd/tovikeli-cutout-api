const SESSION_COOKIE = "tovikeli_session";
const SESSION_DAYS = 30;
const PASSWORD_ITERATIONS = 100_000;
const PASSWORD_BYTES = 32;
const SALT_BYTES = 16;
const VERIFY_TOKEN_MINUTES = 30;
const EMAIL_FROM = "Tovikeli <noreply@tovikeli.top>";

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      console.error("Unhandled error:", error);
      return json({ error: { code: "server_error" } }, 500);
    }
  },
};

async function handleRequest(request, env) {
  const url = new URL(request.url);

  if (url.pathname === "/api/auth/me" && request.method === "GET") {
    return handleMe(request, env);
  }
  if (url.pathname === "/api/auth/register" && request.method === "POST") {
    return handleRegister(request, env);
  }
  if (url.pathname === "/api/auth/resend-verification" && request.method === "POST") {
    return handleResendVerification(request, env);
  }
  if (url.pathname === "/api/auth/login" && request.method === "POST") {
    return handleLogin(request, env);
  }
  if (url.pathname === "/api/auth/logout" && request.method === "POST") {
    return handleLogout(request, env);
  }
  if (url.pathname === "/api/auth/verify-email" && request.method === "GET") {
    return handleVerifyEmail(url, env, true);
  }
  if (url.pathname === "/api/auth/verify-email" && request.method === "POST") {
    return handleVerifyEmail(url, env, false);
  }
  if (url.pathname === "/api/health" && request.method === "GET") {
    return json({ ok: true, service: "tovikeli-cutout-api" });
  }

  return json({ error: { code: "not_found" } }, 404);
}

async function handleRegister(request, env) {
  const body = await readJson(request);
  const validation = validateCredentials(body);
  if (!validation.ok) {
    return json({ error: { code: "validation_error", fields: validation.fields } }, 400);
  }
  if (!env.RESEND_API_KEY || !env.VERIFY_EMAIL_TEMPLATE_ID) {
    return json({ error: { code: "email_service_not_configured" } }, 503);
  }

  const email = normalizeEmail(body.email);
  const existing = await env.DB
    .prepare("SELECT id FROM users WHERE email = ?1 LIMIT 1")
    .bind(email)
    .first();
  if (existing) return json({ error: { code: "email_taken" } }, 409);

  const userId = `u_${crypto.randomUUID()}`;
  const createdAt = new Date().toISOString();
  const passwordHash = await hashPassword(body.password);
  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  const expiresAt = new Date(Date.now() + VERIFY_TOKEN_MINUTES * 60_000).toISOString();

  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO users (id, email, password_hash, created_at, email_verified) VALUES (?1, ?2, ?3, ?4, 0)"
    ).bind(userId, email, passwordHash, createdAt),
    env.DB.prepare(
      "INSERT INTO email_verification_tokens (token_hash, user_id, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)"
    ).bind(tokenHash, userId, expiresAt, createdAt),
  ]);

  const verificationUrl = new URL("/api/auth/verify-email", request.url);
  verificationUrl.searchParams.set("token", token);

  try {
    await sendTemplateEmail(env, {
      to: email,
      templateId: env.VERIFY_EMAIL_TEMPLATE_ID,
      variables: {
        USER_NAME: "用户",
        VERIFICATION_URL: verificationUrl.toString(),
        EXPIRES_IN: String(VERIFY_TOKEN_MINUTES),
      },
      idempotencyKey: `verify-email/${userId}/${tokenHash}`,
    });
  } catch (error) {
    console.error("Verification email send failed:", error);
    try {
      await env.DB.batch([
        env.DB.prepare("DELETE FROM email_verification_tokens WHERE user_id = ?1").bind(userId),
        env.DB.prepare("DELETE FROM users WHERE id = ?1 AND email_verified = 0").bind(userId),
      ]);
    } catch (cleanupError) {
      console.error("Registration cleanup failed", {
        userId,
        error: String(cleanupError),
      });
    }
    return json({ error: { code: "verification_email_failed" } }, 502);
  }

  return json({
    ok: true,
    verificationRequired: true,
    message: "请检查邮箱并点击验证链接。验证链接 30 分钟内有效。",
  }, 201);
}

async function handleResendVerification(request, env) {
  const body = await readJson(request);
  const emailInput = typeof body?.email === "string" ? body.email.trim() : "";
  if (!emailInput || emailInput.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailInput)) {
    return json({ error: { code: "validation_error", fields: { email: "invalid" } } }, 400);
  }
  if (!env.RESEND_API_KEY || !env.VERIFY_EMAIL_TEMPLATE_ID) {
    return json({ error: { code: "email_service_not_configured" } }, 503);
  }

  const email = normalizeEmail(emailInput);
  const genericResponse = () => json({
    ok: true,
    message: "如果该邮箱对应尚未验证的账户且当前允许发送，验证邮件将会发送。请检查收件箱和垃圾邮件文件夹。",
  });

  const user = await env.DB
    .prepare("SELECT id, email_verified FROM users WHERE email = ?1 LIMIT 1")
    .bind(email)
    .first();
  if (!user || user.email_verified) return genericResponse();

  const now = new Date().toISOString();
  const emailHash = await sha256Hex(email);
  const slot = await env.DB.prepare(
    `INSERT INTO email_verification_resend_limits
       (email_hash, window_started_at, last_sent_at, send_count,
        daily_window_started_at, daily_send_count)
     VALUES (?1, ?2, ?2, 1, ?2, 1)
     ON CONFLICT(email_hash) DO UPDATE SET
       daily_window_started_at = CASE
         WHEN daily_window_started_at IS NULL
           OR unixepoch(?2) - unixepoch(daily_window_started_at) >= 86400 THEN ?2
         ELSE daily_window_started_at
       END,
       daily_send_count = CASE
         WHEN daily_window_started_at IS NULL
           OR unixepoch(?2) - unixepoch(daily_window_started_at) >= 86400 THEN 1
         ELSE daily_send_count + 1
       END,
       window_started_at = CASE
         WHEN unixepoch(?2) - unixepoch(window_started_at) >= 3600 THEN ?2
         ELSE window_started_at
       END,
       send_count = CASE
         WHEN unixepoch(?2) - unixepoch(window_started_at) >= 3600 THEN 1
         ELSE send_count + 1
       END,
       last_sent_at = ?2
     WHERE
       daily_window_started_at IS NULL
       OR unixepoch(?2) - unixepoch(daily_window_started_at) >= 86400
       OR (
         daily_send_count < 5
         AND (
           unixepoch(?2) - unixepoch(window_started_at) >= 3600
           OR (unixepoch(?2) - unixepoch(last_sent_at) >= 60 AND send_count < 3)
         )
       )
     RETURNING send_count, daily_send_count`
  ).bind(emailHash, now).first();

  // Return the same response for rate-limited and unknown/verified addresses.
  if (!slot) return genericResponse();

  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  const expiresAt = new Date(Date.now() + VERIFY_TOKEN_MINUTES * 60_000).toISOString();
  await env.DB.prepare(
    "INSERT INTO email_verification_tokens (token_hash, user_id, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)"
  ).bind(tokenHash, user.id, expiresAt, now).run();

  const verificationUrl = new URL("/api/auth/verify-email", request.url);
  verificationUrl.searchParams.set("token", token);

  try {
    await sendTemplateEmail(env, {
      to: email,
      templateId: env.VERIFY_EMAIL_TEMPLATE_ID,
      variables: {
        USER_NAME: "用户",
        VERIFICATION_URL: verificationUrl.toString(),
        EXPIRES_IN: String(VERIFY_TOKEN_MINUTES),
      },
      idempotencyKey: `verify-email-resend/${user.id}/${tokenHash}`,
    });
  } catch (error) {
    console.error("Verification resend failed:", error);
    try {
      await env.DB.prepare("DELETE FROM email_verification_tokens WHERE token_hash = ?1").bind(tokenHash).run();
    } catch (cleanupError) {
      console.error("Resend token cleanup failed", {
        userId: user.id,
        error: String(cleanupError),
      });
    }
    // The rate-limit slot remains consumed to prevent retries from bypassing the cooldown.
    return json({ error: { code: "verification_email_failed" } }, 502);
  }

  try {
    await env.DB.prepare(
      "DELETE FROM email_verification_tokens WHERE user_id = ?1 AND token_hash <> ?2"
    ).bind(user.id, tokenHash).run();
  } catch (cleanupError) {
    // The new email is already sent; old links may remain valid until used or expired.
    console.error("Old verification token cleanup failed", {
      userId: user.id,
      error: String(cleanupError),
    });
  }

  return genericResponse();
}

async function handleLogin(request, env) {
  const body = await readJson(request);
  const validation = validateCredentials(body);
  if (!validation.ok) {
    return json({ error: { code: "validation_error", fields: validation.fields } }, 400);
  }

  const email = normalizeEmail(body.email);

  const user = await env.DB
    .prepare("SELECT id, email, password_hash, created_at, email_verified FROM users WHERE email = ?1 LIMIT 1")
    .bind(email)
    .first();

  if (!user) {
    return json({ error: { code: "invalid_credentials" } }, 401);
  }

  const valid = await verifyPassword(body.password, user.password_hash);
  if (!valid) {
    return json({ error: { code: "invalid_credentials" } }, 401);
  }

  if (!user.email_verified) {
    return json({ error: { code: "email_not_verified", message: "请先完成邮箱验证，再登录。" } }, 403);
  }

  const session = await createSession(env.DB, user.id);

  return json(
    {
      user: {
        id: user.id,
        email: user.email,
        createdAt: user.created_at,
      },
    },
    200,
    { "Set-Cookie": buildSessionCookie(session.id, session.expiresAt) }
  );
}

async function handleMe(request, env) {
  const sessionId = getCookie(request, SESSION_COOKIE);
  if (!sessionId) {
    return json({ error: { code: "unauthorized" } }, 401);
  }

  const session = await env.DB
    .prepare(
      `SELECT s.id, s.user_id, s.expires_at, u.email, u.created_at, u.email_verified
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.id = ?1
       LIMIT 1`
    )
    .bind(sessionId)
    .first();

  if (!session) {
    return unauthorizedWithClearedCookie();
  }

  if (new Date(session.expires_at).getTime() <= Date.now() || !session.email_verified) {
    await env.DB.prepare("DELETE FROM sessions WHERE id = ?1").bind(sessionId).run();
    return unauthorizedWithClearedCookie();
  }

  return json({
    user: {
      id: session.user_id,
      email: session.email,
      createdAt: session.created_at,
    },
  });
}

async function handleLogout(request, env) {
  const sessionId = getCookie(request, SESSION_COOKIE);

  if (sessionId) {
    await env.DB.prepare("DELETE FROM sessions WHERE id = ?1").bind(sessionId).run();
  }

  return json({ ok: true }, 200, { "Set-Cookie": clearSessionCookie() });
}


async function handleVerifyEmail(url, env, confirmOnly) {
  const token = url.searchParams.get("token") || "";
  if (!token || token.length > 200) {
    return verificationResultPage(false, "验证链接无效", "请检查邮件中的链接是否完整。");
  }

  const tokenHash = await sha256Hex(token);
  const record = await env.DB.prepare(
    `SELECT t.user_id, t.expires_at
     FROM email_verification_tokens t
     JOIN users u ON u.id = t.user_id
     WHERE t.token_hash = ?1
     LIMIT 1`
  ).bind(tokenHash).first();

  if (!record) {
    return verificationResultPage(false, "验证链接无效或已使用", "请检查链接是否完整。若仍无法验证，请联系 Tovikeli 支持。");
  }
  if (new Date(record.expires_at).getTime() <= Date.now()) {
    await env.DB.prepare("DELETE FROM email_verification_tokens WHERE token_hash = ?1").bind(tokenHash).run();
    return verificationResultPage(false, "验证链接已过期", "此链接已超过 30 分钟有效期。请返回网站重新发送验证邮件。");
  }

  if (confirmOnly) return verificationConfirmPage(token);

  // Atomically consume a still-valid token while changing the account state.
  // Concurrent POSTs using the same token cannot both perform the state transition.
  const verified = await env.DB.prepare(
    `UPDATE users
     SET email_verified = 1
     WHERE id = ?1
       AND email_verified = 0
       AND EXISTS (
         SELECT 1 FROM email_verification_tokens
         WHERE token_hash = ?2 AND user_id = ?1 AND expires_at > ?3
       )
     RETURNING id`
  ).bind(record.user_id, tokenHash, new Date().toISOString()).first();

  if (!verified) {
    return verificationResultPage(false, "验证链接无效或已使用", "此链接可能已使用或已过期。请返回网站重新发送验证邮件。");
  }

  await env.DB.prepare("DELETE FROM email_verification_tokens WHERE user_id = ?1").bind(record.user_id).run();

  return verificationResultPage(
    true,
    "邮箱验证成功",
    "你的 Tovikeli 账户已完成邮箱验证。现在可以返回网站登录并开始使用。",
    safeAppUrl(env.APP_BASE_URL)
  );
}

async function sendTemplateEmail(env, { to, templateId, variables, idempotencyKey }) {
  if (!env.RESEND_API_KEY || !templateId) throw new Error("Resend API key or template alias is missing");
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
      "Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify({
      from: EMAIL_FROM,
      to: [to],
      template: { id: templateId, variables },
    }),
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`Resend API returned ${response.status}: ${detail.slice(0, 400)}`);
  }
  return response.json();
}

function randomToken() {
  return base64url(crypto.getRandomValues(new Uint8Array(32)));
}

async function sha256Hex(value) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function safeAppUrl(value) {
  try {
    const url = new URL(value || "https://cutout.tovikeli.top/");
    return url.protocol === "https:" ? url.toString() : "https://cutout.tovikeli.top/";
  } catch {
    return "https://cutout.tovikeli.top/";
  }
}

function verificationConfirmPage(token) {
  const action = escapeHtml("/api/auth/verify-email?token=" + encodeURIComponent(token));
  const html = '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Tovikeli 邮箱验证</title></head><body><main><h1>确认邮箱验证</h1><p>点击按钮完成邮箱验证。如果你没有注册账户，可以关闭此页面。</p><form method="post" action="' + action + '"><button type="submit">确认并验证邮箱</button></form><p>Tovikeli</p></main></body></html>';
  return new Response(html, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff" } });
}

function verificationResultPage(success, title, message, redirectUrl = "") {
  const target = redirectUrl ? escapeHtml(redirectUrl) : "";
  const refresh = success && target ? `<meta http-equiv="refresh" content="4;url=${target}">` : "";
  const button = success && target
    ? `<a class="button" href="${target}">返回 Tovikeli</a>`
    : '<a class="button" href="https://cutout.tovikeli.top/">打开 Tovikeli</a>';
  const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">${refresh}
<title>${escapeHtml(title)} · Tovikeli</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:#f6f8f7;color:#202522;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}.card{width:100%;max-width:440px;background:#fff;border:1px solid #edf0ee;border-radius:18px;padding:36px 28px;text-align:center;box-shadow:0 12px 36px rgba(20,40,30,.05)}.icon{width:52px;height:52px;margin:0 auto 20px;border-radius:50%;display:grid;place-items:center;background:${success ? "#e8f9ef" : "#fff5e6"};color:${success ? "#06C668" : "#b7791f"};font-size:28px;font-weight:700}h1{margin:0 0 12px;font-size:24px;line-height:1.4}p{margin:0;color:#66716b;font-size:15px;line-height:1.8}.button{display:inline-block;margin-top:26px;padding:12px 20px;border-radius:9px;background:#06C668;color:#fff;text-decoration:none;font-weight:600}.brand{margin-top:28px;color:#06C668;font-size:18px;font-weight:700}</style>
</head><body><main class="card"><div class="icon">${success ? "✓" : "!"}</div><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>${button}<div class="brand">Tovikeli</div>${success && target ? '<p style="margin-top:14px;font-size:12px">4 秒后自动返回网站</p>' : ""}</main></body></html>`;
  return new Response(html, {
    status: success ? 200 : 400,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" },
  });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

async function createSession(db, userId) {
  const id = `s_${crypto.randomUUID()}`;
  const createdAt = new Date();
  const expiresAt = new Date(
    createdAt.getTime() + SESSION_DAYS * 24 * 60 * 60 * 1000
  );

  await db
    .prepare(
      "INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)"
    )
    .bind(id, userId, expiresAt.toISOString(), createdAt.toISOString())
    .run();

  return { id, expiresAt: expiresAt.toISOString() };
}

function validateCredentials(body) {
  const fields = {};

  if (!body || typeof body.email !== "string") {
    fields.email = "请输入有效的邮箱地址。";
  } else {
    const email = normalizeEmail(body.email);
    if (!email || email.length > 254 || !/^\S+@\S+\.\S+$/.test(email)) {
      fields.email = "请输入有效的邮箱地址。";
    }
  }

  if (!body || typeof body.password !== "string") {
    fields.password = "请输入密码。";
  } else if (body.password.length < 8) {
    fields.password = "密码至少 8 位。";
  } else if (body.password.length > 200) {
    fields.password = "密码过长。";
  }

  return { ok: Object.keys(fields).length === 0, fields };
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const derived = await derivePassword(password, salt, PASSWORD_ITERATIONS);
  return `pbkdf2_sha256$${PASSWORD_ITERATIONS}$${base64url(salt)}$${base64url(derived)}`;
}

async function verifyPassword(password, stored) {
  try {
    const [algorithm, iterationsText, saltText, hashText] = String(stored).split("$");
    if (algorithm !== "pbkdf2_sha256") return false;

    const iterations = Number(iterationsText);
    if (!Number.isInteger(iterations) || iterations < 1 || iterations > 1_000_000) {
      return false;
    }

    const salt = base64urlDecode(saltText);
    const expected = base64urlDecode(hashText);
    const actual = await derivePassword(password, salt, iterations);

    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

async function derivePassword(password, salt, iterations) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    PASSWORD_BYTES * 8
  );

  return new Uint8Array(bits);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64urlDecode(value) {
  const text = String(value);
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") +
    "===".slice((text.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const [rawName, ...rest] = part.trim().split("=");
    if (rawName === name) return rest.join("=");
  }
  return null;
}

function buildSessionCookie(id, expiresAt) {
  return `${SESSION_COOKIE}=${id}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${new Date(expiresAt).toUTCString()}`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function unauthorizedWithClearedCookie() {
  return json(
    { error: { code: "unauthorized" } },
    401,
    { "Set-Cookie": clearSessionCookie() }
  );
}

async function readJson(request) {
  try {
    const contentType = request.headers.get("Content-Type") || "";
    if (!contentType.toLowerCase().includes("application/json")) return null;
    return await request.json();
  } catch {
    return null;
  }
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}
