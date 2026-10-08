const SESSION_COOKIE = "tovikeli_session";
const SESSION_DAYS = 30;
const PASSWORD_ITERATIONS = 100_000;
const PASSWORD_BYTES = 32;
const SALT_BYTES = 16;

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
  if (url.pathname === "/api/auth/login" && request.method === "POST") {
    return handleLogin(request, env);
  }
  if (url.pathname === "/api/auth/logout" && request.method === "POST") {
    return handleLogout(request, env);
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

  const email = normalizeEmail(body.email);

  const existing = await env.DB
    .prepare("SELECT id FROM users WHERE email = ?1 LIMIT 1")
    .bind(email)
    .first();

  if (existing) {
    return json({ error: { code: "email_taken" } }, 409);
  }

  const userId = `u_${crypto.randomUUID()}`;
  const createdAt = new Date().toISOString();
  const passwordHash = await hashPassword(body.password);

  await env.DB
    .prepare(
      "INSERT INTO users (id, email, password_hash, created_at) VALUES (?1, ?2, ?3, ?4)"
    )
    .bind(userId, email, passwordHash, createdAt)
    .run();

  const session = await createSession(env.DB, userId);

  return json(
    { user: { id: userId, email, createdAt } },
    201,
    { "Set-Cookie": buildSessionCookie(session.id, session.expiresAt) }
  );
}

async function handleLogin(request, env) {
  const body = await readJson(request);
  const validation = validateCredentials(body);
  if (!validation.ok) {
    return json({ error: { code: "validation_error", fields: validation.fields } }, 400);
  }

  const email = normalizeEmail(body.email);

  const user = await env.DB
    .prepare("SELECT id, email, password_hash, created_at FROM users WHERE email = ?1 LIMIT 1")
    .bind(email)
    .first();

  if (!user) {
    return json({ error: { code: "invalid_credentials" } }, 401);
  }

  const valid = await verifyPassword(body.password, user.password_hash);
  if (!valid) {
    return json({ error: { code: "invalid_credentials" } }, 401);
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
      `SELECT s.id, s.user_id, s.expires_at, u.email, u.created_at
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

  if (new Date(session.expires_at).getTime() <= Date.now()) {
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
