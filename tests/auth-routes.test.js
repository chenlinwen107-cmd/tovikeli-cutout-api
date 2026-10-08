import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.js";

async function request(path, { method = "GET", body, contentType = "application/json" } = {}) {
  const headers = new Headers();
  if (contentType) headers.set("Content-Type", contentType);
  return worker.fetch(new Request(`https://worker.test${path}`, {
    method,
    headers,
    ...(body !== undefined ? { body: typeof body === "string" ? body : JSON.stringify(body) } : {}),
  }), {});
}

test("health endpoint returns an uncached success response", async () => {
  const response = await request("/api/health");
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.deepEqual(await response.json(), { ok: true, service: "tovikeli-cutout-api" });
});

test("unknown routes return JSON 404", async () => {
  const response = await request("/does-not-exist");
  assert.equal(response.status, 404);
  assert.match(response.headers.get("Content-Type"), /application\/json/);
  assert.deepEqual(await response.json(), { error: { code: "not_found" } });
});

test("registration rejects missing credentials before touching D1", async () => {
  const response = await request("/api/auth/register", { method: "POST", body: {} });
  assert.equal(response.status, 400);
  const payload = await response.json();
  assert.equal(payload.error.code, "validation_error");
  assert.ok(payload.error.fields.email);
  assert.ok(payload.error.fields.password);
});

test("registration rejects malformed JSON safely", async () => {
  const response = await request("/api/auth/register", {
    method: "POST",
    body: "{not-json",
  });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, "validation_error");
});

test("resend rejects malformed email before touching D1", async () => {
  const response = await request("/api/auth/resend-verification", {
    method: "POST",
    body: { email: "not-an-email" },
  });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, "validation_error");
});

test("resend rejects missing email before touching D1", async () => {
  const response = await request("/api/auth/resend-verification", {
    method: "POST",
    body: {},
  });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, "validation_error");
});

test("resend rejects non-JSON content types safely", async () => {
  const response = await request("/api/auth/resend-verification", {
    method: "POST",
    body: '{"email":"person@example.com"}',
    contentType: "text/plain",
  });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, "validation_error");
});

test("verification GET without a token shows an invalid-link page without touching D1", async () => {
  const response = await request("/api/auth/verify-email");
  assert.equal(response.status, 200);
  assert.match(response.headers.get("Content-Type"), /text\/html/);
  assert.match(await response.text(), /验证链接无效/);
  assert.equal(response.headers.get("Cache-Control"), "no-store");
});

test("login rejects missing credentials before touching D1", async () => {
  const response = await request("/api/auth/login", { method: "POST", body: {} });
  assert.equal(response.status, 400);
  const payload = await response.json();
  assert.equal(payload.error.code, "validation_error");
  assert.ok(payload.error.fields.email);
  assert.ok(payload.error.fields.password);
});

test("logout clears the session cookie without requiring a database lookup", async () => {
  const response = await request("/api/auth/logout", { method: "POST" });
  assert.equal(response.status, 200);
  assert.match(response.headers.get("Set-Cookie"), /tovikeli_session=/);
  assert.match(response.headers.get("Set-Cookie"), /Max-Age=0/);
});
