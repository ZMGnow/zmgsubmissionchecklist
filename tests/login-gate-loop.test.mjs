// Login gate: never loop (13 Nov 2026, iPhone "too many redirects"). Run: node --test tests/login-gate-loop.test.mjs
// 1. The sign-in cookie is set on a 200 "Signing in…" page, not a 302.
// 2. A cookie that didn't come back shows a page, never another trip to the Auth Hub.
// 3. A refused pass goes once to a fresh sign-in (Salesforce for staff-only apps, the hub's normal
//    page for apps realtors/clients use, marked zmg_r=1), and a second refusal shows a page.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import { SignJWT } from "jose";

process.env.AUTH_JWT_SECRET = "test-secret-for-login-gate-only-0123456789";
process.env.AUTH_HUB_URL = "https://auth-hub.example";
const src = fs.readFileSync(new URL("../middleware.js", import.meta.url), "utf8");
const staffOnly = /const ALLOWED_ROLES = \["employee"\];/.test(src);
const { default: middleware } = await import("../middleware.js");
const key = new TextEncoder().encode(process.env.AUTH_JWT_SECRET);
const sign = (claims) => new SignJWT(claims).setProtectedHeader({ alg: "HS256" }).setIssuedAt().setExpirationTime("1h").sign(key);
const req = (cookie, path = "/") => new Request(`https://app.example${path}`, { headers: cookie ? { cookie: `zmg_session=${cookie}` } : {} });
const SF = "005AB0000012345XYZ";
/* A pass the app refuses without its own "wrong audience" page: a staff pass with no Salesforce id
   (e.g. an old emailed-code sign-in). */
const refusedClaims = { email: "s@zmgnow.com", purpose: "exchange", role: "employee" };

test("exchange token for staff sets the cookie on a Signing in page", async () => {
  const t = await sign({ email: "s@zmgnow.com", purpose: "exchange", role: "employee", sf_user_id: SF });
  const res = await middleware(req(null, `/?zmg_token=${t}`));
  assert.equal(res.status, 200);
  assert.match(res.headers.get("set-cookie") || "", /^zmg_session=ey/);
  const body = await res.text();
  assert.match(body, /location\.replace\("https:\/\/app\.example\/\?zmg_x=1"\)/);
  assert.doesNotMatch(body, /zmg_token/);
});

test("cookie lost after the Signing in page: a page, never back to the hub", async () => {
  const res = await middleware(req(null, "/?zmg_x=1"));
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("location"), null);
  assert.match(await res.text(), /Couldn't keep you signed in/);
});

test("refused staff pass (no Salesforce id): once to a fresh Salesforce sign-in, marked zmg_r=1", async () => {
  const res = await middleware(req(null, `/?zmg_token=${await sign(refusedClaims)}`));
  assert.equal(res.status, 302);
  const loc = res.headers.get("location") || "";
  assert.ok(loc.startsWith("https://auth-hub.example/api/salesforce/start?return_to="), loc);
  assert.equal(decodeURIComponent(loc.split("return_to=")[1]), "https://app.example/?zmg_r=1");
});

test("refused pass with no role: Salesforce on staff-only apps, the hub's normal page on mixed apps", async () => {
  const res = await middleware(req(null, `/?zmg_token=${await sign({ email: "x@example.com", purpose: "exchange" })}`));
  assert.equal(res.status, 302);
  const loc = res.headers.get("location") || "";
  if (staffOnly) assert.ok(loc.startsWith("https://auth-hub.example/api/salesforce/start?return_to="), loc);
  else assert.ok(loc.startsWith("https://auth-hub.example/login?return_to="), loc);
  assert.match(decodeURIComponent(loc), /zmg_r=1/);
});

test("refused pass twice: a page, never another redirect", async () => {
  const res = await middleware(req(null, `/?zmg_r=1&zmg_token=${await sign(refusedClaims)}`));
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("location"), null);
  const body = await res.text();
  assert.match(body, /Couldn't keep you signed in/);
  assert.match(body, /Sign in with Salesforce/);   /* a staff pass: always Salesforce */
});
