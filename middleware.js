// ZMG universal login gate v2 (Salesforce-only staff) — framework-agnostic
// Vercel Routing Middleware. Works on Next.js apps AND plain static/Vite/CRA
// apps deployed to Vercel, because it only uses standard Request/Response +
// the @vercel/functions `next()` helper.
//
// v2 (Oct 27 2026): staff must sign in with Salesforce.
//   - A staff ("employee") pass is accepted only if it carries the Salesforce
//     user id the Auth Hub got from Salesforce (sf_user_id, starts "005").
//   - Passes with no role at all (made by v1 of this file, or by old emailed
//     codes) are no longer accepted; the person signs in once more.
//   - The session cookie now keeps role / tools / sf_user_id, so the app can
//     tell staff from realtors and clients.
//   - ALLOWED_ROLES below says who this app is for. Staff-only apps:
//     ["employee"]. Apps realtors/clients also use: add their roles.
//
// Env vars (same values everywhere):
//   AUTH_JWT_SECRET  -- same secret as the ZMG Auth Hub
//   AUTH_HUB_URL     -- e.g. https://auth-hub.zmgnow.com

import { jwtVerify, SignJWT } from "jose";
import { next } from "@vercel/functions";

// Who may use this app. EDIT PER APP.
const ALLOWED_ROLES = ["employee", "realtor", "client", "guest"];

const COOKIE_NAME = "zmg_session";
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 400; // 400 days
const SF_USER_ID = /^005[a-zA-Z0-9]{12}(?:[a-zA-Z0-9]{3})?$/;

function secretKey() {
  // Never verify with a blank/short secret: a missing env var must lock the
  // app, not let a token signed with an empty key through.
  const s = process.env.AUTH_JWT_SECRET || "";
  if (s.length < 32) throw new Error("AUTH_JWT_SECRET is not set");
  return new TextEncoder().encode(s);
}

async function verify(token) {
  try {
    const { payload } = await jwtVerify(token, secretKey());
    return payload;
  } catch {
    return null;
  }
}

// The one rule: staff only via Salesforce; everyone else only if this app is
// for them. Kept tiny so it is easy to unit-test.
function passAllowed(payload) {
  if (!payload?.email) return false;
  const role = payload.role;
  if (!role || !ALLOWED_ROLES.includes(role)) return false;
  if (role === "employee" && !SF_USER_ID.test(String(payload.sf_user_id || ""))) return false;
  return true;
}

async function signSession(payload) {
  return await new SignJWT({
    email: payload.email,
    purpose: "session",
    role: payload.role,
    tools: payload.tools ?? undefined,
    sf_user_id: payload.sf_user_id || undefined,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("400d")
    .sign(secretKey());
}

function readCookie(request, name) {
  const header = request.headers.get("cookie");
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    if (key === name) return decodeURIComponent(part.slice(idx + 1).trim());
  }
  return undefined;
}

const CLEAR_COOKIE = `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;

function redirectWithClearedCookie(location) {
  const headers = new Headers({ Location: location });
  headers.append("Set-Cookie", CLEAR_COOKIE);
  return new Response(null, { status: 302, headers });
}

function redirectWithSessionCookie(location, sessionToken) {
  const headers = new Headers({ Location: location });
  headers.append(
    "Set-Cookie",
    `${COOKIE_NAME}=${sessionToken}; Path=/; Max-Age=${SESSION_MAX_AGE_SECONDS}; HttpOnly; Secure; SameSite=Lax`,
  );
  return new Response(null, { status: 302, headers });
}

// Staff-only apps (and anyone whose old pass said "employee") go straight to
// Salesforce; mixed apps show the hub page (Salesforce button + email code).
function loginUrl(request, staffHint) {
  const hubUrl = process.env.AUTH_HUB_URL;
  const returnTo = encodeURIComponent(request.url);
  const staffOnly = ALLOWED_ROLES.length === 1 && ALLOWED_ROLES[0] === "employee";
  const sso = staffOnly || staffHint ? "&sso=salesforce" : "";
  return `${hubUrl}/login?return_to=${returnTo}${sso}`;
}

// A valid pass for a role this app does not serve (e.g. a realtor on a
// staff-only tool). Sending it back to the hub would loop -- the hub would
// silently hand the same realtor pass straight back -- so say so instead.
function wrongAudience(payload) {
  return Boolean(payload?.role) && payload.role !== "employee" && !ALLOWED_ROLES.includes(payload.role);
}

function wrongAudiencePage() {
  const headers = new Headers({ "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  headers.append("Set-Cookie", CLEAR_COOKIE);
  return new Response(
    '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ZMG staff only</title></head>' +
      '<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem"><h1>This tool is for ZMG staff</h1>' +
      '<p>ZMG staff sign in with Salesforce. <a href="/zmg-logout">Sign out</a>, then sign in again with Salesforce.</p></body></html>',
    { status: 403, headers },
  );
}

// Signed-out check (11 Nov 2026, People Sync). When someone leaves, the ZMG Dashboard's
// People Sync adds them to the Auth Hub's revoked_sessions list. A pass this app made
// before that moment must stop working, so a session is checked with the hub
// (POST /api/session-status) at most every 5 minutes per person. If the hub can't be
// reached the person is let in (retried in 30 s): an outage must never lock everyone out.
const SIGNED_OUT_CACHE = new Map();
async function signedOut(token, payload) {
  const key = String(payload?.email || "").toLowerCase() + "|" + String(payload?.iat || "");
  const hit = SIGNED_OUT_CACHE.get(key);
  if (hit && Date.now() - hit.at < hit.ttl) return hit.out;
  let out = false;
  let ttl = 30 * 1000;
  try {
    // With REVOCATION_CHECK_KEY the hub is asked by email + issue time (works whatever
    // secret signed the pass); without it, by the pass itself (hub-signed passes only).
    const checkKey = process.env.REVOCATION_CHECK_KEY;
    const r = await fetch(`${process.env.AUTH_HUB_URL}/api/session-status`, {
      method: "POST",
      headers: checkKey
        ? { "Content-Type": "application/json", Authorization: `Bearer ${checkKey}` }
        : { "Content-Type": "application/json" },
      body: JSON.stringify(checkKey ? { email: payload?.email, issued_at: payload?.iat } : { token }),
      signal: AbortSignal.timeout(2500),
    });
    if (r.ok) {
      const j = await r.json();
      out = j?.reason === "signed_out";
      ttl = 5 * 60 * 1000;
    }
  } catch {
    // hub unreachable: let them in, ask again soon
  }
  if (SIGNED_OUT_CACHE.size > 2000) SIGNED_OUT_CACHE.clear();
  SIGNED_OUT_CACHE.set(key, { out, at: Date.now(), ttl });
  return out;
}

// Signed out: drop this app's cookie and send them back through sign-in (which
// refuses them). API calls get a 401 instead of a redirect.
function signedOutResponse(request, url, cookieNames) {
  const headers = new Headers();
  for (const name of cookieNames) {
    headers.append("Set-Cookie", `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
  }
  if (url.pathname.startsWith("/api/")) {
    headers.set("Content-Type", "application/json");
    return new Response(JSON.stringify({ error: "Signed out", code: "signed_out" }), { status: 401, headers });
  }
  headers.set("Location", `${process.env.AUTH_HUB_URL}/login?return_to=${encodeURIComponent(request.url)}`);
  return new Response(null, { status: 302, headers });
}

export default async function middleware(request) {
  const url = new URL(request.url);
  const exchangeToken = url.searchParams.get("zmg_token");

  // Local logout: clears this app's cookie, then bounces through the hub's
  // own logout.
  if (url.pathname === "/zmg-logout") {
    const hubUrl = process.env.AUTH_HUB_URL;
    const appOrigin = `${url.protocol}//${url.host}/`;
    return redirectWithClearedCookie(
      `${hubUrl}/logout?return_to=${encodeURIComponent(appOrigin)}`,
    );
  }

  // Coming back from the hub with a one-time token -- exchange it locally.
  if (exchangeToken) {
    const payload = await verify(exchangeToken);
    url.searchParams.delete("zmg_token");
    if (payload?.purpose === "exchange" && passAllowed(payload)) {
      const sessionToken = await signSession(payload);
      return redirectWithSessionCookie(url.toString(), sessionToken);
    }
    if (payload?.purpose === "exchange" && wrongAudience(payload)) return wrongAudiencePage();
    const cleanReq = new Request(url.toString(), request);
    return redirectWithClearedCookie(loginUrl(cleanReq, payload?.role === "employee"));
  }

  const sessionCookie = readCookie(request, COOKIE_NAME);
  if (sessionCookie) {
    const payload = await verify(sessionCookie);
    if (payload?.purpose === "session" && passAllowed(payload)) {
      if (await signedOut(sessionCookie, payload)) return signedOutResponse(request, url, [COOKIE_NAME]);
      return next();
    }
    if (payload?.purpose === "session" && wrongAudience(payload)) return wrongAudiencePage();
    // Old pass (no role, or staff without Salesforce) -- drop it and sign in again.
    return redirectWithClearedCookie(loginUrl(request, !payload?.role || payload?.role === "employee"));
  }

  return Response.redirect(loginUrl(request, false), 302);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\.(?:png|jpg|jpeg|gif|svg|ico|webp|css|js|woff2?)$).*)"],
};
