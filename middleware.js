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
const ALLOWED_ROLES = ["employee"];

const COOKIE_NAME = "zmg_session";
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 400; // 400 days
const SF_USER_ID = /^005[a-zA-Z0-9]{12}(?:[a-zA-Z0-9]{3})?$/;

function secretKey() {
  return new TextEncoder().encode(process.env.AUTH_JWT_SECRET);
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
