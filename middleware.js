// ZMG universal login gate — framework-agnostic Vercel Routing Middleware.
// Works on Next.js apps AND plain static/Vite/CRA apps deployed to Vercel,
// because it only uses standard Request/Response + the @vercel/functions
// `next()` helper (NOT next/server, which only exists inside Next.js apps).
//
// Setup per app:
//   1. Copy this file to the project root as `middleware.js`.
//   2. Add "@vercel/functions" to package.json dependencies (any recent
//      version is fine, it has ~0 transitive deps).
//   3. Set two env vars on the app (same values everywhere):
//        AUTH_JWT_SECRET  -- same secret as the ZMG Auth Hub
//        AUTH_HUB_URL     -- e.g. https://zmg-auth-hub.vercel.app
//
// Do not edit the matcher below unless you know what you're adding to it --
// it deliberately protects everything except static assets.

import { jwtVerify, SignJWT } from "jose";
import { next } from "@vercel/functions";

const COOKIE_NAME = "zmg_session";
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 400; // 400 days

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

async function signSession(email) {
  return await new SignJWT({ email, purpose: "session" })
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

function redirectWithClearedCookie(location) {
  const headers = new Headers({ Location: location });
  headers.append(
    "Set-Cookie",
    `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
  );
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

function loginRedirect(request) {
  const hubUrl = process.env.AUTH_HUB_URL;
  const returnTo = encodeURIComponent(request.url);
  return Response.redirect(`${hubUrl}/login?return_to=${returnTo}`, 302);
}

export default async function middleware(request) {
  const url = new URL(request.url);
  const exchangeToken = url.searchParams.get("zmg_token");

  // Local logout: clears this app's cookie, then bounces through the hub's
  // own logout so the next login (here or elsewhere) asks for a fresh code.
  if (url.pathname === "/zmg-logout") {
    const hubUrl = process.env.AUTH_HUB_URL;
    const appOrigin = `${url.protocol}//${url.host}/`;
    return redirectWithClearedCookie(
      `${hubUrl}/logout?return_to=${encodeURIComponent(appOrigin)}`,
    );
  }

  // Coming back from the hub with a freshly verified one-time token --
  // exchange it locally (no network call) for this app's own session cookie.
  if (exchangeToken) {
    const payload = await verify(exchangeToken);
    if (payload?.purpose === "exchange" && payload?.email) {
      url.searchParams.delete("zmg_token");
      const sessionToken = await signSession(payload.email);
      return redirectWithSessionCookie(url.toString(), sessionToken);
    }
    // Bad/expired exchange token -- fall through to a normal login redirect.
    return loginRedirect(request);
  }

  const sessionCookie = readCookie(request, COOKIE_NAME);
  if (sessionCookie) {
    const payload = await verify(sessionCookie);
    if (payload?.purpose === "session" && payload?.email) {
      return next();
    }
  }

  return loginRedirect(request);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\.(?:png|jpg|jpeg|gif|svg|ico|webp|css|js|woff2?)$).*)"],
};
