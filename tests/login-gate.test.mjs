// Login gate: staff only with Salesforce. Run with `node --test`.
import assert from 'node:assert/strict';
import test from 'node:test';
import { SignJWT } from 'jose';

process.env.AUTH_JWT_SECRET = 'test-secret-for-login-gate-only-0123456789';
process.env.AUTH_HUB_URL = 'https://auth-hub.example';
const { default: middleware } = await import('../middleware.js');
const STAFF_ONLY = false; // realtors, clients and guests keep the access they had before the lockdown
const key = new TextEncoder().encode(process.env.AUTH_JWT_SECRET);
const sign = (claims) => new SignJWT(claims).setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime('1h').sign(key);
const page = (cookie, path = '/') => new Request(`https://app.example${path}`, { headers: cookie ? { cookie: `zmg_session=${cookie}` } : {} });
const isPass = (res) => res.headers.get('x-middleware-next') === '1';
const SF = '005AB0000012345XYZ';

test('Salesforce staff session gets in', async () => {
  const res = await middleware(page(await sign({ email: 's@zmgnow.com', purpose: 'session', role: 'employee', sf_user_id: SF })));
  assert.ok(isPass(res));
});

test('emailed-code staff session is cleared and sent to Salesforce', async () => {
  const res = await middleware(page(await sign({ email: 's@zmgnow.com', purpose: 'session', role: 'employee' })));
  assert.equal(res.status, 302);
  assert.match(res.headers.get('location'), /sso=salesforce/);
  assert.match(res.headers.get('set-cookie'), /zmg_session=;.*Max-Age=0/);
});

test('legacy session with no role is cleared', async () => {
  const res = await middleware(page(await sign({ email: 's@zmgnow.com', purpose: 'session' })));
  assert.equal(res.status, 302);
  assert.match(res.headers.get('set-cookie'), /Max-Age=0/);
});

test('realtor session: allowed only on mixed apps', async () => {
  const res = await middleware(page(await sign({ email: 'a@x.com', purpose: 'session', role: 'realtor' })));
  assert.equal(isPass(res), !STAFF_ONLY);
});

test('exchange: staff token keeps role and sf_user_id in the new cookie', async () => {
  const tok = await sign({ email: 's@zmgnow.com', purpose: 'exchange', role: 'employee', sf_user_id: SF });
  const res = await middleware(page(null, `/?zmg_token=${tok}`));
  assert.equal(res.status, 302);
  const cookie = res.headers.get('set-cookie').match(/zmg_session=([^;]+)/)[1];
  const claims = JSON.parse(Buffer.from(cookie.split('.')[1], 'base64url'));
  assert.equal(claims.role, 'employee');
  assert.equal(claims.sf_user_id, SF);
  assert.doesNotMatch(res.headers.get('location'), /zmg_token/);
});

test('exchange: staff token without Salesforce is refused', async () => {
  const tok = await sign({ email: 's@zmgnow.com', purpose: 'exchange', role: 'employee' });
  const res = await middleware(page(null, `/?zmg_token=${tok}`));
  assert.equal(res.status, 302);
  assert.match(res.headers.get('location'), /auth-hub\.example\/login.*sso=salesforce/);
  assert.doesNotMatch(res.headers.get('set-cookie') || '', /zmg_session=ey/);
});

test('mobile-app pass (no role) is refused', async () => {
  const res = await middleware(page(await sign({ email: 'mobile-app@zmgnow.com', purpose: 'session', client: 'mobile-app' })));
  assert.equal(res.status, 302);
});

test('no cookie goes to the hub', async () => {
  const res = await middleware(page(null));
  assert.equal(res.status, 302);
  assert.match(res.headers.get('location'), /auth-hub\.example\/login/);
});

test('send-submission API refuses non-Salesforce sessions', async () => {
  const { default: handler } = await import('../api/send-submission.js');
  const run = async (cookie) => {
    const res = { statusCode: 0, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
    await handler({ method: 'POST', headers: cookie ? { cookie: `zmg_session=${cookie}` } : {}, body: {} }, res);
    return res;
  };
  for (const claims of [null, { email: 's@zmgnow.com', purpose: 'session', role: 'employee' }, { email: 's@zmgnow.com', purpose: 'session' }]) {
    const res = await run(claims && await sign(claims));
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.code, 'salesforce_required');
  }
  // A Salesforce staff session passes the auth check (then fails validation on the empty body).
  const ok = await run(await sign({ email: 's@zmgnow.com', purpose: 'session', role: 'employee', sf_user_id: SF }));
  assert.equal(ok.statusCode, 400);
});

