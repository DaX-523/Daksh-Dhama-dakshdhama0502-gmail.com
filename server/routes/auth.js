import { randomUUID } from 'node:crypto';
import { sql, newId, nowIso } from '../db.js';
import { send, badRequest, unauthenticated, forbidden, notFound } from '../http.js';
import {
  issueAccessToken, verifyPassword, hashPassword, newRefreshToken, hashRefreshToken,
  ACCESS_TTL_SECONDS, REFRESH_TTL_SECONDS,
} from '../auth.js';
import { resolve } from '../permissions.js';

const COOKIE = 'refresh';
const COOKIE_ATTRS = 'HttpOnly; Secure; SameSite=Strict; Path=/v1/auth';

// Unknown emails still pay for a scrypt, so response time does not reveal which accounts exist.
const DUMMY_HASH = hashPassword(randomUUID());

function readCookie(req, name) {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return rest.join('=');
  }
  return null;
}

const setRefreshCookie = (res, raw) =>
  res.setHeader('set-cookie', `${COOKIE}=${raw}; ${COOKIE_ATTRS}; Max-Age=${REFRESH_TTL_SECONDS}`);
const clearRefreshCookie = (res) => res.setHeader('set-cookie', `${COOKIE}=; ${COOKIE_ATTRS}; Max-Age=0`);

const userById = (db, id) => sql(db, 'SELECT id, email, name FROM users WHERE id = ?').get(id);

const membershipsOf = (db, userId) =>
  sql(
    db,
    `SELECT o.id, o.name, o.theme, m.role, m.status, m.perm_version
       FROM memberships m
       JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
      WHERE m.user_id = ? AND m.status IN ('active', 'suspended')
      ORDER BY o.name, o.id`
  ).all(userId);

// Not a member of the org you asked for: invisible, so 404. A member who is suspended
// can see the org but not act in it, so 403.
function pickOrg(rows, orgId) {
  if (orgId !== undefined && orgId !== null) {
    if (typeof orgId !== 'string') throw badRequest('orgId must be a string');
    const row = rows.find((r) => r.id === orgId);
    if (!row) throw notFound();
    if (row.status !== 'active') throw forbidden('your membership in this organization is suspended', 'suspended');
    return row;
  }
  const row = rows.find((r) => r.status === 'active');
  if (row) return row;
  if (rows.length) throw forbidden('your membership in this organization is suspended', 'suspended');
  throw forbidden('you are not an active member of any organization', 'no_active_membership');
}

function view(db, user, rows, org) {
  return {
    user,
    org: { id: org.id, name: org.name, theme: org.theme },
    role: org.role,
    orgs: rows.filter((r) => r.status === 'active').map(({ id, name, theme, role }) => ({ id, name, theme, role })),
    permissions: resolve(db, { userId: user.id, orgId: org.id }).permissions,
  };
}

function startRefreshFamily(db, res, userId, familyId = newId('fam')) {
  const raw = newRefreshToken();
  const expires = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString();
  sql(db, 'INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?, ?, ?, ?, ?)')
    .run(newId('rtk'), userId, hashRefreshToken(raw), familyId, expires);
  setRefreshCookie(res, raw);
}

// An access token for one org, plus everything the console needs to render that org.
export function sessionFor(db, secret, userId, orgId) {
  const user = userById(db, userId);
  const rows = membershipsOf(db, userId);
  const org = pickOrg(rows, orgId);
  const token = issueAccessToken(
    { userId: user.id, orgId: org.id, role: org.role, permVersion: org.perm_version },
    secret
  );
  return { token, expiresIn: ACCESS_TTL_SECONDS, ...view(db, user, rows, org) };
}

export function signIn(db, secret, res, userId, orgId) {
  const body = sessionFor(db, secret, userId, orgId);
  startRefreshFamily(db, res, userId);
  return body;
}

export function registerAuthRoutes(router, { db, secret }) {
  router.post('/v1/auth/login', (ctx, _params, res) => {
    const { email, password, orgId } = ctx.body;
    if (typeof email !== 'string' || typeof password !== 'string' || email.trim() === '' || password === '') {
      throw badRequest('enter your email and password', 'missing_credentials');
    }
    const found = sql(db, 'SELECT id, password_hash FROM users WHERE email = ?').get(email.trim().toLowerCase());
    const passwordOk = verifyPassword(password, found?.password_hash ?? DUMMY_HASH);
    if (!found || !passwordOk) throw unauthenticated('invalid email or password');

    send(res, 200, signIn(db, secret, res, found.id, orgId));
  });

  // Rotation: each refresh token works once. Presenting one that was already rotated means
  // it leaked, so the whole family is revoked and every holder has to sign in again.
  router.post('/v1/auth/refresh', (ctx, _params, res) => {
    const raw = readCookie(ctx.req, COOKIE);
    const row = raw ? sql(db, 'SELECT * FROM refresh_tokens WHERE token_hash = ?').get(hashRefreshToken(raw)) : null;
    const now = nowIso();
    const revokeFamily = sql(db, 'UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL');

    const refuse = () => {
      clearRefreshCookie(res);
      return unauthenticated('refresh token is not valid');
    };
    if (!row) throw refuse();
    if (row.revoked_at || row.expires_at <= now) {
      if (row.revoked_at && row.expires_at > now) revokeFamily.run(now, row.family_id);
      throw refuse();
    }

    // Built before rotating, so asking for an org you no longer belong to fails without
    // spending the cookie, and the client can retry without an org.
    const body = sessionFor(db, secret, row.user_id, ctx.body.orgId);

    const rotated = db.transaction(() => {
      const rotate = sql(db, 'UPDATE refresh_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL AND expires_at > ?');
      if (rotate.run(now, row.id, now).changes === 1) return true;
      revokeFamily.run(now, row.family_id);
      return false;
    })();
    if (!rotated) throw refuse();

    startRefreshFamily(db, res, row.user_id, row.family_id);
    send(res, 200, body);
  });

  router.post('/v1/auth/logout', (ctx, _params, res) => {
    const raw = readCookie(ctx.req, COOKIE);
    const row = raw ? sql(db, 'SELECT family_id FROM refresh_tokens WHERE token_hash = ?').get(hashRefreshToken(raw)) : null;
    if (row) sql(db, 'UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL').run(nowIso(), row.family_id);
    clearRefreshCookie(res);
    send(res, 204);
  });

  router.post('/v1/auth/token', (ctx, _params, res) => {
    if (typeof ctx.body.orgId !== 'string' || ctx.body.orgId === '') throw badRequest('orgId is required');
    send(res, 200, sessionFor(db, secret, ctx.userId, ctx.body.orgId));
  });

  router.get('/v1/auth/me', (ctx, _params, res) => {
    const user = userById(db, ctx.userId);
    const rows = membershipsOf(db, ctx.userId);
    send(res, 200, view(db, user, rows, rows.find((r) => r.id === ctx.orgId)));
  });
}
