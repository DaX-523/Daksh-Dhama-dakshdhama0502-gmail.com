import { randomUUID } from 'node:crypto';
import { newId, nowIso } from '../db.js';
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

export function registerAuthRoutes(router, { db, secret }) {
  const userByEmail = db.prepare('SELECT id, email, name, password_hash FROM users WHERE email = ?');
  const userById = db.prepare('SELECT id, email, name FROM users WHERE id = ?');
  const membershipsOf = db.prepare(
    `SELECT o.id, o.name, o.theme, m.role, m.status, m.perm_version
       FROM memberships m
       JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
      WHERE m.user_id = ? AND m.status IN ('active', 'suspended')
      ORDER BY o.name, o.id`
  );
  const refreshByHash = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?');
  const insertRefresh = db.prepare(
    'INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?, ?, ?, ?, ?)'
  );
  const rotateRefresh = db.prepare(
    'UPDATE refresh_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL AND expires_at > ?'
  );
  const revokeFamily = db.prepare(
    'UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL'
  );

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

  function view(user, rows, org) {
    return {
      user,
      org: { id: org.id, name: org.name, theme: org.theme },
      role: org.role,
      orgs: rows.filter((r) => r.status === 'active').map(({ id, name, theme, role }) => ({ id, name, theme, role })),
      permissions: resolve(db, { userId: user.id, orgId: org.id }).permissions,
    };
  }

  function withToken(user, rows, org) {
    const token = issueAccessToken(
      { userId: user.id, orgId: org.id, role: org.role, permVersion: org.perm_version },
      secret
    );
    return { token, expiresIn: ACCESS_TTL_SECONDS, ...view(user, rows, org) };
  }

  function startRefreshFamily(res, userId, familyId = newId('fam')) {
    const raw = newRefreshToken();
    const expires = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString();
    insertRefresh.run(newId('rtk'), userId, hashRefreshToken(raw), familyId, expires);
    setRefreshCookie(res, raw);
  }

  router.post('/v1/auth/login', (ctx, _params, res) => {
    const { email, password, orgId } = ctx.body;
    if (typeof email !== 'string' || typeof password !== 'string') {
      throw badRequest('email and password are required');
    }
    const found = userByEmail.get(email.trim().toLowerCase());
    const passwordOk = verifyPassword(password, found?.password_hash ?? DUMMY_HASH);
    if (!found || !passwordOk) throw unauthenticated('invalid email or password');

    const user = { id: found.id, email: found.email, name: found.name };
    const rows = membershipsOf.all(user.id);
    const body = withToken(user, rows, pickOrg(rows, orgId));
    startRefreshFamily(res, user.id);
    send(res, 200, body);
  });

  // Rotation: each refresh token works once. Presenting one that was already rotated means
  // it leaked, so the whole family is revoked and every holder has to sign in again.
  router.post('/v1/auth/refresh', (ctx, _params, res) => {
    const raw = readCookie(ctx.req, COOKIE);
    const row = raw ? refreshByHash.get(hashRefreshToken(raw)) : null;
    const now = nowIso();

    const rotated = db.transaction(() => {
      if (!row) return false;
      if (rotateRefresh.run(now, row.id, now).changes === 1) return true;
      if (row.expires_at > now) revokeFamily.run(now, row.family_id);
      return false;
    })();

    if (!rotated) {
      clearRefreshCookie(res);
      throw unauthenticated('refresh token is not valid');
    }

    const user = userById.get(row.user_id);
    const rows = membershipsOf.all(user.id);
    const body = withToken(user, rows, pickOrg(rows, ctx.body.orgId));
    startRefreshFamily(res, user.id, row.family_id);
    send(res, 200, body);
  });

  router.post('/v1/auth/logout', (ctx, _params, res) => {
    const raw = readCookie(ctx.req, COOKIE);
    const row = raw ? refreshByHash.get(hashRefreshToken(raw)) : null;
    if (row) revokeFamily.run(nowIso(), row.family_id);
    clearRefreshCookie(res);
    send(res, 204);
  });

  router.post('/v1/auth/token', (ctx, _params, res) => {
    if (typeof ctx.body.orgId !== 'string' || ctx.body.orgId === '') throw badRequest('orgId is required');
    const user = userById.get(ctx.userId);
    const rows = membershipsOf.all(user.id);
    send(res, 200, withToken(user, rows, pickOrg(rows, ctx.body.orgId)));
  });

  router.get('/v1/auth/me', (ctx, _params, res) => {
    const user = userById.get(ctx.userId);
    const rows = membershipsOf.all(user.id);
    send(res, 200, view(user, rows, rows.find((r) => r.id === ctx.orgId)));
  });
}
