import { sql, newId, nowIso } from '../db.js';
import { send, badRequest, conflict, notFound, deviceBusy } from '../http.js';
import { assertCan, assertCanStartSession, MODE_PERMISSION } from '../permissions.js';
import { auditDenials, auditAllow } from '../audit.js';
import { expireSessions, snapshotAuthority, sessionExpiry } from '../lifecycle.js';
import { isUniqueViolation } from '../validate.js';

const SESSION_SELECT = `
  SELECT s.id, s.org_id, s.user_id, u.name AS user_name, s.device_id, d.name AS device_name, s.mode, s.state,
         s.end_reason, s.authorized_by, s.started_at, s.expires_at, s.ended_at
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    JOIN devices d ON d.id = s.device_id`;

const sessionView = (s) => ({ ...s, authorized_by: JSON.parse(s.authorized_by) });

function sessionInOrg(db, orgId, id) {
  const session = sql(db, `${SESSION_SELECT} WHERE s.id = ? AND s.org_id = ?`).get(id, orgId);
  if (!session) throw notFound();
  return session;
}

const AUDIT_MAX_LIMIT = 500;

function pageParam(query, name, { fallback, min, max }) {
  const raw = query.get(name);
  if (raw === null) return fallback;
  if (!/^\d+$/.test(raw)) throw badRequest(`${name} must be a whole number`, 'invalid_pagination');
  const value = Number(raw);
  if (value < min || value > max) throw badRequest(`${name} must be from ${min} to ${max}`, 'invalid_pagination');
  return value;
}

export function registerSessionRoutes(router, { db }) {
  router.post('/v1/orgs/:org/sessions', (ctx, params, res) => {
    const { deviceId, mode } = ctx.body;
    const meta = { action: 'session.start', targetType: 'device', targetId: typeof deviceId === 'string' ? deviceId : null };
    const session = auditDenials(db, ctx, meta, () => {
      if (typeof deviceId !== 'string') throw badRequest('deviceId is required');
      if (!sql(db, 'SELECT 1 FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, ctx.orgId)) {
        throw notFound();
      }
      const permissions = assertCanStartSession(db, ctx, mode, deviceId);
      const authority = snapshotAuthority(db, {
        userId: ctx.userId, orgId: ctx.orgId, permissions, needed: ['session:start', MODE_PERMISSION[mode]],
      });
      const id = newId('ses');
      const startedAt = new Date();

      db.transaction(() => {
        expireSessions(db, ctx.orgId);
        try {
          sql(
            db,
            `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
             VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)`
          ).run(id, ctx.orgId, ctx.userId, deviceId, mode, JSON.stringify(authority), startedAt.toISOString(), sessionExpiry(db, ctx.orgId, startedAt));
        } catch (err) {
          if (!isUniqueViolation(err)) throw err;
          const holder = sql(
            db,
            `SELECT id FROM sessions WHERE device_id = ? AND state = 'active' AND mode IN ('control', 'terminal')`
          ).get(deviceId);
          throw deviceBusy(`device already has an exclusive session: ${holder?.id ?? 'unknown'}`);
        }
        auditAllow(db, ctx, { action: 'session.start', targetType: 'session', targetId: id });
      })();
      return sessionInOrg(db, ctx.orgId, id);
    });
    send(res, 201, sessionView(session));
  });

  router.get('/v1/orgs/:org/sessions', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'session.list', targetType: 'org', targetId: ctx.orgId }, () =>
      assertCan(db, ctx, 'session:view')
    );
    expireSessions(db, ctx.orgId);
    const sessions = sql(
      db,
      `${SESSION_SELECT} WHERE s.org_id = ?
        ORDER BY CASE s.state WHEN 'ended' THEN 1 ELSE 0 END, s.started_at DESC, s.id
        LIMIT 200`
    ).all(ctx.orgId);
    send(res, 200, { sessions: sessions.map(sessionView) });
  });

  // Sessions are addressed without an org in the path, so they are looked up inside the
  // caller's token org: a session in another org is a 404 like everything else.
  router.get('/v1/sessions/:id', (ctx, params, res) => {
    expireSessions(db, ctx.orgId);
    const session = sessionInOrg(db, ctx.orgId, params.id);
    if (session.user_id !== ctx.userId) {
      auditDenials(db, ctx, { action: 'session.view', targetType: 'session', targetId: session.id }, () =>
        assertCan(db, ctx, 'session:view', session.device_id)
      );
    }
    send(res, 200, sessionView(session));
  });

  router.delete('/v1/sessions/:id', (ctx, params, res) => {
    expireSessions(db, ctx.orgId);
    const current = sessionInOrg(db, ctx.orgId, params.id);
    const own = current.user_id === ctx.userId;
    const meta = { action: own ? 'session.stop' : 'session.terminate', targetType: 'session', targetId: current.id };

    const session = auditDenials(db, ctx, meta, () => {
      if (!own) assertCan(db, ctx, 'session:terminate', current.device_id);
      return db.transaction(() => {
        const ended = sql(
          db,
          `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ?
            WHERE id = ? AND state IN ('connecting', 'active')`
        ).run(own ? 'user_stopped' : 'admin_terminated', nowIso(), current.id);
        if (ended.changes !== 1) throw conflict('that session has already ended');
        auditAllow(db, ctx, meta);
        return sessionInOrg(db, ctx.orgId, current.id);
      })();
    });
    send(res, 200, sessionView(session));
  });

  router.get('/v1/orgs/:org/audit', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'audit.read', targetType: 'org', targetId: ctx.orgId }, () =>
      assertCan(db, ctx, 'audit:read')
    );
    const limit = pageParam(ctx.query, 'limit', { fallback: 50, min: 1, max: AUDIT_MAX_LIMIT });
    const offset = pageParam(ctx.query, 'offset', { fallback: 0, min: 0, max: Number.MAX_SAFE_INTEGER });
    const events = sql(
      db,
      `SELECT a.id, a.actor_id, u.name AS actor_name, a.action, a.target_type, a.target_id, a.result,
              a.reason_code, a.request_id, a.at
         FROM audit_events a LEFT JOIN users u ON u.id = a.actor_id
        WHERE a.org_id = ?
        ORDER BY a.at DESC, a.id DESC
        LIMIT ? OFFSET ?`
    ).all(ctx.orgId, limit, offset);
    send(res, 200, { events, limit, offset });
  });
}

