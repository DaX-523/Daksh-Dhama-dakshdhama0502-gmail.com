import { sql, nowIso } from './db.js';
import { badRequest, forbidden, lastOwner } from './http.js';

export const OWNER = 'owner';

// Ranks answer one question only: who may modify whom. Never whether someone may do something.
export function roleRanks(db) {
  return new Map(sql(db, 'SELECT key, rank FROM roles').all().map((r) => [r.key, r.rank]));
}

export function assertRoleExists(db, role) {
  if (typeof role !== 'string' || !roleRanks(db).has(role)) throw badRequest('unknown role', 'unknown_role');
}

// Strictly lower rank only. Owners are the exception: only an owner can manage another owner.
export function assertCanModify(db, callerRole, targetRole) {
  if (callerRole === OWNER) return;
  const ranks = roleRanks(db);
  if (!(ranks.get(targetRole) < ranks.get(callerRole))) {
    throw forbidden('you can only manage members whose role is below yours', 'insufficient_rank');
  }
}

export function canAssign(db, callerRole, newRole, ranks = roleRanks(db)) {
  return callerRole === OWNER || ranks.get(newRole) < ranks.get(callerRole);
}

export function assertCanAssign(db, callerRole, newRole) {
  if (!canAssign(db, callerRole, newRole)) throw forbidden(`you cannot assign the ${newRole} role`, 'insufficient_rank');
}

// Counts active owners. A suspended owner cannot run the org, so they do not count.
export function assertNotLastOwner(db, orgId, userId) {
  const target = sql(db, 'SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, userId);
  if (!target || target.role !== OWNER || target.status !== 'active') return;
  const { owners } = sql(
    db,
    `SELECT COUNT(*) AS owners FROM memberships WHERE org_id = ? AND role = ? AND status = 'active'`
  ).get(orgId, OWNER);
  if (owners <= 1) throw lastOwner();
}

export function endActiveSessions(db, { orgId, userId = null, deviceId = null, reason, exceptSessionId = null }) {
  return sql(
    db,
    `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ?
      WHERE org_id = ? AND state IN ('connecting', 'active')
        AND (? IS NULL OR user_id = ?)
        AND (? IS NULL OR device_id = ?)
        AND (? IS NULL OR id != ?)`
  ).run(reason, nowIso(), orgId, userId, userId, deviceId, deviceId, exceptSessionId, exceptSessionId).changes;
}

// Sessions past their TTL are ended lazily, on the next read or write that touches them.
export function expireSessions(db, orgId) {
  const now = nowIso();
  return sql(
    db,
    `UPDATE sessions SET state = 'ended', end_reason = 'session_expired', ended_at = expires_at
      WHERE org_id = ? AND state IN ('connecting', 'active') AND expires_at <= ?`
  ).run(orgId, now).changes;
}

// What authorised a session, frozen when it starts. The session never re-checks it.
export function snapshotAuthority(db, { userId, orgId, permissions, needed }) {
  const role = sql(db, 'SELECT role FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, userId)?.role ?? null;
  const decisive = Object.fromEntries(needed.map((p) => [p, permissions[p]]));
  const grantIds = [...new Set(Object.values(decisive).map((r) => r.source).filter((s) => s?.startsWith('grant:')).map((s) => s.slice(6)))];
  return { role, grantIds, permissions: decisive, snapshotAt: nowIso() };
}

export function sessionExpiry(db, orgId, from = new Date()) {
  const { minutes } = sql(db, 'SELECT max_session_minutes AS minutes FROM organizations WHERE id = ?').get(orgId);
  return new Date(from.getTime() + minutes * 60_000).toISOString();
}
