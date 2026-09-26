import { HttpError } from './http.js';
import { sql, newId, nowIso } from './db.js';

export function audit(db, { orgId, actorId = null, action, targetType = null, targetId = null, result, reasonCode = null, requestId = null }) {
  sql(
    db,
    `INSERT INTO audit_events (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id, at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(newId('aud'), orgId, actorId, action, targetType, targetId, result, reasonCode, requestId, nowIso());
}

// Refusals on authority grounds are recorded: every 403, and the last-owner guard.
const isRefusal = (err) => err instanceof HttpError && (err.status === 403 || err.code === 'LAST_OWNER');

// The denial row is written after the failed transaction rolled back, so it survives it.
export function auditDenials(db, ctx, meta, fn) {
  try {
    return fn();
  } catch (err) {
    if (isRefusal(err)) {
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: meta.action,
        targetType: meta.targetType ?? null,
        targetId: meta.targetId ?? null,
        result: 'deny',
        reasonCode: err.reason ?? err.code.toLowerCase(),
        requestId: ctx.requestId,
      });
    }
    throw err;
  }
}

// The success row, from inside the transaction that made the change.
export const auditAllow = (db, ctx, meta) =>
  audit(db, { orgId: ctx.orgId, actorId: ctx.userId, result: 'allow', requestId: ctx.requestId, ...meta });
