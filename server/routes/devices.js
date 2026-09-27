import { sql, newId, nowIso, bumpPermVersion } from '../db.js';
import { send, badRequest, conflict, notFound, forbidden, normalizeTs, HttpError } from '../http.js';
import {
  assertCan, assertCanOrgScope, assertAllowed, assertMayGrant, resolve, resolveDevices,
} from '../permissions.js';
import { audit, auditDenials, auditAllow } from '../audit.js';
import { assertCanModify, endActiveSessions } from '../lifecycle.js';
import { requireName, isUniqueViolation, isForeignKeyViolation } from '../validate.js';

const KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];

const deviceView = (d, permissions) => ({
  id: d.id, name: d.name, kind: d.kind, online: d.online === 1, permissions,
});

function liveDevice(db, orgId, deviceId) {
  const device = typeof deviceId === 'string'
    ? sql(db, 'SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, orgId)
    : null;
  if (!device) throw notFound();
  return device;
}

function assertDeviceNameFree(db, orgId, name, exceptId = null) {
  const taken = sql(
    db,
    `SELECT 1 FROM devices WHERE org_id = ? AND deleted_at IS NULL AND lower(name) = lower(?) AND (? IS NULL OR id != ?)`
  ).get(orgId, name, exceptId, exceptId);
  if (taken) throw conflict('a device with that name already exists in this organization');
}

function requireKind(kind) {
  if (!KINDS.includes(kind)) throw badRequest(`kind must be one of ${KINDS.join(', ')}`);
  return kind;
}

function requireOnline(online) {
  if (typeof online !== 'boolean') throw badRequest('online must be true or false');
  return online ? 1 : 0;
}

function grantStatus(g, now) {
  if (g.revoked_at) return 'revoked';
  if (g.expires_at && g.expires_at <= now) return 'expired';
  if (g.starts_at && g.starts_at > now) return 'scheduled';
  return 'active';
}

function grantsWithPermissions(db, rows) {
  const now = nowIso();
  return rows.map((g) => ({
    id: g.id, user_id: g.user_id, user_name: g.user_name, device_id: g.device_id, device_name: g.device_name,
    effect: g.effect, starts_at: g.starts_at, expires_at: g.expires_at, created_by: g.created_by,
    created_at: g.created_at, status: grantStatus(g, now),
    permissions: sql(db, 'SELECT permission FROM grant_permissions WHERE grant_id = ? ORDER BY permission')
      .all(g.id).map((r) => r.permission),
  }));
}

const GRANT_SELECT = `
  SELECT g.*, u.name AS user_name, d.name AS device_name
    FROM grants g
    JOIN users u ON u.id = g.user_id
    LEFT JOIN devices d ON d.id = g.device_id`;

function readGrantBody(body) {
  const { userId, deviceId = null, effect, permissions, startsAt = null, expiresAt = null } = body;
  if (typeof userId !== 'string' || userId === '') throw badRequest('userId is required');
  if (deviceId !== null && typeof deviceId !== 'string') throw badRequest('deviceId must be a string or null');
  if (effect !== 'allow' && effect !== 'deny') throw badRequest('effect must be allow or deny');
  if (!Array.isArray(permissions) || permissions.length === 0 || !permissions.every((p) => typeof p === 'string')) {
    throw badRequest('permissions must be a non-empty list of permission names');
  }
  const starts = normalizeTs(startsAt, 'startsAt');
  const expires = normalizeTs(expiresAt, 'expiresAt');
  if (expires && expires <= nowIso()) {
    throw new HttpError(400, 'GRANT_EXPIRED', 'expiresAt is already in the past', 'expired_grant');
  }
  if (starts && expires && expires <= starts) throw badRequest('expiresAt must be after startsAt');
  return { userId, deviceId, effect, patterns: [...new Set(permissions)], starts, expires };
}

export function registerDeviceRoutes(router, { db }) {
  router.get('/v1/orgs/:org/devices', (ctx, params, res) => {
    const devices = sql(db, 'SELECT * FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY name, id').all(ctx.orgId);
    const resolved = resolveDevices(db, { userId: ctx.userId, orgId: ctx.orgId, deviceIds: devices.map((d) => d.id) });
    auditDenials(db, ctx, { action: 'device.list', targetType: 'org', targetId: ctx.orgId }, () =>
      assertAllowed('device:list', resolved.org['device:list'])
    );
    const visible = devices.filter((d) => resolved.byDevice[d.id]['device:view'].effect === 'allow');
    send(res, 200, { devices: visible.map((d) => deviceView(d, resolved.byDevice[d.id])) });
  });

  router.post('/v1/orgs/:org/devices', (ctx, params, res) => {
    const device = auditDenials(db, ctx, { action: 'device.provision', targetType: 'device' }, () => {
      assertCanOrgScope(db, ctx, 'device:provision');
      const name = requireName(ctx.body.name, 'name');
      const kind = requireKind(ctx.body.kind);
      const online = ctx.body.online === undefined ? 0 : requireOnline(ctx.body.online);
      const id = newId('dev');
      db.transaction(() => {
        assertDeviceNameFree(db, ctx.orgId, name);
        sql(db, 'INSERT INTO devices (id, org_id, name, kind, online) VALUES (?, ?, ?, ?, ?)').run(id, ctx.orgId, name, kind, online);
        auditAllow(db, ctx, { action: 'device.provision', targetType: 'device', targetId: id });
      })();
      return liveDevice(db, ctx.orgId, id);
    });
    const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: device.id });
    send(res, 201, { device: deviceView(device, permissions) });
  });

  router.get('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const device = liveDevice(db, ctx.orgId, params.id);
    const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: device.id });
    auditDenials(db, ctx, { action: 'device.view', targetType: 'device', targetId: device.id }, () =>
      assertAllowed('device:view', permissions['device:view'])
    );
    send(res, 200, { device: deviceView(device, permissions) });
  });

  router.patch('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const meta = { action: 'device.update', targetType: 'device', targetId: params.id };
    const device = auditDenials(db, ctx, meta, () => {
      const current = liveDevice(db, ctx.orgId, params.id);
      assertCan(db, ctx, 'device:update', current.id);
      const { name, online } = ctx.body;
      if (name === undefined && online === undefined) throw badRequest('nothing to update: send name or online');
      const next = {
        name: name === undefined ? current.name : requireName(name, 'name'),
        online: online === undefined ? current.online : requireOnline(online),
      };
      db.transaction(() => {
        if (name !== undefined) assertDeviceNameFree(db, ctx.orgId, next.name, current.id);
        sql(db, 'UPDATE devices SET name = ?, online = ? WHERE id = ?').run(next.name, next.online, current.id);
        auditAllow(db, ctx, meta);
      })();
      return liveDevice(db, ctx.orgId, current.id);
    });
    const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: device.id });
    send(res, 200, { device: deviceView(device, permissions) });
  });

  router.delete('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const meta = { action: 'device.decommission', targetType: 'device', targetId: params.id };
    auditDenials(db, ctx, meta, () => {
      const device = liveDevice(db, ctx.orgId, params.id);
      assertCan(db, ctx, 'device:provision', device.id);
      db.transaction(() => {
        sql(db, 'UPDATE devices SET deleted_at = ? WHERE id = ?').run(nowIso(), device.id);
        endActiveSessions(db, { orgId: ctx.orgId, deviceId: device.id, reason: 'device_transferred' });
        auditAllow(db, ctx, meta);
      })();
    });
    send(res, 204);
  });

  // Needs device:provision on this device here, and org-wide in the destination. The token only
  // names the source org, so the destination membership is looked up and checked explicitly.
  router.post('/v1/orgs/:org/devices/:id/transfer', (ctx, params, res) => {
    const meta = { action: 'device.transfer', targetType: 'device', targetId: params.id };
    const moved = auditDenials(db, ctx, meta, () => {
      const device = liveDevice(db, ctx.orgId, params.id);
      assertCan(db, ctx, 'device:provision', device.id);

      const targetOrgId = ctx.body.targetOrgId;
      if (typeof targetOrgId !== 'string' || targetOrgId === '') throw badRequest('targetOrgId is required');
      if (targetOrgId === ctx.orgId) throw badRequest('the device is already in this organization', 'same_org');
      const target = sql(
        db,
        `SELECT m.status FROM memberships m JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
          WHERE m.org_id = ? AND m.user_id = ?`
      ).get(targetOrgId, ctx.userId);
      if (!target || target.status === 'removed' || target.status === 'invited') throw notFound();
      assertCanOrgScope(db, { userId: ctx.userId, orgId: targetOrgId }, 'device:provision');

      db.transaction(() => {
        assertDeviceNameFree(db, targetOrgId, device.name);
        endActiveSessions(db, { orgId: ctx.orgId, deviceId: device.id, reason: 'device_transferred' });
        sql(db, 'UPDATE grants SET revoked_at = ? WHERE org_id = ? AND device_id = ? AND revoked_at IS NULL')
          .run(nowIso(), ctx.orgId, device.id);
        sql(db, 'UPDATE devices SET org_id = ? WHERE id = ?').run(targetOrgId, device.id);
        auditAllow(db, ctx, meta);
        audit(db, {
          orgId: targetOrgId, actorId: ctx.userId, action: 'device.transfer_in', targetType: 'device',
          targetId: device.id, result: 'allow', requestId: ctx.requestId,
        });
      })();
      return { id: device.id, org_id: targetOrgId };
    });
    send(res, 200, { device: moved });
  });

  router.get('/v1/orgs/:org/grants', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'grant.list', targetType: 'org', targetId: ctx.orgId }, () =>
      assertCan(db, ctx, 'user:read')
    );
    const userId = ctx.query.get('userId');
    const rows = sql(
      db,
      `${GRANT_SELECT}
        WHERE g.org_id = ? AND g.revoked_at IS NULL AND (? IS NULL OR g.user_id = ?)
        ORDER BY g.created_at DESC, g.id`
    ).all(ctx.orgId, userId, userId);
    send(res, 200, { grants: grantsWithPermissions(db, rows) });
  });

  // Deny grants and revoking allow grants take authority away from someone, so they follow the
  // same rank rule as changing that person's role. Allow grants are bounded by laundering instead.
  router.post('/v1/orgs/:org/grants', (ctx, params, res) => {
    const grant = auditDenials(db, ctx, { action: 'grant.create', targetType: 'user', targetId: ctx.body.userId ?? null }, () => {
      const deviceId = ctx.body.deviceId ?? null;
      if (deviceId !== null) {
        liveDevice(db, ctx.orgId, deviceId);
        assertCan(db, ctx, 'grant:create', deviceId);
      } else {
        assertCanOrgScope(db, ctx, 'grant:create');
      }
      const g = readGrantBody(ctx.body);
      const target = sql(
        db,
        `SELECT role FROM memberships WHERE org_id = ? AND user_id = ? AND status IN ('active', 'suspended')`
      ).get(ctx.orgId, g.userId);
      if (!target) throw notFound();
      if (g.userId === ctx.userId) throw forbidden('you cannot create a grant for yourself', 'self_grant');
      if (g.effect === 'deny') assertCanModify(db, ctx.role, target.role);
      else assertMayGrant(db, ctx, g.patterns, g.deviceId);

      const id = newId('grt');
      db.transaction(() => {
        sql(
          db,
          `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(id, ctx.orgId, g.userId, g.deviceId, g.effect, g.starts, g.expires, ctx.userId, nowIso());
        const insert = sql(db, 'INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)');
        try {
          for (const p of g.patterns) insert.run(id, p);
        } catch (err) {
          if (isForeignKeyViolation(err)) throw badRequest('unknown permission in permissions', 'unknown_permission');
          throw err;
        }
        bumpPermVersion(db, { orgId: ctx.orgId, userId: g.userId });
        auditAllow(db, ctx, { action: 'grant.create', targetType: 'grant', targetId: id });
      })();
      return grantsWithPermissions(db, [sql(db, `${GRANT_SELECT} WHERE g.id = ?`).get(id)])[0];
    });
    send(res, 201, { grant });
  });

  router.delete('/v1/orgs/:org/grants/:id', (ctx, params, res) => {
    const meta = { action: 'grant.revoke', targetType: 'grant', targetId: params.id };
    auditDenials(db, ctx, meta, () => {
      const grant = sql(db, 'SELECT * FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL').get(params.id, ctx.orgId);
      if (!grant) throw notFound();
      if (grant.device_id !== null) assertCan(db, ctx, 'grant:revoke', grant.device_id);
      else assertCanOrgScope(db, ctx, 'grant:revoke');
      if (grant.user_id === ctx.userId) throw forbidden('you cannot revoke a grant that applies to you', 'self_grant');
      if (grant.effect === 'allow') {
        const target = sql(db, 'SELECT role FROM memberships WHERE org_id = ? AND user_id = ?').get(ctx.orgId, grant.user_id);
        if (target) assertCanModify(db, ctx.role, target.role);
      }
      db.transaction(() => {
        sql(db, 'UPDATE grants SET revoked_at = ? WHERE id = ?').run(nowIso(), grant.id);
        bumpPermVersion(db, { orgId: ctx.orgId, userId: grant.user_id });
        auditAllow(db, ctx, meta);
      })();
    });
    send(res, 204);
  });
}
