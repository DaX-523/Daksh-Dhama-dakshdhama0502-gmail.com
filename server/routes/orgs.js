import { sql, newId, nowIso, bumpPermVersion } from '../db.js';
import { send, badRequest, conflict, notFound, forbidden, selfRoleChange } from '../http.js';
import { assertCan, resolve } from '../permissions.js';
import { audit, auditDenials, auditAllow } from '../audit.js';
import {
  OWNER, roleRanks, canAssign, assertRoleExists, assertCanModify, assertCanAssign, assertNotLastOwner, endActiveSessions,
} from '../lifecycle.js';
import { requireName, requireInt } from '../validate.js';

export const THEMES = ['cobalt', 'amber', 'moss', 'plum', 'rust', 'teal'];

const orgView = (o) => ({ id: o.id, name: o.name, theme: o.theme, max_session_minutes: o.max_session_minutes });

const memberView = (m) => ({
  user_id: m.user_id, email: m.email, name: m.name, role: m.role, status: m.status, joined_at: m.joined_at,
});

function requireTheme(theme) {
  if (!THEMES.includes(theme)) throw badRequest(`theme must be one of ${THEMES.join(', ')}`);
  return theme;
}

// Org names only have to be unique among the orgs one person belongs to, so the switcher never
// shows two identical entries. Globally unique names would leak which names other tenants use.
function assertNameFree(db, userId, name, exceptOrgId = null) {
  const taken = sql(
    db,
    `SELECT 1 FROM organizations o
       JOIN memberships m ON m.org_id = o.id AND m.user_id = ? AND m.status IN ('active', 'suspended')
      WHERE o.deleted_at IS NULL AND lower(o.name) = lower(?) AND (? IS NULL OR o.id != ?)`
  ).get(userId, name, exceptOrgId, exceptOrgId);
  if (taken) throw conflict('you already belong to an organization with that name');
}

function unusedTheme(db, userId) {
  const used = new Set(
    sql(
      db,
      `SELECT o.theme FROM organizations o JOIN memberships m ON m.org_id = o.id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).all(userId).map((r) => r.theme)
  );
  return THEMES.find((t) => !used.has(t)) ?? THEMES[Math.floor(Math.random() * THEMES.length)];
}

function memberOf(db, orgId, userId) {
  const m = sql(
    db,
    `SELECT m.*, u.email, u.name FROM memberships m JOIN users u ON u.id = m.user_id
      WHERE m.org_id = ? AND m.user_id = ? AND m.status IN ('active', 'suspended')`
  ).get(orgId, userId);
  if (!m) throw notFound();
  return m;
}

// Removal and leaving share one path: the membership ends, its sessions end, its grants are
// revoked so a later re-invite starts from the role baseline, and the user row is kept.
function endMembership(db, ctx, target, action) {
  assertNotLastOwner(db, ctx.orgId, target.user_id);
  sql(db, `UPDATE memberships SET status = 'removed' WHERE id = ?`).run(target.id);
  bumpPermVersion(db, { orgId: ctx.orgId, userId: target.user_id });
  endActiveSessions(db, { orgId: ctx.orgId, userId: target.user_id, reason: 'membership_removed' });
  sql(db, 'UPDATE grants SET revoked_at = ? WHERE org_id = ? AND user_id = ? AND revoked_at IS NULL')
    .run(nowIso(), ctx.orgId, target.user_id);
  auditAllow(db, ctx, { action, targetType: 'user', targetId: target.user_id });
}

export function registerOrgRoutes(router, { db }) {
  router.get('/v1/orgs', (ctx, _params, res) => {
    const orgs = sql(
      db,
      `SELECT o.*, m.role FROM organizations o JOIN memberships m ON m.org_id = o.id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
        ORDER BY o.name, o.id`
    ).all(ctx.userId);
    send(res, 200, { orgs: orgs.map((o) => ({ ...orgView(o), role: o.role })) });
  });

  router.post('/v1/orgs', (ctx, _params, res) => {
    const name = requireName(ctx.body.name, 'name');
    const theme = ctx.body.theme === undefined ? unusedTheme(db, ctx.userId) : requireTheme(ctx.body.theme);
    const id = newId('org');

    db.transaction(() => {
      assertNameFree(db, ctx.userId, name);
      sql(db, 'INSERT INTO organizations (id, name, theme) VALUES (?, ?, ?)').run(id, name, theme);
      sql(db, `INSERT INTO memberships (id, org_id, user_id, role, status, joined_at) VALUES (?, ?, ?, ?, 'active', ?)`)
        .run(newId('mem'), id, ctx.userId, OWNER, nowIso());
      audit(db, { orgId: id, actorId: ctx.userId, action: 'org.create', targetType: 'org', targetId: id, result: 'allow', requestId: ctx.requestId });
    })();

    const org = sql(db, 'SELECT * FROM organizations WHERE id = ?').get(id);
    send(res, 201, { ...orgView(org), role: OWNER });
  });

  router.patch('/v1/orgs/:org', (ctx, params, res) => {
    const org = auditDenials(db, ctx, { action: 'org.update', targetType: 'org', targetId: ctx.orgId }, () => {
      assertCan(db, ctx, 'org:update');
      const { name, theme, maxSessionMinutes } = ctx.body;
      if (name === undefined && theme === undefined && maxSessionMinutes === undefined) {
        throw badRequest('nothing to update: send name, theme or maxSessionMinutes');
      }
      const current = sql(db, 'SELECT * FROM organizations WHERE id = ?').get(ctx.orgId);
      const next = {
        name: name === undefined ? current.name : requireName(name, 'name'),
        theme: theme === undefined ? current.theme : requireTheme(theme),
        minutes: maxSessionMinutes === undefined ? current.max_session_minutes : requireInt(maxSessionMinutes, 'maxSessionMinutes', { min: 1, max: 1440 }),
      };
      return db.transaction(() => {
        if (name !== undefined) assertNameFree(db, ctx.userId, next.name, ctx.orgId);
        sql(db, 'UPDATE organizations SET name = ?, theme = ?, max_session_minutes = ? WHERE id = ?')
          .run(next.name, next.theme, next.minutes, ctx.orgId);
        auditAllow(db, ctx, { action: 'org.update', targetType: 'org', targetId: ctx.orgId });
        return sql(db, 'SELECT * FROM organizations WHERE id = ?').get(ctx.orgId);
      })();
    });
    send(res, 200, orgView(org));
  });

  router.delete('/v1/orgs/:org', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'org.delete', targetType: 'org', targetId: ctx.orgId }, () => {
      assertCan(db, ctx, 'org:delete');
      db.transaction(() => {
        const now = nowIso();
        sql(db, 'UPDATE organizations SET deleted_at = ? WHERE id = ?').run(now, ctx.orgId);
        endActiveSessions(db, { orgId: ctx.orgId, reason: 'membership_removed' });
        sql(db, 'UPDATE invites SET revoked_at = ? WHERE org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL')
          .run(now, ctx.orgId);
        auditAllow(db, ctx, { action: 'org.delete', targetType: 'org', targetId: ctx.orgId });
      })();
    });
    send(res, 204);
  });

  // The roles in this org's catalogue, and which of them the caller may hand out. The console
  // builds its role pickers from this instead of knowing any rank rule itself.
  router.get('/v1/orgs/:org/roles', (ctx, _params, res) => {
    const ranks = roleRanks(db);
    const roles = sql(db, 'SELECT key, label FROM roles ORDER BY rank DESC').all();
    send(res, 200, { roles: roles.map((r) => ({ ...r, assignable: canAssign(db, ctx.role, r.key, ranks) })) });
  });

  router.get('/v1/orgs/:org/members', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'member.list', targetType: 'org', targetId: ctx.orgId }, () =>
      assertCan(db, ctx, 'user:read')
    );
    const members = sql(
      db,
      `SELECT m.*, u.email, u.name FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND m.status IN ('active', 'suspended')
        ORDER BY u.name, u.id`
    ).all(ctx.orgId);
    send(res, 200, { members: members.map(memberView) });
  });

  router.delete('/v1/orgs/:org/members/me', (ctx, _params, res) => {
    auditDenials(db, ctx, { action: 'member.leave', targetType: 'user', targetId: ctx.userId }, () => {
      const me = memberOf(db, ctx.orgId, ctx.userId);
      db.transaction(() => endMembership(db, ctx, me, 'member.leave'))();
    });
    send(res, 204);
  });

  router.patch('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    const meta = { action: 'member.role_update', targetType: 'user', targetId: params.userId };
    const updated = auditDenials(db, ctx, meta, () => {
      assertCan(db, ctx, 'user:role:update');
      if (params.userId === ctx.userId) throw selfRoleChange();
      const target = memberOf(db, ctx.orgId, params.userId);
      const role = ctx.body.role;
      assertRoleExists(db, role);
      assertCanModify(db, ctx.role, target.role);
      assertCanAssign(db, ctx.role, role);

      return db.transaction(() => {
        if (role !== target.role) {
          if (target.role === OWNER) assertNotLastOwner(db, ctx.orgId, target.user_id);
          sql(db, 'UPDATE memberships SET role = ? WHERE id = ?').run(role, target.id);
          bumpPermVersion(db, { orgId: ctx.orgId, userId: target.user_id });
          auditAllow(db, ctx, meta);
        }
        return memberOf(db, ctx.orgId, target.user_id);
      })();
    });
    send(res, 200, { member: memberView(updated) });
  });

  router.post('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    const meta = { action: 'member.suspend', targetType: 'user', targetId: params.userId };
    const updated = auditDenials(db, ctx, meta, () => {
      assertCan(db, ctx, 'user:remove');
      if (params.userId === ctx.userId) throw forbidden('you cannot suspend yourself', 'self_action');
      const target = memberOf(db, ctx.orgId, params.userId);
      assertCanModify(db, ctx.role, target.role);
      if (target.status === 'suspended') throw conflict('that member is already suspended');

      return db.transaction(() => {
        assertNotLastOwner(db, ctx.orgId, target.user_id);
        sql(db, `UPDATE memberships SET status = 'suspended' WHERE id = ?`).run(target.id);
        bumpPermVersion(db, { orgId: ctx.orgId, userId: target.user_id });
        endActiveSessions(db, { orgId: ctx.orgId, userId: target.user_id, reason: 'user_suspended' });
        auditAllow(db, ctx, meta);
        return memberOf(db, ctx.orgId, target.user_id);
      })();
    });
    send(res, 200, { member: memberView(updated) });
  });

  router.delete('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    const meta = { action: 'member.reinstate', targetType: 'user', targetId: params.userId };
    const updated = auditDenials(db, ctx, meta, () => {
      assertCan(db, ctx, 'user:remove');
      const target = memberOf(db, ctx.orgId, params.userId);
      assertCanModify(db, ctx.role, target.role);
      if (target.status !== 'suspended') throw conflict('that member is not suspended');

      return db.transaction(() => {
        sql(db, `UPDATE memberships SET status = 'active' WHERE id = ?`).run(target.id);
        bumpPermVersion(db, { orgId: ctx.orgId, userId: target.user_id });
        auditAllow(db, ctx, meta);
        return memberOf(db, ctx.orgId, target.user_id);
      })();
    });
    send(res, 200, { member: memberView(updated) });
  });

  router.delete('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    const self = params.userId === ctx.userId;
    const action = self ? 'member.leave' : 'member.remove';
    auditDenials(db, ctx, { action, targetType: 'user', targetId: params.userId }, () => {
      if (!self) assertCan(db, ctx, 'user:remove');
      const target = memberOf(db, ctx.orgId, params.userId);
      if (!self) assertCanModify(db, ctx.role, target.role);
      db.transaction(() => endMembership(db, ctx, target, action))();
    });
    send(res, 204);
  });

  router.get('/v1/orgs/:org/users/:userId/effective', (ctx, params, res) => {
    const deviceId = ctx.query.get('deviceId');
    const result = auditDenials(db, ctx, { action: 'user.effective', targetType: 'user', targetId: params.userId }, () => {
      if (params.userId !== ctx.userId) assertCan(db, ctx, 'user:read');
      memberOf(db, ctx.orgId, params.userId);
      if (deviceId !== null && !sql(db, 'SELECT 1 FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, ctx.orgId)) {
        throw notFound();
      }
      return resolve(db, { userId: params.userId, orgId: ctx.orgId, deviceId });
    });
    send(res, 200, { user_id: params.userId, device_id: deviceId, role: result.role, permissions: result.permissions });
  });
}
