import { badRequest, forbidden } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

const statements = new WeakMap();

function prepared(db) {
  let s = statements.get(db);
  if (!s) {
    s = {
      catalogue: db.prepare('SELECT key FROM permissions ORDER BY key'),
      membership: db.prepare(
        `SELECT m.role, m.status FROM memberships m
           JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
          WHERE m.org_id = ? AND m.user_id = ?`
      ),
      baseline: db.prepare('SELECT permission FROM role_permissions WHERE role = ?'),
      grants: db.prepare(
        `SELECT g.id, g.effect, g.device_id AS deviceId, gp.permission AS pattern
           FROM grants g
           JOIN grant_permissions gp ON gp.grant_id = g.id
          WHERE g.user_id = ? AND g.org_id = ? AND g.revoked_at IS NULL
            AND (g.starts_at IS NULL OR g.starts_at <= ?)
            AND (g.expires_at IS NULL OR g.expires_at > ?)
            AND (g.device_id IS NULL OR EXISTS (
                  SELECT 1 FROM devices d
                   WHERE d.id = g.device_id AND d.org_id = g.org_id AND d.deleted_at IS NULL))
          ORDER BY g.created_at, g.id`
      ),
      liveDevices: db.prepare('SELECT id FROM devices WHERE org_id = ? AND deleted_at IS NULL'),
    };
    statements.set(db, s);
  }
  return s;
}

const allow = (source) => ({ effect: 'allow', source, reason: null });
const deny = (source, reason) => ({ effect: 'deny', source, reason });

export const covers = (pattern, key) =>
  pattern === '*' || pattern === key || (pattern.endsWith(':*') && key.startsWith(pattern.slice(0, -1)));

function load(db, userId, orgId, now) {
  const s = prepared(db);
  const catalogue = s.catalogue.all().map((r) => r.key);
  const membership = s.membership.get(orgId, userId);

  if (!membership || membership.status === 'removed' || membership.status === 'invited') {
    return { catalogue, role: null, blocked: 'not_a_member' };
  }
  if (membership.status === 'suspended') {
    return { catalogue, role: membership.role, blocked: 'suspended' };
  }

  const at = now.toISOString();
  return {
    catalogue,
    role: membership.role,
    blocked: null,
    baseline: new Set(s.baseline.all(membership.role).map((r) => r.permission)),
    grants: s.grants.all(userId, orgId, at, at),
  };
}

// deviceId null evaluates the org scope: the role baseline plus org-wide grants only.
function atDevice(inputs, key, deviceId) {
  const applicable = inputs.grants.filter(
    (g) => (g.deviceId === null || g.deviceId === deviceId) && covers(g.pattern, key)
  );
  const denied = applicable.find((g) => g.effect === 'deny');
  if (denied) return deny(`grant:${denied.id}`, 'explicit_deny');
  if (inputs.baseline.has(key)) return allow(`role:${inputs.role}`);
  const granted = applicable.find((g) => g.effect === 'allow');
  return granted ? allow(`grant:${granted.id}`) : deny(null, 'implicit');
}

// The org-level answer is the union over the org scope and every device: allowed if it is
// allowed anywhere. An org-wide deny applies on every device, so nothing can reopen it.
function atOrg(inputs, key) {
  const scoped = atDevice(inputs, key, null);
  if (scoped.effect === 'allow' || scoped.reason === 'explicit_deny') return scoped;

  for (const g of inputs.grants) {
    if (g.deviceId === null || g.effect !== 'allow' || !covers(g.pattern, key)) continue;
    const onDevice = atDevice(inputs, key, g.deviceId);
    if (onDevice.effect === 'allow') return onDevice;
  }
  return scoped;
}

// Holding a permission across the whole org: allowed at the org scope and denied on no device.
function acrossOrg(inputs, key) {
  const scoped = atDevice(inputs, key, null);
  if (scoped.effect !== 'allow') return scoped;
  const carved = inputs.grants.find((g) => g.deviceId !== null && g.effect === 'deny' && covers(g.pattern, key));
  return carved ? deny(`grant:${carved.id}`, 'explicit_deny') : scoped;
}

const denyAll = (catalogue, reason) => Object.fromEntries(catalogue.map((k) => [k, deny(null, reason)]));

function evaluate(inputs, deviceId) {
  if (inputs.blocked) return denyAll(inputs.catalogue, inputs.blocked);
  const decideOne = deviceId === null ? (k) => atOrg(inputs, k) : (k) => atDevice(inputs, k, deviceId);
  return Object.fromEntries(inputs.catalogue.map((k) => [k, decideOne(k)]));
}

const liveDeviceIds = (db, orgId) => new Set(prepared(db).liveDevices.all(orgId).map((r) => r.id));

export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const inputs = load(db, userId, orgId, now);
  if (deviceId !== null && !inputs.blocked && !liveDeviceIds(db, orgId).has(deviceId)) {
    return { role: inputs.role, permissions: denyAll(inputs.catalogue, 'scope_mismatch') };
  }
  return { role: inputs.role, permissions: evaluate(inputs, deviceId) };
}

// One load for a whole list: the org-level set plus one set per device.
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const inputs = load(db, userId, orgId, now);
  const live = liveDeviceIds(db, orgId);
  const byDevice = {};
  for (const id of deviceIds) {
    byDevice[id] = live.has(id) || inputs.blocked ? evaluate(inputs, id) : denyAll(inputs.catalogue, 'scope_mismatch');
  }
  return { role: inputs.role, org: evaluate(inputs, null), byDevice };
}

const lookup = (db, ctx, permission, deviceId) =>
  resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId }).permissions[permission] ?? deny(null, 'implicit');

// `reason` overrides the resolved reason when the caller needs to say WHICH check failed.
function refusal(permission, result, reason = null) {
  if (result.reason === 'suspended') return forbidden('your membership in this organization is suspended', 'suspended');
  const denied = result.reason === 'explicit_deny';
  const message = denied ? `${permission} is denied to you by ${result.source}` : `you do not have ${permission}`;
  return forbidden(message, reason ?? (denied ? 'explicit_deny' : 'missing_permission'));
}

export function can(db, ctx, permission, deviceId = null) {
  return lookup(db, ctx, permission, deviceId).effect === 'allow';
}

export function assertCan(db, ctx, permission, deviceId = null) {
  const result = lookup(db, ctx, permission, deviceId);
  if (result.effect !== 'allow') throw refusal(permission, result);
  return result;
}

// For actions that name no device and must not ride on a device-scoped grant, such as adding a
// device or creating an org-wide grant: the role baseline and org-wide grants only.
export function assertCanOrgScope(db, ctx, permission) {
  const inputs = load(db, ctx.userId, ctx.orgId, new Date());
  const result = inputs.blocked ? deny(null, inputs.blocked) : atDevice(inputs, permission, null);
  if (result.effect !== 'allow') throw refusal(permission, result);
  return result;
}

// Checks an answer the caller already resolved, so a list endpoint resolves once per request.
export function assertAllowed(permission, result) {
  if (result?.effect !== 'allow') throw refusal(permission, result ?? deny(null, 'implicit'));
  return result;
}

export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const inputs = load(db, ctx.userId, ctx.orgId, new Date());
  if (inputs.blocked) throw refusal('grant:create', deny(null, inputs.blocked));

  for (const key of inputs.catalogue.filter((k) => patterns.some((p) => covers(p, k)))) {
    const held = deviceId === null ? acrossOrg(inputs, key) : atDevice(inputs, key, deviceId);
    if (held.effect === 'allow') continue;
    if (held.reason === 'implicit' && atOrg(inputs, key).effect === 'allow') {
      const where = deviceId === null ? 'across the whole organization' : 'on this device';
      throw forbidden(`you cannot grant ${key}: you do not hold it ${where}`, 'scope_mismatch');
    }
    throw forbidden(`you cannot grant ${key}: you do not hold it`, held.reason === 'explicit_deny' ? 'explicit_deny' : 'missing_permission');
  }
}

// Returns the resolved set it checked, so the caller can snapshot it without resolving twice.
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const needed = MODE_PERMISSION[mode];
  if (!needed) throw badRequest('mode must be one of view, control, terminal');

  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  if (permissions['session:start'].effect !== 'allow') {
    throw refusal('session:start', permissions['session:start'], 'missing_permission');
  }
  if (permissions[needed].effect !== 'allow') {
    throw refusal(needed, permissions[needed], 'missing_device_permission');
  }
  return permissions;
}
