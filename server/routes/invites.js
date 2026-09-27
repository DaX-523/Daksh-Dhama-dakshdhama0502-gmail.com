import { sql, newId, nowIso } from '../db.js';
import { send, conflict, notFound, gone, unauthenticated } from '../http.js';
import { newInviteToken, hashInviteToken, hashPassword, verifyPassword } from '../auth.js';
import { assertCan } from '../permissions.js';
import { audit, auditDenials, auditAllow } from '../audit.js';
import { assertRoleExists, assertCanAssign } from '../lifecycle.js';
import { requireEmail, requireName, requirePassword, isUniqueViolation } from '../validate.js';
import { signIn } from './auth.js';

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function statusOf(invite, now) {
  if (invite.accepted_at) return 'accepted';
  if (invite.revoked_at) return 'revoked';
  return invite.expires_at <= now ? 'expired' : 'pending';
}

const inviteView = (i, now) => ({
  id: i.id, email: i.email, role: i.role, status: statusOf(i, now),
  expires_at: i.expires_at, created_at: i.created_at, invited_by: i.invited_by,
});

// The raw token is only ever hashed and compared. It is never stored, logged or echoed back.
function liveInviteFor(db, rawToken) {
  const invite = sql(
    db,
    `SELECT i.*, o.name AS org_name FROM invites i
       JOIN organizations o ON o.id = i.org_id AND o.deleted_at IS NULL
      WHERE i.token_hash = ?`
  ).get(hashInviteToken(rawToken));
  if (!invite) throw notFound();
  const status = statusOf(invite, nowIso());
  if (status === 'accepted') throw conflict('this invite has already been used');
  if (status !== 'pending') throw gone(status === 'expired' ? 'this invite has expired' : 'this invite was cancelled');
  return invite;
}

export function registerInviteRoutes(router, { db, secret }) {
  router.post('/v1/orgs/:org/invites', (ctx, params, res) => {
    const created = auditDenials(db, ctx, { action: 'invite.create', targetType: 'invite' }, () => {
      assertCan(db, ctx, 'user:invite');
      const email = requireEmail(ctx.body.email);
      assertRoleExists(db, ctx.body.role);
      assertCanAssign(db, ctx.role, ctx.body.role);

      const raw = newInviteToken();
      const id = newId('inv');
      const now = nowIso();
      const expiresAt = new Date(Date.now() + INVITE_TTL_MS).toISOString();

      db.transaction(() => {
        const member = sql(
          db,
          `SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
            WHERE m.org_id = ? AND u.email = ? AND m.status IN ('active', 'suspended')`
        ).get(ctx.orgId, email);
        if (member) throw conflict('that person is already a member of this organization');

        // The live-invite index knows nothing about time, so an expired invite would block a new
        // one forever. Close expired ones first; a still-pending invite is a real conflict.
        sql(
          db,
          `UPDATE invites SET revoked_at = ?
            WHERE org_id = ? AND email = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at <= ?`
        ).run(now, ctx.orgId, email, now);

        try {
          sql(
            db,
            `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          ).run(id, ctx.orgId, email, ctx.body.role, hashInviteToken(raw), ctx.userId, expiresAt, now);
        } catch (err) {
          if (isUniqueViolation(err)) throw conflict('a pending invite already exists for that email');
          throw err;
        }
        auditAllow(db, ctx, { action: 'invite.create', targetType: 'invite', targetId: id });
      })();

      return { invite: inviteView(sql(db, 'SELECT * FROM invites WHERE id = ?').get(id), now), inviteToken: raw };
    });
    send(res, 201, created);
  });

  router.get('/v1/orgs/:org/invites', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'invite.list', targetType: 'org', targetId: ctx.orgId }, () =>
      assertCan(db, ctx, 'user:invite')
    );
    const now = nowIso();
    const invites = sql(db, 'SELECT * FROM invites WHERE org_id = ? ORDER BY created_at DESC, id').all(ctx.orgId);
    send(res, 200, { invites: invites.map((i) => inviteView(i, now)) });
  });

  router.delete('/v1/orgs/:org/invites/:id', (ctx, params, res) => {
    const meta = { action: 'invite.revoke', targetType: 'invite', targetId: params.id };
    auditDenials(db, ctx, meta, () => {
      assertCan(db, ctx, 'user:invite');
      db.transaction(() => {
        const revoked = sql(
          db,
          `UPDATE invites SET revoked_at = ?
            WHERE id = ? AND org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL`
        ).run(nowIso(), params.id, ctx.orgId);
        if (revoked.changes !== 1) throw notFound();
        auditAllow(db, ctx, meta);
      })();
    });
    send(res, 204);
  });

  router.get('/v1/invites/:token', (_ctx, params, res) => {
    const invite = liveInviteFor(db, params.token);
    send(res, 200, { orgName: invite.org_name, role: invite.role, email: invite.email, expiresAt: invite.expires_at });
  });

  // An email that already has an account must prove it owns that account with its password.
  // Otherwise a leaked invite link would hand the account itself to whoever clicked it.
  router.post('/v1/invites/:token/accept', (ctx, params, res) => {
    const invite = liveInviteFor(db, params.token);
    const existing = sql(db, 'SELECT id, password_hash FROM users WHERE email = ?').get(invite.email);

    let newUser = null;
    if (existing) {
      if (!verifyPassword(String(ctx.body.password ?? ''), existing.password_hash)) {
        throw unauthenticated('this email already has an account: enter that account\'s password to accept');
      }
    } else {
      const name = requireName(ctx.body.name, 'name');
      newUser = { id: newId('usr'), name, hash: hashPassword(requirePassword(ctx.body.password)) };
    }
    const userId = existing?.id ?? newUser.id;

    db.transaction(() => {
      const now = nowIso();
      if (newUser) {
        sql(db, 'INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)')
          .run(newUser.id, invite.email, newUser.name, newUser.hash);
      }

      const claimed = sql(
        db,
        `UPDATE invites SET accepted_at = ?, accepted_by = ?
          WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?`
      ).run(now, userId, invite.id, now);
      if (claimed.changes !== 1) throw conflict('this invite has already been used');

      const current = sql(db, 'SELECT id, status FROM memberships WHERE org_id = ? AND user_id = ?').get(invite.org_id, userId);
      if (current && (current.status === 'active' || current.status === 'suspended')) {
        throw conflict('you are already a member of this organization');
      }
      if (current) {
        sql(
          db,
          `UPDATE memberships SET role = ?, status = 'active', perm_version = perm_version + 1, invited_by = ?, joined_at = ?
            WHERE id = ?`
        ).run(invite.role, invite.invited_by, now, current.id);
      } else {
        sql(
          db,
          `INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at)
           VALUES (?, ?, ?, ?, 'active', ?, ?)`
        ).run(newId('mem'), invite.org_id, userId, invite.role, invite.invited_by, now);
      }
      audit(db, {
        orgId: invite.org_id, actorId: userId, action: 'invite.accept', targetType: 'invite', targetId: invite.id,
        result: 'allow', requestId: ctx.requestId,
      });
    })();

    send(res, 200, signIn(db, secret, res, userId, invite.org_id));
  });
}
