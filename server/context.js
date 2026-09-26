import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, forbidden, notFound } from './http.js';

const BEARER = /^Bearer ([^\s]+)$/;

// A suspended member may still switch to an org where they are active.
const OPEN_WHEN_SUSPENDED = new Set(['POST /v1/auth/token']);

export function authenticate(db, secret) {
  const membershipOf = db.prepare(
    `SELECT m.id, m.org_id, m.user_id, m.role, m.status, m.perm_version
       FROM memberships m
       JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
      WHERE m.org_id = ? AND m.user_id = ?`
  );

  return function buildContext(req, params) {
    const match = BEARER.exec(req.headers.authorization ?? '');
    if (!match) throw unauthenticated('missing bearer token');

    const claims = verifyAccessToken(match[1], secret);
    const membership = membershipOf.get(claims.org, claims.sub);
    if (!membership || membership.status === 'removed' || membership.status === 'invited') {
      throw unauthenticated('not a member of this organization');
    }
    assertFresh(claims, membership);

    // The token names exactly one org. Any other org in the path is invisible to this caller.
    if (params.org !== undefined && params.org !== claims.org) throw notFound();

    if (membership.status === 'suspended') {
      const route = `${req.method} ${new URL(req.url, 'http://x').pathname}`;
      if (!OPEN_WHEN_SUSPENDED.has(route)) {
        throw forbidden('your membership in this organization is suspended', 'suspended');
      }
    }

    return { userId: claims.sub, orgId: claims.org, role: membership.role, membership, claims };
  };
}
