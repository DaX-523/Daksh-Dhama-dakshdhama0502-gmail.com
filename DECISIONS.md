# DECISIONS

Each section: what I chose, the evidence, the alternative I rejected and why it fails, and what
would change my mind. Line numbers are as of the commit that last touched the file.

---

### The token header is checked but never trusted, and the signature is compared as text

**What I chose:** HMAC-SHA256 is hardcoded. The header only has to equal `{ alg: HS256, typ: JWT }`.
Each segment's characters are checked before decoding, and the signature is compared as base64url
text in constant time (`server/auth.js:50`, `:68`, `:76`).

**Why:** Node's base64url decoder does not reject bad input: `Buffer.from('!!!not-base64!!!',
'base64url')` returns 7 bytes. For one real HMAC I counted 4 different signature strings that decode
to the same 32 bytes, because the last character carries 2 spare bits. `check-jwt.js` went from 0/43
to 43/43 in `01cff46`.

**What I rejected:** decoding the signature and comparing bytes. It passes every shipped test but
accepts 4 spellings of each signature. Also rejected: calling `timingSafeEqual` without a length
check first. It throws `ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH` on a truncated signature, which becomes a
500 instead of a 401.

**What would change my mind:** tokens from a second issuer that uses a different valid base64
spelling. Then I would normalise both sides before comparing instead of rejecting.

---

### The org-level answer counts device-scoped grants

**What I chose:** the org-level answer is "allowed anywhere in the org": allowed at the org scope
(role baseline plus org-wide grants), or allowed on at least one device. An org-wide deny closes it
everywhere (`server/permissions.js:79`).

**Why:** the Acme viewer can start a view session on lab-mac-01 only, through a device-scoped
`session:start` grant, and "Start a session" in the Sessions card is gated by `session:start` with no
device. On the live server, Dana (a viewer in Globex) gets org-level `device:control` allowed with
source `grant:grt_dana_control_one_device`, while the globex-kiosk-02 row still says deny.

**What I rejected:** org level as baseline plus org-wide grants only. The viewer would never see
"Start a session" although the API accepts that session on lab-mac-01, so the screen would hide
something the server allows. Also rejected: reporting `explicit_deny` at org level whenever a
device-scoped deny exists. It would tell the Acme viewer that `device:view` is denied across the org
when only kiosk-lobby-01 is.

**What would change my mind:** a UI case expecting an org-level entry to be absent for someone who
holds the permission on exactly one device.

---

### Suspension is enforced when the request is authenticated, not only in permission checks

**What I chose:** `server/context.js:31` refuses a suspended membership with `403 suspended` on every
route except switching org (`POST /auth/token`).

**Why:** some routes check no permission at all: creating an org, listing orgs, `/auth/me`, and
leaving with `DELETE /members/me`. Leaving is the one that matters. A suspended member could leave on
their own, turning a reversible suspension an admin chose into a removal. Tested live: Sam, suspended
in Acme, gets 403 suspended when asking for Acme, and lands in Globex when signing in without an org.

**What I rejected:** relying on `resolve()` returning reason `suspended`. That covers every
permission-gated route and none of the ungated ones.

**What would change my mind:** a requirement that a suspended member can still read their own
profile. `/auth/me` would then join the exception list.

---

### Switching to an org you do not belong to is a 404, not a 401

**What I chose:** `POST /auth/token`, and login with an explicit `orgId`, return 404 when you are not
a member and `403 suspended` when you are a suspended member (`server/routes/auth.js:42`).

**Why:** a 401 tells the client its credentials are bad, so it drops the token and signs out, even
though the token is still valid for its own org. A 404 matches the rule used everywhere else: an org
you cannot see does not exist for you. Tested: switching to `org_nope` is 404.

**What I rejected:** 401, for the reason above, and 403 for non-members, which confirms the org exists.

**What would change my mind:** a hidden-tier case expecting 401 here. PERMISSIONS.md:177 says "Not a
member → 401", so this is the decision I am least sure of. See the section at the end.

---

### An existing account has to enter its password to accept an invite

**What I chose:** if the invited email already has an account, accepting requires that account's
password. A new email gives a name and a password (`server/routes/invites.js:123`).

**Why:** accepting signs the person in. If an existing user were attached on the invite token alone,
anyone holding a leaked link would be signed in as that person, including in their other orgs
through the org switcher. Tested: wrong password is 401, the right one joins, and both orgs appear.

**What I rejected:** attaching on the token alone (above). Also rejected: refusing invites to existing
emails, which breaks "an existing platform user with no membership here gets attached on accept".

**What would change my mind:** if accepting did not sign anyone in, attaching without a password
would be harmless.

---

### Removing a member also revokes their grants in that org

**What I chose:** `endMembership` (`server/routes/orgs.js:58`) sets the membership to removed, bumps
`perm_version`, ends their sessions in the org and revokes their grants there. The user row stays.

**Why:** the membership row is reused if the same person is invited again (`UNIQUE (org_id,
user_id)`), and their grants are keyed by user and org. Tested: gave a member an `audit:read` grant,
removed them, re-invited them, and `audit:read` came back deny.

**What I rejected:** leaving grants alone because users are never deleted. A re-invite would silently
restore old extra permissions that the person re-inviting them never saw.

**What would change my mind:** a need to pause someone with their setup intact. That is what
suspension is for, and suspension keeps grants.

---

### Last-owner protection counts active owners and also guards suspension

**What I chose:** `assertNotLastOwner` (`server/lifecycle.js:33`) counts owners whose membership is
active, and it runs on demote, remove, leave and suspend.

**Why:** admins cannot modify owners, so only an owner can reinstate a suspended owner. Tested: the
sole owner of a new org gets `409 LAST_OWNER` when leaving.

**What I rejected:** counting every membership with role owner. With one active and one suspended
owner, the active one could be demoted, and then nobody could run the org or reinstate the other.

**What would change my mind:** a recovery path for ownerless orgs outside the API.

---

### Refresh rotation is decided by a conditional update

**What I chose:** a refresh only proceeds if `UPDATE ... WHERE id = ? AND revoked_at IS NULL AND
expires_at > ?` changed exactly one row. Presenting a token that was already rotated revokes its
whole family (`server/routes/auth.js:116`).

**Why:** tested live: reusing an old refresh cookie is 401, and it also kills the newest cookie from
the same sign-in. This server runs handlers one at a time on one connection, so a read-then-update
could not race today. The conditional update keeps that true if it ever runs as more than one process.

**What I rejected:** read the row, check `revoked_at`, then update. Two refreshes with the same cookie
in two processes could both pass the check and both get new tokens.

**What would change my mind:** users with several tabs being signed out by near-simultaneous
refreshes. Then I would give the previous token a few seconds of grace.

---

### Routes read data from the token's org, never from the org in the URL

**What I chose:** every route queries with `ctx.orgId` (the org in the verified token). The org in the
path only has to match it, which `server/context.js:29` checks and turns into a 404.

**Why:** I deleted the check at `context.js:29` to prove `check-api.js` tests isolation. The test
failed as it should ("got 200 want 404"), but a live request showed more: while routes still read
`params.org`, an Acme token received Globex's members, audit log and grants. Only devices held,
because the engine refuses devices outside the caller's org. After switching every route to
`ctx.orgId` and repeating the experiment, the same requests returned Acme's own data, never Globex's.

**What I rejected:** trusting `params.org` once the context check has passed. It works, but all
isolation then rests on one line, and one refactor away from a cross-tenant leak.

**What would change my mind:** an endpoint that genuinely addresses two orgs. Transfer is the only one,
and it looks the destination membership up explicitly (`server/routes/devices.js:159`).

---

### You can only hand out authority you hold, at the scope you are handing it out

**What I chose:** an allow grant on one device needs every permission it names allowed for the caller
on that device. An org-wide allow grant needs it allowed at org scope and denied on no device
(`acrossOrg`, `server/permissions.js:92`). Wildcards are expanded against the `permissions` table
before checking. Adding a device and creating an org-wide grant also need the permission at org scope,
not on some device (`assertCanOrgScope`, `server/permissions.js:151`).

**Why:** tested live. A viewer holding `device:provision` on one device gets `403 scope_mismatch`
granting it org-wide, and `403` adding a device. An admin with an org-wide deny on `device:terminal`
gets `403 explicit_deny` handing terminal to anyone. The same admin asking to hand out `device:*` gets
`403` naming `device:reboot`: the wildcard includes the permission that exists only in the database,
and admins do not hold it.

**What I rejected:** checking against the org-level answer, which is "allowed on any device" (see the
section above). Holding a permission on one device would then be enough to grant it everywhere.

**What would change my mind:** a product need for delegated admins who manage one device fleet. That
needs grants scoped to a set of devices, which the schema does not have.

---

### Deny grants follow the same rank rule as role changes, and nobody edits grants about themselves

**What I chose:** creating a deny grant, or revoking an allow grant, needs the caller to outrank the
person it applies to (`server/routes/devices.js:225`). Nobody can create or revoke a grant that
applies to themselves (`:257`).

**Why:** AUTH-DATA-MODEL.md §8 lists the checks for creating grants and rank is not among them, but a
deny grant takes authority away exactly like a demotion does. Tested: an admin denying an owner's
`org:update` gets `403 insufficient_rank`. An admin revoking a deny that applies to them gets
`403 self_grant`, which would otherwise be a self-grant by another route.

**What I rejected:** following the §8 list as written. An admin could deny the owners `grant:revoke`
and `user:role:update`, and the owners could not undo it through their own grants either.

**What would change my mind:** a hidden-tier case where an admin is expected to deny something to
another admin. It contradicts nothing written, so this is a rule I added, not one I was given.

---

### Session exclusivity is decided by the unique index, and expiry happens on the next read

**What I chose:** starting a session inserts and lets `one_exclusive_session_per_device` refuse a
second exclusive session, which becomes `409 DEVICE_BUSY` naming the holder
(`server/routes/sessions.js:59`). Sessions past `expires_at` are ended as `session_expired` by
`expireSessions` (`server/lifecycle.js:55`) before any session read or start in that org.

**Why:** two exclusive requests sent at the same moment returned exactly one 201 and one 409. A
session whose `expires_at` I moved into the past read back as `ended / session_expired`, and the
device immediately accepted a new exclusive session.

**What I rejected:** checking for an active session before inserting, which races. Also rejected: a
background timer to end expired sessions, which adds a moving part and still leaves a window where a
dead session blocks the device until the timer runs.

**What would change my mind:** a report of sessions expiring for an org nobody reads, for example to
notify someone. Then a periodic sweep would earn its place.

---

## Where this repo argues with itself

**Not a member: 401 or 404?** PERMISSIONS.md:177 says "Not a member, or no valid credentials → `401
UNAUTHENTICATED`." AUTH-DATA-MODEL.md:252 says "a token for org A used against org B routes →
`404`". Built: a token whose own membership is gone is 401, and naming any other org (in a path or
when switching) is 404. Reason in the section above.

**Equal roles.** PERMISSIONS.md:224 says "modify a user of equal role (admin → admin) | `403`".
`scripts/check-api.js:150` expects an owner demoting another owner to succeed. Built against the
test: owners may manage owners, everyone else only roles below their own (`server/lifecycle.js:16`).

**What wildcards expand to.** PERMISSIONS.md:163 says "`device:*` collapses to the seven device
permissions; `*` to all nineteen." The database has a twentieth permission (`device:reboot` in my
copy). Built against the database: wildcards expand against the `permissions` table at request time
(`server/permissions.js:40`).

**Who writes login.** README.md:72 lists the routes to write as "orgs, members, invites, devices,
grants, sessions, audit", which leaves auth out, but no auth route exists and `check-api.js` fails
its first request with 404. Built the auth routes in `server/routes/auth.js`.

**A device you may not view: absent or forbidden?** UI-INVENTORY.md says a device the caller cannot
`device:view` "is not listed at all", while PERMISSIONS.md §5 says "You can see it but lack the
permission → `403`" and BRIEF.md §5.1 gates `GET /devices/{id}` on `device:view`. Built both as
written: the list leaves the row out (`server/routes/devices.js:90`), and the detail route answers
`403 explicit_deny`, because the device is in the caller's own org.

**Stale section numbers.** `scripts/check-permissions.js:2` cites "PERMISSIONS.md §11 or §12", and
`server/http.js:3` cites §10 for the error shape. PERMISSIONS.md ends at §10, and the error shape is
in §5. No behaviour depends on this; noted so nobody goes looking.

## Deliberately not built

- **Rate limiting and lockout on login.** Listed as out of scope in README.md. Unknown emails still
  cost a scrypt, so timing does not reveal which accounts exist.
- **Auditing sign-in attempts.** `audit_events.org_id` is NOT NULL and a failed sign-in has no org to
  belong to. Writing it into every org the person belongs to would leak one org's attempts to another.
- **Email delivery and password reset.** The invite token is returned once in the API response,
  as the brief says.
- **Pagination and search for members, devices, grants and sessions.** Only the audit log pages
  (`limit` 1 to 500, `offset`), because it is the one list that grows without bound. The session
  list returns the newest 200.
- **Real device status.** `online` is a stored flag that `PATCH /devices/{id}` can set. Nothing
  connects to a device, by the "no real remote access" rule.

## Tools and sources

- **Claude (Anthropic), used through Claude Code**, for the whole build: reading the specs and tests,
  writing the server code, running the test suites and live smoke tests, and drafting this file and
  the BUILD-LOG entries from what we ran. I reviewed each change and committed it myself.
- **Libraries:** only what the starter shipped with (better-sqlite3, React, Vite, Playwright). Tokens
  and password hashing use `node:crypto`. Nothing was added.
- No blog posts or other candidates' repositories were used. `q1-starter/`, the reference
  implementation that came with the fork, was deleted in the first commit (`bb0175a`) and not used.
