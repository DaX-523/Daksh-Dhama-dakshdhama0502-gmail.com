# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.


## Phase 0 — orientation

**2026-09-26**

Set up the repo: moved `starter/` to the root so `BUILD-LOG.md` and `DECISIONS.md` sit at the
root. Deleted `q1-starter/`, `tools/`, `DISCOVERY-RUBRIC.md` and `HARDENING.md`. Specs moved to `docs/`.


`.nvmrc` wants Node 22, I'm on 20.17. Install and all suites ran fine, so staying on 20.

Starting line on the untouched skeleton:
- `check-jwt.js`: 0 passed, 43 failed. Every case fails with the stub's TODO error, not a 401,
  so a verifier that just throws on everything can't pass by accident.
- `check-api.js`: the first request, "dana logs in", gets a 404 and the run aborts. There is no
  `/v1/auth/login` at all. The README's list of routes to write doesn't mention auth.
- `check-permissions.js` and `npm run personalisation` both die on the `resolve()` stub.
- Playwright not run yet, it needs a console first.

The database has a role (`reviewer`) and a permission (`device:reboot`) that aren't in any
doc. They're there to catch code that copies the docs' role table. Grading uses different
ones, so my code reads roles and permissions from the database instead of a list I type in.



## Phase 1 — token verification

**2026-09-26**

Implemented `verifyAccessToken` in `server/auth.js`. `check-jwt.js` went from 0/43 to 43/43.

Node doesn't reject bad base64: decoding garbage like `!!!not-base64!!!` just returns some
bytes instead of an error. So each part of the token is checked for allowed characters first.

The signature is compared as text, not as decoded bytes, because a few different strings
decode to the same bytes and would all pass.

Lengths are checked first, because it crashes on different lengths and a
cut-off signature would give a 500 instead of a 401.

## Phase 2 — caller context and the resolution engine

**2026-09-26**

Wrote the permission engine (`server/permissions.js`), the request context
(`server/context.js`) and the auth routes (login, refresh, logout, switch org, me).
`check-permissions.js` 35/35, personalisation 18/18.

How a permission gets decided: not an active member means everything is denied. Otherwise
a deny grant wins, then the role's list, then an allow grant, else it's an "implicit" deny.
The role's list and the grants are read from the database on every request.

NOTE: Dana is only a viewer in Globex, but her org-level `device:control` came
back allow, from her grant on globex-desk-01. Org level means "allowed on at least one
device". The row for globex-kiosk-02 still says deny.

A test passing for the wrong reason: "Acme token against Globex -> 404" already passes,
but only because the devices route doesn't exist yet and everything is a 404. It proves
nothing until the route is there.

The docs don't say what switching to an org you're not in should return. I return 404 as
you can't see orgs you don't belong to and 403 if you're a member but suspended.

Suspended members get 403 on every route, even ones with no permission check like
creating an org. Only switching to another org still works.

Refresh tokens work once. Tested re-using an old one: it fails, and it also kills the
newer token from the same sign-in, so the person has to log in again.

## Phase 3 — orgs, members, invites

**2026-09-26**

Wrote orgs, members and invites, plus `lifecycle.js` (who can change whom, last owner,
ending sessions) and `audit.js`.

An expired invite still blocked a new invite for the same email. The database rule "one
live invite per email" only looks at accepted/cancelled, not at the expiry date. So before
creating an invite I close any expired one for that email. Tested by moving an invite's
expiry into the past and re-inviting: 201. Side effect: the old invite now shows as
"revoked" in the list, not "expired".

The docs say an existing user who accepts an invite gets "attached". Taken literally,
anyone holding the link would be logged in as that person. So an existing account has to
type its own password to accept. Tested: wrong password 401, right password joins.

Removing someone now also revokes their grants in that org. Without that, re-inviting them
brings their old extra permissions back. Tested: gave a member an audit:read grant, removed
them, re-invited them: audit:read is deny.

Owners can change other owners (check-api expects Dana to demote the other Acme owner),
but everyone else can only change roles below their own. So "equal role is 403" is about
admins, not owners.

Last-owner check only counts active owners. A suspended owner can't run the org. I also
block suspending the last owner, which the docs don't mention.

Sam suspended in Acme can still log in: she lands in Globex, her first active org. Asking
for Acme explicitly gives 403 suspended.

## Phase 4 — devices and grants

**2026-09-26**

Wrote devices and grants. Then ran the experiment from phase 2: deleted the org check in
`context.js`. check-api's cross-org test failed (got 200, want 404), so it tests isolation
now. But calling the API by hand showed worse: an Acme token got Globex's members, audit log
and grants, because the routes read the org from the URL. Changed every route to use the
org from the token and repeated it: same requests now return Acme's own data, nothing from
Globex. Put the check back.

`device:*` includes `device:reboot`, which only exists in the database. An admin asking to
hand out `device:*` gets 403 naming `device:reboot`, because admins don't hold it.

A viewer with `device:provision` on one device can decommission that device, but can't add
new devices or give provision to someone org-wide (403 scope_mismatch).

A grant expiring at `2031-01-01T05:30:00+05:30` is stored as `2031-01-01T00:00:00.000Z`.
Times are compared as text, so everything has to be stored the same way.

Added a rule the docs don't have: a deny grant needs you to outrank the person, like a role
change. Otherwise an admin could deny the owner things. Tested: 403.

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
