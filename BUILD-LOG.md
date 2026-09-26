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

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

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
