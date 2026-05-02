---
"hono-dpop": minor
---

Drop Node.js 20 support; require Node.js 22 or newer.

Node.js 20 reached end-of-life on 2026-04-30. The `engines.node` field has
been bumped from `>=20` to `>=22`, and the CI matrix no longer tests against
Node 20. Consumers still on Node 20 will see an `EBADENGINE` warning from
npm/pnpm on install — upgrade to Node 22 LTS or Node 24.

Also bumps `pnpm/action-setup` in CI workflows from v4 to v6.
