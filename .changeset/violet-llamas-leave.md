---
"hono-dpop": patch
---

Internal release. No user-visible behavior change — published artifacts
(`dist/`) are byte-equivalent for the public API surface.

Aggregates dev-only work since `0.2.0`:

- Migrate to Biome 2 (`@biomejs/biome` 1.9 → 2.4)
- Refresh CI action versions: `actions/checkout` v6, `actions/setup-node` v6, `codecov/codecov-action` v6
- Refresh dev dependencies (vitest, tsup, typescript transitive ranges)
- Sync threat model with shipped features (size limits, nonce provider, jkt-binding helpers, clock injection)
- Add ADRs 0005-0008 documenting post-launch design decisions
- Add boundary test pinning `htm` case-sensitivity per RFC 9110 §9.1
