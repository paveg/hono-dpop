# ADR-0004: jti replay protection via a pluggable single-method store

## Status
Accepted

## Context
RFC 9449 §11.1 requires the resource server to detect proof replay within a freshness window. The mechanism is a record of seen `jti` values bounded by an expiry. Where that record lives — process memory, Redis, Cloudflare KV, Durable Object, Postgres — is a deployment decision that depends on the consumer's topology, durability requirements, and budget.

We needed a store interface narrow enough that implementing it for any backend is trivial, while still expressing the atomicity guarantee that replay protection demands.

A useful comparison is `hono-idempotency`, which exposes a 5-method interface (`get`, `set`, `lock`, `unlock`, etc.) because it has to store full responses for replay. DPoP needs none of that: the proof carries its own response — verification is deterministic — so the store only needs to remember "has this `jti` been seen?".

## Decision
The interface (`src/stores/types.ts`) is two methods, with `check` doing all the work:

```ts
interface DPoPNonceStore {
  check(jti: string, expiresAt: number): Promise<boolean>;
  purge(): Promise<number>;
}
```

`check` is **atomic test-and-set**: returns `true` if the `jti` was not previously recorded (and now is), `false` if it was already present within its expiry window. Implementations must guarantee that exactly one concurrent caller observes `true` for the same `jti`. `purge` is for stores without native expiration; backends like Redis with TTL can no-op it.

`expiresAt` is a Unix-millisecond absolute timestamp computed by the middleware from `iat` plus the configured `jtiTtl`. Pushing the timestamp through the interface — rather than passing a TTL — lets stateful stores set per-key expiry directly without recomputing the deadline.

## Consequences
**Positive**

- A new backend implementation is ~30 lines (see `src/stores/memory.ts`).
- Atomicity is the explicit contract, so reviewers of a Redis or KV adapter know what to look for (use `SET NX PX` or equivalent CAS, not `GET` then `SET`).
- The interface does not leak DPoP types — the store is a generic seen-set with expiry, reusable for other replay-cache scenarios.

**Negative**

- All durability and HA guarantees are pushed onto the implementer. A consumer that picks the in-memory store on a multi-instance deployment will silently allow cross-instance replays.
- The interface gives the store no signal about which proof a `jti` belongs to, so a backend cannot apply per-key cardinality limits or per-tenant quotas without extending the contract.
- The atomicity requirement is documented but not machine-enforced. A naive `get`-then-`set` implementation will pass tests under low load and fail under contention.
