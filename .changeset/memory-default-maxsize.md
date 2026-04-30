---
"hono-dpop": minor
---

`memoryNonceStore()` now defaults `maxSize` to 100,000 entries (was previously unbounded). This prevents OOM under unique-jti flood without an explicit `maxSize` option.

**Migration**: callers who relied on unbounded growth must now set `memoryNonceStore({ maxSize: <very large number> })` explicitly. Most callers will not need to change anything — the default is sized for typical workloads (peak ~333 jti/sec sustained for 5 minutes).
