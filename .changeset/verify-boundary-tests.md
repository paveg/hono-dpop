---
"hono-dpop": patch
---

Add boundary tests asserting that `parseProof` tolerates extra JWS header fields (such as `kid`, `x5c`, `cty`) alongside the required `typ` / `alg` / `jwk`. No behavior change — these tests pin the existing tolerance as a contract so future tightening is a deliberate decision.
