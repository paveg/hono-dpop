---
"hono-dpop": patch
---

Middleware input-boundary hardening:

- Always call `nonceProvider.isValid` even when the proof's `nonce` claim is missing, removing a small timing oracle that distinguished "missing nonce" from "invalid nonce".
- Validate the `algorithms` option at factory time: passing an unsupported value (e.g. via a TypeScript escape hatch) now throws synchronously instead of silently being ignored at request time.
