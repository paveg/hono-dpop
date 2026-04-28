# hono-dpop on Cloudflare Workers

```bash
pnpm install
pnpm dev    # local dev via wrangler
pnpm deploy # publish to your account
```

Send a `DPoP` proof header to `GET /api/me` to receive `{ jkt }`.
