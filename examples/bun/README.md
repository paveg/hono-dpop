# hono-dpop on Bun

```bash
bun install
bun run dev # listens on http://localhost:3000
```

`GET /` is public. `GET /api/me` requires a `DPoP` proof header and returns `{ jkt }`.
