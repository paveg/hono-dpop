# hono-dpop on Node.js

```bash
pnpm install
pnpm dev # listens on http://localhost:3000
```

`GET /` is public. `GET /api/me` requires a `DPoP` proof header and returns `{ jkt }`.
