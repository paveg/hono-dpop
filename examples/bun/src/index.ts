import { Hono } from "hono";
import type { DPoPEnv } from "hono-dpop";
import { dpop } from "hono-dpop";
import { memoryNonceStore } from "hono-dpop/stores/memory";

const app = new Hono<DPoPEnv>();

app.get("/", (c) => c.text("hono-dpop bun example"));

app.use("/api/*", dpop({ nonceStore: memoryNonceStore() }));

app.get("/api/me", (c) => c.json({ jkt: c.get("dpop")?.jkt }));

Bun.serve({ fetch: app.fetch, port: 3000 });
