import { Hono } from "hono";
import type { DPoPEnv } from "hono-dpop";
import { dpop } from "hono-dpop";
import { memoryNonceStore } from "hono-dpop/stores/memory";

// Bindings is empty today; declared so future KV/D1 bindings slot in cleanly.
type Bindings = Record<string, never>;

const app = new Hono<{ Bindings: Bindings } & DPoPEnv>();

app.use("/api/*", (c, next) => {
	// Per-request store: Workers isolates may be reused, but a fresh in-memory cache
	// per request keeps the example self-contained. Replace with `kvNonceStore` once
	// it ships in v0.2.0 to share the replay window across isolates.
	const middleware = dpop({ nonceStore: memoryNonceStore() });
	return middleware(c, next);
});

app.get("/api/me", (c) => {
	return c.json({ jkt: c.get("dpop")?.jkt });
});

export default app;
