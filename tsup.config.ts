import { defineConfig } from "tsup";

export default defineConfig({
	entry: [
		"src/index.ts",
		"src/stores/memory.ts",
		"src/stores/redis.ts",
		"src/stores/cloudflare-kv.ts",
		"src/stores/cloudflare-d1.ts",
		"src/stores/durable-objects.ts",
	],
	format: ["esm", "cjs"],
	dts: true,
	clean: true,
	sourcemap: true,
	external: ["hono", "hono-problem-details"],
});
