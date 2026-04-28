import { bench, describe } from "vitest";
import { memoryNonceStore } from "../src/stores/memory.js";

const TTL_MS = 5 * 60_000;
const PRELOAD = 10_000;

// Top-level await: vitest's benchmark runner does not invoke beforeAll/beforeEach hooks,
// so async setup must complete before bench() registration.
const cold = memoryNonceStore();
const warm = memoryNonceStore();
const preloadExpiresAt = Date.now() + TTL_MS;
for (let i = 0; i < PRELOAD; i++) {
	await warm.check(`preload-${i}`, preloadExpiresAt);
}

let coldCounter = 0;
let warmCounter = 0;

describe("memoryNonceStore.check", () => {
	bench("cold (empty store)", async () => {
		await cold.check(`cold-${coldCounter++}`, Date.now() + TTL_MS);
	});

	bench("warm (10k pre-populated)", async () => {
		await warm.check(`warm-${warmCounter++}`, Date.now() + TTL_MS);
	});
});
