import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { redisStore } from "../../src/stores/redis.js";

/**
 * Mock Redis client backed by a Map with TTL support. Implements SET NX/EX semantics
 * matching the surface used by ioredis, node-redis, and @upstash/redis.
 */
function createMockRedis() {
	const data = new Map<string, { value: string; expireAt?: number }>();
	return {
		data,
		async set(
			key: string,
			value: string,
			opts?: { NX?: boolean; EX?: number },
		): Promise<string | null> {
			if (opts?.NX) {
				const existing = data.get(key);
				if (existing && (!existing.expireAt || Date.now() < existing.expireAt)) {
					return null;
				}
			}
			data.set(key, {
				value,
				expireAt: opts?.EX ? Date.now() + opts.EX * 1000 : undefined,
			});
			return "OK";
		},
	};
}

describe("redisStore", () => {
	beforeEach(() => vi.useFakeTimers());
	afterEach(() => vi.useRealTimers());

	it("returns true and records jti when not seen", async () => {
		const client = createMockRedis();
		const store = redisStore({ client });
		expect(await store.check("a", Date.now() + 60_000)).toBe(true);
		expect(client.data.has("dpop:jti:a")).toBe(true);
	});

	it("returns false on replay within window", async () => {
		const client = createMockRedis();
		const store = redisStore({ client });
		const exp = Date.now() + 60_000;
		expect(await store.check("a", exp)).toBe(true);
		expect(await store.check("a", exp)).toBe(false);
	});

	it("computes EX from min(ttl, expiresAt - now) — short window wins", async () => {
		const client = createMockRedis();
		let captured: { NX?: boolean; EX?: number } | undefined;
		const orig = client.set.bind(client);
		client.set = async (k, v, opts) => {
			captured = opts;
			return orig(k, v, opts);
		};
		const store = redisStore({ client, ttl: 600 });
		// 30s remaining, ttl=600 → use 30
		await store.check("a", Date.now() + 30_000);
		expect(captured?.EX).toBe(30);
		expect(captured?.NX).toBe(true);
	});

	it("computes EX from min(ttl, expiresAt - now) — ttl wins", async () => {
		const client = createMockRedis();
		let captured: { NX?: boolean; EX?: number } | undefined;
		const orig = client.set.bind(client);
		client.set = async (k, v, opts) => {
			captured = opts;
			return orig(k, v, opts);
		};
		const store = redisStore({ client, ttl: 60 });
		// 600s remaining, ttl=60 → use 60
		await store.check("a", Date.now() + 600_000);
		expect(captured?.EX).toBe(60);
	});

	it("uses default ttl of 300 seconds when not provided", async () => {
		const client = createMockRedis();
		let captured: { NX?: boolean; EX?: number } | undefined;
		const orig = client.set.bind(client);
		client.set = async (k, v, opts) => {
			captured = opts;
			return orig(k, v, opts);
		};
		const store = redisStore({ client });
		await store.check("a", Date.now() + 999_999);
		expect(captured?.EX).toBe(300);
	});

	it("returns false immediately when expiresAt is in the past (no SET issued)", async () => {
		const client = createMockRedis();
		let setCount = 0;
		const orig = client.set.bind(client);
		client.set = async (k, v, opts) => {
			setCount++;
			return orig(k, v, opts);
		};
		const store = redisStore({ client });
		expect(await store.check("a", Date.now() - 1)).toBe(false);
		expect(setCount).toBe(0);
	});

	it("returns false when expiresAt equals now (zero remaining)", async () => {
		const client = createMockRedis();
		const store = redisStore({ client });
		expect(await store.check("a", Date.now())).toBe(false);
	});

	it("custom keyPrefix isolates entries", async () => {
		const client = createMockRedis();
		const a = redisStore({ client, keyPrefix: "tenantA:" });
		const b = redisStore({ client, keyPrefix: "tenantB:" });
		const exp = Date.now() + 60_000;
		expect(await a.check("jti1", exp)).toBe(true);
		expect(await b.check("jti1", exp)).toBe(true);
		expect(client.data.has("tenantA:jti1")).toBe(true);
		expect(client.data.has("tenantB:jti1")).toBe(true);
	});

	it("re-acquires after the Redis EX expires", async () => {
		const client = createMockRedis();
		const store = redisStore({ client, ttl: 60 });
		await store.check("a", Date.now() + 60_000);
		vi.advanceTimersByTime(60 * 1000);
		expect(await store.check("a", Date.now() + 60_000)).toBe(true);
	});

	it("purge() returns 0", async () => {
		const client = createMockRedis();
		const store = redisStore({ client });
		await store.check("a", Date.now() + 60_000);
		expect(await store.purge()).toBe(0);
	});

	describe("boundary cases", () => {
		it('check returns true when client.set resolves "OK"', async () => {
			const client = { set: async () => "OK" as string | null };
			const store = redisStore({ client });
			expect(await store.check("a", Date.now() + 60_000)).toBe(true);
		});

		it("check returns false when client.set resolves null (NX collision)", async () => {
			const client = { set: async () => null as string | null };
			const store = redisStore({ client });
			expect(await store.check("a", Date.now() + 60_000)).toBe(false);
		});

		it("check returns false when client.set resolves undefined", async () => {
			const client = { set: async () => undefined as unknown as string | null };
			const store = redisStore({ client });
			expect(await store.check("a", Date.now() + 60_000)).toBe(false);
		});

		it("propagates exceptions thrown by client.set", async () => {
			const client = {
				set: async () => {
					throw new Error("redis down");
				},
			};
			const store = redisStore({ client });
			await expect(store.check("a", Date.now() + 60_000)).rejects.toThrow("redis down");
		});

		it("expiresAt = now + 1 → EX = 1 (Math.ceil(0.001))", async () => {
			let captured: { NX?: boolean; EX?: number } | undefined;
			const client = {
				set: async (_k: string, _v: string, opts?: { NX?: boolean; EX?: number }) => {
					captured = opts;
					return "OK" as string | null;
				},
			};
			const store = redisStore({ client });
			await store.check("a", Date.now() + 1);
			expect(captured?.EX).toBe(1);
		});

		it("expiresAt = now → returns false without issuing SET (remainingSeconds <= 0)", async () => {
			let setCount = 0;
			const client = {
				set: async () => {
					setCount++;
					return "OK" as string | null;
				},
			};
			const store = redisStore({ client });
			expect(await store.check("a", Date.now())).toBe(false);
			expect(setCount).toBe(0);
		});

		it("expiresAt = now - 1000 → returns false without issuing SET", async () => {
			let setCount = 0;
			const client = {
				set: async () => {
					setCount++;
					return "OK" as string | null;
				},
			};
			const store = redisStore({ client });
			expect(await store.check("a", Date.now() - 1000)).toBe(false);
			expect(setCount).toBe(0);
		});

		it('keyPrefix = "" leaves the key as bare jti', async () => {
			let capturedKey: string | undefined;
			const client = {
				set: async (key: string) => {
					capturedKey = key;
					return "OK" as string | null;
				},
			};
			const store = redisStore({ client, keyPrefix: "" });
			await store.check("abc", Date.now() + 60_000);
			expect(capturedKey).toBe("abc");
		});

		it('keyPrefix = "tenant:" + jti = "abc" → key = "tenant:abc"', async () => {
			let capturedKey: string | undefined;
			const client = {
				set: async (key: string) => {
					capturedKey = key;
					return "OK" as string | null;
				},
			};
			const store = redisStore({ client, keyPrefix: "tenant:" });
			await store.check("abc", Date.now() + 60_000);
			expect(capturedKey).toBe("tenant:abc");
		});

		it("purge() always returns 0 (no-op contract)", async () => {
			const client = { set: async () => "OK" as string | null };
			const store = redisStore({ client });
			expect(await store.purge()).toBe(0);
		});
	});
});
