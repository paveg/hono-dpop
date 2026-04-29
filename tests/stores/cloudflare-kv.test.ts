import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { kvStore } from "../../src/stores/cloudflare-kv.js";

interface KVNamespaceMock {
	data: Map<string, string>;
	get(key: string, opts?: { type?: "text" }): Promise<string | null>;
	put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
}

function createMockKV(): KVNamespaceMock {
	const data = new Map<string, string>();
	return {
		data,
		async get(key) {
			const value = data.get(key);
			return value === undefined ? null : value;
		},
		async put(key, value) {
			data.set(key, value);
		},
	};
}

describe("kvStore", () => {
	beforeEach(() => vi.useFakeTimers());
	afterEach(() => vi.useRealTimers());

	it("returns true on first sighting and stores a marker", async () => {
		const kv = createMockKV();
		const store = kvStore({ namespace: kv });
		expect(await store.check("a", Date.now() + 60_000)).toBe(true);
		expect(kv.data.has("dpop:jti:a")).toBe(true);
	});

	it("returns false on replay (key already present)", async () => {
		const kv = createMockKV();
		const store = kvStore({ namespace: kv });
		const exp = Date.now() + 60_000;
		expect(await store.check("a", exp)).toBe(true);
		expect(await store.check("a", exp)).toBe(false);
	});

	it("returns false immediately when expiresAt is in the past", async () => {
		const kv = createMockKV();
		let putCount = 0;
		const orig = kv.put.bind(kv);
		kv.put = async (k, v, o) => {
			putCount++;
			return orig(k, v, o);
		};
		const store = kvStore({ namespace: kv });
		expect(await store.check("a", Date.now() - 1)).toBe(false);
		expect(putCount).toBe(0);
	});

	it("clamps expirationTtl to KV minimum of 60s", async () => {
		const kv = createMockKV();
		let captured: { expirationTtl?: number } | undefined;
		const orig = kv.put.bind(kv);
		kv.put = async (k, v, o) => {
			captured = o;
			return orig(k, v, o);
		};
		const store = kvStore({ namespace: kv });
		// Only 5s remaining → clamped up to 60
		await store.check("a", Date.now() + 5_000);
		expect(captured?.expirationTtl).toBe(60);
	});

	it("uses ceil(remainingMs / 1000) for expirationTtl above floor", async () => {
		const kv = createMockKV();
		let captured: { expirationTtl?: number } | undefined;
		const orig = kv.put.bind(kv);
		kv.put = async (k, v, o) => {
			captured = o;
			return orig(k, v, o);
		};
		const store = kvStore({ namespace: kv });
		// 120_001 ms → ceil(120.001) = 121
		await store.check("a", Date.now() + 120_001);
		expect(captured?.expirationTtl).toBe(121);
	});

	it("custom keyPrefix isolates entries", async () => {
		const kv = createMockKV();
		const a = kvStore({ namespace: kv, keyPrefix: "tenantA:" });
		const b = kvStore({ namespace: kv, keyPrefix: "tenantB:" });
		const exp = Date.now() + 60_000;
		expect(await a.check("jti1", exp)).toBe(true);
		expect(await b.check("jti1", exp)).toBe(true);
		expect(kv.data.has("tenantA:jti1")).toBe(true);
		expect(kv.data.has("tenantB:jti1")).toBe(true);
	});

	it("raceWindowMs > 0 triggers read-back; mismatch returns false", async () => {
		const kv = createMockKV();
		const orig = kv.put.bind(kv);
		let putCount = 0;
		// Simulate a concurrent overwrite between put and read-back
		kv.put = async (k, v, o) => {
			await orig(k, v, o);
			putCount++;
			if (putCount === 1) {
				await orig(k, "hijacked-marker", o);
			}
		};
		const store = kvStore({ namespace: kv, raceWindowMs: 5 });
		const promise = store.check("a", Date.now() + 60_000);
		await vi.advanceTimersByTimeAsync(5);
		expect(await promise).toBe(false);
	});

	it("raceWindowMs > 0 returns true when read-back matches", async () => {
		const kv = createMockKV();
		const store = kvStore({ namespace: kv, raceWindowMs: 5 });
		const promise = store.check("a", Date.now() + 60_000);
		await vi.advanceTimersByTimeAsync(5);
		expect(await promise).toBe(true);
	});

	it("purge() returns 0", async () => {
		const kv = createMockKV();
		const store = kvStore({ namespace: kv });
		await store.check("a", Date.now() + 60_000);
		expect(await store.purge()).toBe(0);
	});

	describe("boundary cases", () => {
		it("expiresAt = now + 5_000 → expirationTtl clamped up to 60", async () => {
			const kv = createMockKV();
			let captured: { expirationTtl?: number } | undefined;
			kv.put = async (_k, _v, o) => {
				captured = o;
			};
			const store = kvStore({ namespace: kv });
			await store.check("a", Date.now() + 5_000);
			expect(captured?.expirationTtl).toBe(60);
		});

		it("expiresAt = now + 60_000 → expirationTtl = 60 (exact floor)", async () => {
			const kv = createMockKV();
			let captured: { expirationTtl?: number } | undefined;
			kv.put = async (_k, _v, o) => {
				captured = o;
			};
			const store = kvStore({ namespace: kv });
			await store.check("a", Date.now() + 60_000);
			expect(captured?.expirationTtl).toBe(60);
		});

		it("expiresAt = now + 61_000 → expirationTtl = 61 (above floor)", async () => {
			const kv = createMockKV();
			let captured: { expirationTtl?: number } | undefined;
			kv.put = async (_k, _v, o) => {
				captured = o;
			};
			const store = kvStore({ namespace: kv });
			await store.check("a", Date.now() + 61_000);
			expect(captured?.expirationTtl).toBe(61);
		});

		it("expiresAt = now → returns false without put (remainingMs <= 0)", async () => {
			const kv = createMockKV();
			let putCount = 0;
			kv.put = async () => {
				putCount++;
			};
			const store = kvStore({ namespace: kv });
			expect(await store.check("a", Date.now())).toBe(false);
			expect(putCount).toBe(0);
		});

		it("expiresAt = now - 1 → returns false without put", async () => {
			const kv = createMockKV();
			let putCount = 0;
			kv.put = async () => {
				putCount++;
			};
			const store = kvStore({ namespace: kv });
			expect(await store.check("a", Date.now() - 1)).toBe(false);
			expect(putCount).toBe(0);
		});

		it("default raceWindowMs (0) skips read-back; first put wins", async () => {
			const kv = createMockKV();
			let getCount = 0;
			const origGet = kv.get.bind(kv);
			kv.get = async (k, o) => {
				getCount++;
				return origGet(k, o);
			};
			const store = kvStore({ namespace: kv });
			expect(await store.check("a", Date.now() + 60_000)).toBe(true);
			// Only the pre-put get fires; no read-back
			expect(getCount).toBe(1);
		});

		it("raceWindowMs > 0 with mismatched read-back returns false", async () => {
			const kv = createMockKV();
			const origPut = kv.put.bind(kv);
			let putCount = 0;
			kv.put = async (k, v, o) => {
				await origPut(k, v, o);
				putCount++;
				if (putCount === 1) {
					await origPut(k, "different-marker", o);
				}
			};
			const store = kvStore({ namespace: kv, raceWindowMs: 5 });
			const promise = store.check("a", Date.now() + 60_000);
			await vi.advanceTimersByTimeAsync(5);
			expect(await promise).toBe(false);
		});

		it("propagates exceptions thrown by KV.put", async () => {
			const kv = createMockKV();
			kv.put = async () => {
				throw new Error("kv unavailable");
			};
			const store = kvStore({ namespace: kv });
			await expect(store.check("a", Date.now() + 60_000)).rejects.toThrow("kv unavailable");
		});

		it("returns false when KV.get already returns an existing marker (replay)", async () => {
			const kv = createMockKV();
			kv.get = async () => "existing-marker";
			let putCount = 0;
			kv.put = async () => {
				putCount++;
			};
			const store = kvStore({ namespace: kv });
			expect(await store.check("a", Date.now() + 60_000)).toBe(false);
			expect(putCount).toBe(0);
		});

		it('keyPrefix = "" stores the key as bare jti', async () => {
			const kv = createMockKV();
			let capturedKey: string | undefined;
			kv.put = async (k) => {
				capturedKey = k;
			};
			const store = kvStore({ namespace: kv, keyPrefix: "" });
			await store.check("abc", Date.now() + 60_000);
			expect(capturedKey).toBe("abc");
		});
	});
});
