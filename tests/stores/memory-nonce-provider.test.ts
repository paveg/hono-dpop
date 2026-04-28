import type { Context } from "hono";
import { describe, expect, it } from "vitest";
import { memoryNonceProvider } from "../../src/stores/memory-nonce-provider.js";

const fakeCtx = {} as Context;

describe("memoryNonceProvider", () => {
	it("issues a UUID nonce", async () => {
		const provider = memoryNonceProvider();
		const nonce = await provider.issueNonce(fakeCtx);
		expect(nonce).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
	});

	it("isValid accepts the current nonce", async () => {
		const provider = memoryNonceProvider();
		const nonce = await provider.issueNonce(fakeCtx);
		expect(await provider.isValid(nonce, fakeCtx)).toBe(true);
	});

	it("isValid rejects unknown nonces", async () => {
		const provider = memoryNonceProvider();
		expect(await provider.isValid("not-the-nonce", fakeCtx)).toBe(false);
	});

	it("rotates after rotateAfter ms and accepts both current and previous by default", async () => {
		let now = 1_000_000;
		const provider = memoryNonceProvider({ rotateAfter: 1000, clock: () => now });
		const first = await provider.issueNonce(fakeCtx);
		now += 1500;
		const second = await provider.issueNonce(fakeCtx);
		expect(second).not.toBe(first);
		expect(await provider.isValid(second, fakeCtx)).toBe(true);
		expect(await provider.isValid(first, fakeCtx)).toBe(true); // previous still accepted
	});

	it("retainPrevious=false rejects previous nonce after rotation", async () => {
		let now = 1_000_000;
		const provider = memoryNonceProvider({
			rotateAfter: 1000,
			retainPrevious: false,
			clock: () => now,
		});
		const first = await provider.issueNonce(fakeCtx);
		now += 1500;
		const second = await provider.issueNonce(fakeCtx);
		expect(await provider.isValid(first, fakeCtx)).toBe(false);
		expect(await provider.isValid(second, fakeCtx)).toBe(true);
	});

	it("does not rotate within rotateAfter window", async () => {
		let now = 1_000_000;
		const provider = memoryNonceProvider({ rotateAfter: 5000, clock: () => now });
		const a = await provider.issueNonce(fakeCtx);
		now += 100;
		const b = await provider.issueNonce(fakeCtx);
		expect(a).toBe(b);
	});

	it("isValid also triggers rotation when due", async () => {
		let now = 1_000_000;
		const provider = memoryNonceProvider({ rotateAfter: 1000, clock: () => now });
		const first = await provider.issueNonce(fakeCtx);
		now += 1500;
		// Trigger rotation via isValid (first becomes previous)
		expect(await provider.isValid(first, fakeCtx)).toBe(true);
		const second = await provider.issueNonce(fakeCtx);
		expect(second).not.toBe(first);
	});
});
