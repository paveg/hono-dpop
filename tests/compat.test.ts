import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { dpop } from "../src/middleware.js";
import { memoryNonceStore } from "../src/stores/memory.js";
import { freshJti, generateKeyPair, nowSeconds, signProof } from "./helpers.js";

describe("getHonoProblemDetails", () => {
	beforeEach(() => {
		vi.resetModules();
	});

	it("returns the module when hono-problem-details is installed", async () => {
		const { getHonoProblemDetails } = await import("../src/compat.js");
		const pd = await getHonoProblemDetails();
		expect(pd).not.toBeNull();
		expect(pd).toHaveProperty("problemDetails");
	});

	it("caches result on subsequent calls", async () => {
		const { getHonoProblemDetails } = await import("../src/compat.js");
		const a = await getHonoProblemDetails();
		const b = await getHonoProblemDetails();
		expect(a).toBe(b);
	});

	it("returns null when hono-problem-details is not installed", async () => {
		vi.doMock("hono-problem-details", () => {
			throw new Error("Cannot find module 'hono-problem-details'");
		});
		const { getHonoProblemDetails } = await import("../src/compat.js");
		expect(await getHonoProblemDetails()).toBeNull();
	});

	it("caches null when module is unavailable", async () => {
		const factory = vi.fn(() => {
			throw new Error("Cannot find module 'hono-problem-details'");
		});
		vi.doMock("hono-problem-details", factory);
		const { getHonoProblemDetails } = await import("../src/compat.js");
		await getHonoProblemDetails();
		await getHonoProblemDetails();
		expect(factory).toHaveBeenCalledTimes(1);
	});
});

describe("middleware fallback when hono-problem-details is unavailable", () => {
	beforeEach(() => vi.resetModules());

	it("falls back to inline problemResponse with WWW-Authenticate", async () => {
		vi.doMock("hono-problem-details", () => {
			throw new Error("Cannot find module 'hono-problem-details'");
		});
		const app = new Hono();
		app.use("/api/*", dpop({ nonceStore: memoryNonceStore() }));
		app.get("/api/me", (c) => c.text("ok"));

		const res = await app.request("https://localhost/api/me");
		expect(res.status).toBe(401);
		expect(res.headers.get("Content-Type")).toContain("application/problem+json");
		expect(res.headers.get("WWW-Authenticate")).toContain('error="invalid_dpop_proof"');
	});

	it("uses hono-problem-details and adds WWW-Authenticate when present", async () => {
		const app = new Hono();
		app.use("/api/*", dpop({ nonceStore: memoryNonceStore() }));
		app.get("/api/me", (c) => {
			const proof = c.get("dpop");
			return c.json({ jkt: proof?.jkt });
		});

		const keyPair = await generateKeyPair("ES256");
		const jwt = await signProof({
			alg: "ES256",
			keyPair,
			payload: {
				jti: freshJti(),
				htm: "GET",
				htu: "https://localhost/api/me",
				iat: nowSeconds(),
			},
		});
		const ok = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
		expect(ok.status).toBe(200);

		const bad = await app.request("https://localhost/api/me");
		expect(bad.status).toBe(401);
		expect(bad.headers.get("WWW-Authenticate")).toContain("DPoP");
	});
});
