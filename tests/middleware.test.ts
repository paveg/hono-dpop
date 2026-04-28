import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { dpop } from "../src/middleware.js";
import { memoryNonceStore } from "../src/stores/memory.js";
import type { DPoPNonceStore, NonceProvider } from "../src/stores/types.js";
import type { DPoPOptions } from "../src/types.js";
import { computeAth } from "../src/verify.js";
import { freshJti, generateKeyPair, nowSeconds, signProof } from "./helpers.js";

function createApp(opts: Partial<DPoPOptions> = {}) {
	const nonceStore = opts.nonceStore ?? memoryNonceStore();
	const app = new Hono();
	app.use("/api/*", dpop({ ...opts, nonceStore }));
	app.get("/api/me", (c) => {
		const proof = c.get("dpop");
		return c.json({ jkt: proof?.jkt, jti: proof?.jti });
	});
	app.post("/api/order", (c) => c.json({ ok: true }));
	return { app, nonceStore };
}

async function makeProof(
	opts: {
		htm?: string;
		url?: string;
		jti?: string;
		iat?: number;
		ath?: string;
		nonce?: string;
	} = {},
) {
	const keyPair = await generateKeyPair("ES256");
	const url = opts.url ?? "https://localhost/api/me";
	const jwt = await signProof({
		alg: "ES256",
		keyPair,
		payload: {
			jti: opts.jti ?? freshJti(),
			htm: opts.htm ?? "GET",
			htu: url,
			iat: opts.iat ?? nowSeconds(),
			ath: opts.ath,
			nonce: opts.nonce,
		},
	});
	return { jwt, keyPair };
}

describe("dpop middleware", () => {
	it("D1: rejects when DPoP header is missing", async () => {
		const { app } = createApp();
		const res = await app.request("https://localhost/api/me");
		expect(res.status).toBe(401);
		expect(res.headers.get("WWW-Authenticate")).toContain("DPoP");
		expect(res.headers.get("Content-Type")).toContain("application/problem+json");
		const body = (await res.json()) as { code: string };
		expect(body.code).toBe("INVALID_DPOP_PROOF");
	});

	it("D2: accepts valid proof and exposes c.get('dpop')", async () => {
		const { app } = createApp();
		const { jwt } = await makeProof();
		const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
		expect(res.status).toBe(200);
		const body = (await res.json()) as { jkt: string };
		expect(body.jkt).toMatch(/^[A-Za-z0-9_-]{43}$/);
	});

	it("D3: rejects htm mismatch", async () => {
		const { app } = createApp();
		const { jwt } = await makeProof({ htm: "POST" });
		const res = await app.request("https://localhost/api/me", {
			method: "GET",
			headers: { DPoP: jwt },
		});
		expect(res.status).toBe(401);
		expect((await res.json()).detail).toMatch(/htm/);
	});

	it("D4: rejects htu mismatch", async () => {
		const { app } = createApp();
		const { jwt } = await makeProof({ url: "https://other.example/api/me" });
		const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
		expect(res.status).toBe(401);
		expect((await res.json()).detail).toMatch(/htu/);
	});

	it("D5: rejects iat too old", async () => {
		const { app } = createApp({ iatTolerance: 5 });
		const { jwt } = await makeProof({ iat: nowSeconds() - 600 });
		const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
		expect(res.status).toBe(401);
		expect((await res.json()).detail).toMatch(/iat/);
	});

	it("D6: replayed jti returns JTI_REPLAY", async () => {
		const { app } = createApp();
		const { jwt } = await makeProof();
		const r1 = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
		expect(r1.status).toBe(200);
		const r2 = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
		expect(r2.status).toBe(401);
		expect(((await r2.json()) as { code: string }).code).toBe("JTI_REPLAY");
	});

	it("D7: requireAccessToken rejects when Authorization missing", async () => {
		const { app } = createApp({ requireAccessToken: true });
		const { jwt } = await makeProof();
		const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
		expect(res.status).toBe(401);
		expect(((await res.json()) as { code: string }).code).toBe("MISSING_ACCESS_TOKEN");
	});

	it("D8: ath mismatch returns 401 ATH_MISMATCH", async () => {
		const { app } = createApp();
		const { jwt } = await makeProof({ ath: "wrong-hash" });
		const res = await app.request("https://localhost/api/me", {
			headers: { DPoP: jwt, Authorization: "DPoP some-token" },
		});
		expect(res.status).toBe(401);
		expect(((await res.json()) as { code: string }).code).toBe("ATH_MISMATCH");
	});

	it("D9: ath verifies when correct", async () => {
		const { app } = createApp();
		const token = "the-access-token-value";
		const ath = await computeAth(token);
		const { jwt } = await makeProof({ ath });
		const res = await app.request("https://localhost/api/me", {
			headers: { DPoP: jwt, Authorization: `DPoP ${token}` },
		});
		expect(res.status).toBe(200);
	});

	it("D10: rejects when access token presented but ath claim missing", async () => {
		const { app } = createApp();
		const { jwt } = await makeProof();
		const res = await app.request("https://localhost/api/me", {
			headers: { DPoP: jwt, Authorization: "DPoP some-token" },
		});
		expect(res.status).toBe(401);
		expect((await res.json()).detail).toMatch(/ath claim is required/);
	});

	it("algorithms whitelist rejects out-of-list alg", async () => {
		const { app } = createApp({ algorithms: ["RS256"] });
		const { jwt } = await makeProof(); // signed with ES256
		const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
		expect(res.status).toBe(401);
		expect((await res.json()).detail).toMatch(/allowed/);
	});

	it("getRequestUrl override is honored", async () => {
		const { app } = createApp({
			getRequestUrl: () => "https://api.public.example/api/me",
		});
		const { jwt } = await makeProof({ url: "https://api.public.example/api/me" });
		const res = await app.request("https://internal/api/me", { headers: { DPoP: jwt } });
		expect(res.status).toBe(200);
	});

	it("getAccessToken override is honored", async () => {
		const token = "custom-token";
		const ath = await computeAth(token);
		const { app } = createApp({ getAccessToken: () => token });
		const { jwt } = await makeProof({ ath });
		const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
		expect(res.status).toBe(200);
	});

	it("onError gets the ProblemDetail", async () => {
		const seen: string[] = [];
		const { app } = createApp({
			onError: (problem) => {
				seen.push(problem.code);
				return new Response("nope", { status: 418 });
			},
		});
		const res = await app.request("https://localhost/api/me");
		expect(res.status).toBe(418);
		expect(seen).toContain("INVALID_DPOP_PROOF");
	});

	it("ignores Authorization header that is not 'DPoP <token>'", async () => {
		const { app } = createApp();
		const { jwt } = await makeProof();
		const res = await app.request("https://localhost/api/me", {
			headers: { DPoP: jwt, Authorization: "Bearer something" },
		});
		expect(res.status).toBe(200);
	});

	it("requireAccessToken: empty DPoP token still treated as missing", async () => {
		const { app } = createApp({ requireAccessToken: true });
		const { jwt } = await makeProof();
		const res = await app.request("https://localhost/api/me", {
			headers: { DPoP: jwt, Authorization: "DPoP    " },
		});
		expect(res.status).toBe(401);
		expect(((await res.json()) as { code: string }).code).toBe("MISSING_ACCESS_TOKEN");
	});

	it("rejects bad signature", async () => {
		const { app } = createApp();
		const { jwt } = await makeProof();
		const parts = jwt.split(".");
		const bad = `${parts[0]}.${parts[1]}.${parts[2].slice(0, -2)}AA`;
		const res = await app.request("https://localhost/api/me", { headers: { DPoP: bad } });
		expect(res.status).toBe(401);
		expect((await res.json()).detail).toMatch(/signature/);
	});

	it("propagates unexpected errors from getRequestUrl", async () => {
		const app = new Hono();
		app.use(
			"/api/*",
			dpop({
				nonceStore: memoryNonceStore(),
				getRequestUrl: () => {
					throw new Error("boom");
				},
			}),
		);
		app.onError((err, c) => c.json({ error: (err as Error).message }, 500));
		app.get("/api/me", (c) => c.text("ok"));

		const { jwt } = await makeProof();
		const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
		expect(res.status).toBe(500);
	});

	it("propagates unexpected store errors", async () => {
		const failingStore: DPoPNonceStore = {
			async check() {
				throw new Error("store down");
			},
			async purge() {
				return 0;
			},
		};
		const app = new Hono();
		app.use("/api/*", dpop({ nonceStore: failingStore }));
		app.onError((err, c) => c.json({ error: (err as Error).message }, 500));
		app.get("/api/me", (c) => c.text("ok"));

		const { jwt } = await makeProof();
		const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
		expect(res.status).toBe(500);
	});

	it("rejects multiple DPoP headers (comma-joined)", async () => {
		const { app } = createApp();
		const { jwt } = await makeProof();
		const { jwt: jwt2 } = await makeProof();
		const res = await app.request("https://localhost/api/me", {
			headers: { DPoP: `${jwt}, ${jwt2}` },
		});
		expect(res.status).toBe(401);
		expect((await res.json()).detail).toMatch(/multiple DPoP headers/);
	});

	describe("nonceProvider (RFC 9449 §8)", () => {
		const constantProvider = (nonce: string): NonceProvider => ({
			issueNonce: () => nonce,
			isValid: (n) => n === nonce,
		});

		it("rejects proof without nonce when provider is set", async () => {
			const { app } = createApp({ nonceProvider: constantProvider("server-nonce-1") });
			const { jwt } = await makeProof();
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(401);
			const body = (await res.json()) as { code: string };
			expect(body.code).toBe("USE_NONCE");
			expect(res.headers.get("DPoP-Nonce")).toBe("server-nonce-1");
			expect(res.headers.get("WWW-Authenticate")).toContain("use_dpop_nonce");
			expect(res.headers.get("WWW-Authenticate")).toContain('nonce="server-nonce-1"');
		});

		it("rejects proof with invalid nonce and reissues", async () => {
			const { app } = createApp({ nonceProvider: constantProvider("server-nonce-2") });
			const { jwt } = await makeProof({ nonce: "wrong-nonce" });
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(401);
			expect(res.headers.get("DPoP-Nonce")).toBe("server-nonce-2");
		});

		it("accepts proof with valid nonce and echoes nonce on success", async () => {
			const { app } = createApp({ nonceProvider: constantProvider("server-nonce-3") });
			const { jwt } = await makeProof({ nonce: "server-nonce-3" });
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(200);
			expect(res.headers.get("DPoP-Nonce")).toBe("server-nonce-3");
		});
	});
});
