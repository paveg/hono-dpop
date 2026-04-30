import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { base64urlEncode } from "../src/base64url.js";
import { dpop } from "../src/middleware.js";
import { memoryNonceStore } from "../src/stores/memory.js";
import type { DPoPNonceStore, NonceProvider } from "../src/stores/types.js";
import type { DPoPOptions } from "../src/types.js";
import { computeAth } from "../src/verify.js";
import { exportPublicJwk, freshJti, generateKeyPair, nowSeconds, signProof } from "./helpers.js";

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

	it("rejects DPoP header exceeding maxProofSize", async () => {
		const { app } = createApp({ maxProofSize: 100 });
		const { jwt } = await makeProof();
		// Real proof is well over 100 bytes
		const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
		expect(res.status).toBe(401);
		expect((await res.json()).detail).toMatch(/exceeds 100 bytes/);
	});

	it("rejects access token exceeding maxAccessTokenSize", async () => {
		const { app } = createApp({ maxAccessTokenSize: 5 });
		const token = "way-too-long-token";
		const ath = await computeAth(token);
		const { jwt } = await makeProof({ ath });
		const res = await app.request("https://localhost/api/me", {
			headers: { DPoP: jwt, Authorization: `DPoP ${token}` },
		});
		expect(res.status).toBe(401);
		expect((await res.json()).detail).toMatch(/access token exceeds/);
	});

	it("clock option overrides Date.now for iat freshness", async () => {
		// Fixed-time clock 1000 seconds in the past
		const fixedSeconds = nowSeconds() - 1000;
		const fixedMs = fixedSeconds * 1000;
		const { app } = createApp({ clock: () => fixedMs, iatTolerance: 5 });
		const { jwt } = await makeProof({ iat: fixedSeconds });
		const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
		expect(res.status).toBe(200);
	});

	it("htuComparison trailing-slash-insensitive: matches across trailing slash", async () => {
		const app = new Hono();
		app.use(
			"/api/*",
			dpop({
				nonceStore: memoryNonceStore(),
				htuComparison: "trailing-slash-insensitive",
				// Force the request URL to have a trailing slash; the proof signs without.
				getRequestUrl: () => "https://api.example.com/api/me/",
			}),
		);
		app.get("/api/me", (c) => {
			const proof = c.get("dpop");
			return c.json({ htu: proof?.htu });
		});
		const { jwt } = await makeProof({ url: "https://api.example.com/api/me" });
		const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
		expect(res.status).toBe(200);
		const body = (await res.json()) as { htu: string };
		// Stored htu reflects the policy: trailing slash stripped.
		expect(body.htu).toBe("https://api.example.com/api/me");
	});

	it("htuComparison strict (default) rejects when only trailing slash differs", async () => {
		const app = new Hono();
		app.use(
			"/api/*",
			dpop({
				nonceStore: memoryNonceStore(),
				getRequestUrl: () => "https://api.example.com/api/me/",
			}),
		);
		app.get("/api/me", (c) => c.text("ok"));
		const { jwt } = await makeProof({ url: "https://api.example.com/api/me" });
		const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
		expect(res.status).toBe(401);
		expect((await res.json()).detail).toMatch(/htu/);
	});

	it("allowFutureIat: accepts iat in the future", async () => {
		const { app } = createApp({ allowFutureIat: true, iatTolerance: 60 });
		const { jwt } = await makeProof({ iat: nowSeconds() + 1000 });
		const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
		expect(res.status).toBe(200);
	});

	it("WWW-Authenticate includes algs hint on 401", async () => {
		const { app } = createApp({ algorithms: ["ES256", "ES384"] });
		const res = await app.request("https://localhost/api/me");
		expect(res.status).toBe(401);
		expect(res.headers.get("WWW-Authenticate")).toContain('algs="ES256 ES384"');
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

	describe("Authorization scheme case-insensitivity (RFC 7235)", () => {
		it("accepts 'dpop <token>' (lowercase scheme)", async () => {
			const { app } = createApp();
			const token = "the-access-token-value";
			const ath = await computeAth(token);
			const { jwt } = await makeProof({ ath });
			const res = await app.request("https://localhost/api/me", {
				headers: { DPoP: jwt, Authorization: `dpop ${token}` },
			});
			expect(res.status).toBe(200);
		});

		it("accepts 'DPOP <token>' (uppercase scheme)", async () => {
			const { app } = createApp();
			const token = "the-access-token-value";
			const ath = await computeAth(token);
			const { jwt } = await makeProof({ ath });
			const res = await app.request("https://localhost/api/me", {
				headers: { DPoP: jwt, Authorization: `DPOP ${token}` },
			});
			expect(res.status).toBe(200);
		});

		it("accepts 'Dpop <token>' (mixed case)", async () => {
			const { app } = createApp();
			const token = "the-access-token-value";
			const ath = await computeAth(token);
			const { jwt } = await makeProof({ ath });
			const res = await app.request("https://localhost/api/me", {
				headers: { DPoP: jwt, Authorization: `Dpop ${token}` },
			});
			expect(res.status).toBe(200);
		});

		it("still ignores 'Bearer <token>'", async () => {
			const { app } = createApp();
			// No ath claim; if Bearer were treated as a DPoP token, the ath check would fail.
			const { jwt } = await makeProof();
			const res = await app.request("https://localhost/api/me", {
				headers: { DPoP: jwt, Authorization: "Bearer some-token" },
			});
			expect(res.status).toBe(200);
		});
	});

	describe("access-token size check ordering (DoS shield)", () => {
		it("rejects oversized access token before signature verification", async () => {
			const { app } = createApp({ maxAccessTokenSize: 10 });
			// Intentionally bad signature: tamper with the last byte. If the size
			// check ran AFTER sig verification, we'd get an INVALID_DPOP_PROOF
			// with a "signature" detail. Because the size check runs first, we
			// expect the size-rejection detail instead.
			const { jwt } = await makeProof();
			const parts = jwt.split(".");
			const bad = `${parts[0]}.${parts[1]}.${parts[2].slice(0, -2)}AA`;
			const huge = "x".repeat(50_000);
			const res = await app.request("https://localhost/api/me", {
				headers: { DPoP: bad, Authorization: `DPoP ${huge}` },
			});
			expect(res.status).toBe(401);
			const body = (await res.json()) as { code: string; detail: string };
			expect(body.code).toBe("INVALID_DPOP_PROOF");
			expect(body.detail).toMatch(/access token exceeds/);
			expect(body.detail).not.toMatch(/signature/);
		});

		it("still rejects invalid signature normally when access token is within size", async () => {
			const { app } = createApp();
			const { jwt } = await makeProof();
			const parts = jwt.split(".");
			const bad = `${parts[0]}.${parts[1]}.${parts[2].slice(0, -2)}AA`;
			const res = await app.request("https://localhost/api/me", {
				headers: { DPoP: bad, Authorization: "DPoP small-token" },
			});
			expect(res.status).toBe(401);
			expect((await res.json()).detail).toMatch(/signature/);
		});
	});

	describe("nonceProvider issueNonce memoization", () => {
		it("invokes nonceProvider.issueNonce at most once on success", async () => {
			let calls = 0;
			const provider: NonceProvider = {
				issueNonce: () => {
					calls++;
					return "server-nonce-memo";
				},
				isValid: (n) => n === "server-nonce-memo",
			};
			const { app } = createApp({ nonceProvider: provider });
			const { jwt } = await makeProof({ nonce: "server-nonce-memo" });
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(200);
			expect(res.headers.get("DPoP-Nonce")).toBe("server-nonce-memo");
			expect(calls).toBeLessThanOrEqual(1);
		});

		it("invokes nonceProvider.issueNonce at most once on use_nonce challenge", async () => {
			let calls = 0;
			const provider: NonceProvider = {
				issueNonce: () => {
					calls++;
					return "server-nonce-challenge";
				},
				isValid: () => false,
			};
			const { app } = createApp({ nonceProvider: provider });
			// No nonce in proof → use_dpop_nonce path.
			const { jwt } = await makeProof();
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(401);
			expect(((await res.json()) as { code: string }).code).toBe("USE_NONCE");
			expect(res.headers.get("DPoP-Nonce")).toBe("server-nonce-challenge");
			expect(calls).toBeLessThanOrEqual(1);
		});
	});

	it("onError receives the algs-enriched problem", async () => {
		let captured: { wwwAuthExtras?: Record<string, string> } | undefined;
		const { app } = createApp({
			algorithms: ["ES256"],
			onError: (problem) => {
				captured = problem;
				return new Response("nope", { status: 401 });
			},
		});
		await app.request("https://localhost/api/me");
		expect(captured?.wwwAuthExtras?.algs).toBe("ES256");
	});

	describe("boundary values", () => {
		// --- A. size boundaries (maxProofSize / maxAccessTokenSize) ---

		it("A1: accepts proof header at exactly maxProofSize bytes", async () => {
			const { jwt } = await makeProof();
			// JWT is ASCII (base64url + dots) so byte length == string length.
			const { app } = createApp({ maxProofSize: jwt.length });
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(200);
		});

		it("A2: rejects proof header at maxProofSize + 1 bytes", async () => {
			const { jwt } = await makeProof();
			const { app } = createApp({ maxProofSize: jwt.length - 1 });
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(401);
			expect((await res.json()).detail).toMatch(new RegExp(`exceeds ${jwt.length - 1} bytes`));
		});

		it("A3: accepts access token at exactly maxAccessTokenSize bytes", async () => {
			const token = "exact-size-token"; // 16 bytes ASCII
			const ath = await computeAth(token);
			const { jwt } = await makeProof({ ath });
			const { app } = createApp({ maxAccessTokenSize: token.length });
			const res = await app.request("https://localhost/api/me", {
				headers: { DPoP: jwt, Authorization: `DPoP ${token}` },
			});
			expect(res.status).toBe(200);
		});

		it("A4: rejects access token at maxAccessTokenSize + 1 bytes", async () => {
			const token = "exact-size-token";
			const ath = await computeAth(token);
			const { jwt } = await makeProof({ ath });
			const { app } = createApp({ maxAccessTokenSize: token.length - 1 });
			const res = await app.request("https://localhost/api/me", {
				headers: { DPoP: jwt, Authorization: `DPoP ${token}` },
			});
			expect(res.status).toBe(401);
			expect((await res.json()).detail).toMatch(/access token exceeds/);
		});

		it("A5: maxProofSize: 0 rejects any non-empty proof", async () => {
			const { jwt } = await makeProof();
			const { app } = createApp({ maxProofSize: 0 });
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(401);
			expect((await res.json()).detail).toMatch(/exceeds 0 bytes/);
		});

		// --- B. Authorization scheme parsing (resolveAccessToken) ---

		it("B1: empty Authorization header is treated as no token (ignored)", async () => {
			const { app } = createApp();
			const { jwt } = await makeProof();
			// Empty Authorization → falsy → undefined → ath check skipped → 200.
			const res = await app.request("https://localhost/api/me", {
				headers: { DPoP: jwt, Authorization: "" },
			});
			expect(res.status).toBe(200);
		});

		it("B2: 'DPoP' (no space, no token) is treated as missing", async () => {
			const { app } = createApp({ requireAccessToken: true });
			const { jwt } = await makeProof();
			const res = await app.request("https://localhost/api/me", {
				headers: { DPoP: jwt, Authorization: "DPoP" },
			});
			expect(res.status).toBe(401);
			expect(((await res.json()) as { code: string }).code).toBe("MISSING_ACCESS_TOKEN");
		});

		it("B3: leading-space ' DPoP token' is normalized by HTTP transport (RFC 7230 OWS strip)", async () => {
			// Characterization: HTTP libraries strip optional whitespace around
			// header field-values per RFC 7230 §3.2.4 before the middleware sees them.
			// So the leading space disappears, the scheme parses cleanly as "DPoP",
			// the access token "token" is extracted, and the request advances past
			// the missing-access-token check. The proof has no ath claim, so the
			// next failure is INVALID_DPOP_PROOF "ath claim is required".
			const { app } = createApp({ requireAccessToken: true });
			const { jwt } = await makeProof();
			const res = await app.request("https://localhost/api/me", {
				headers: { DPoP: jwt, Authorization: " DPoP token" },
			});
			expect(res.status).toBe(401);
			const body = (await res.json()) as { code: string; detail: string };
			expect(body.code).toBe("INVALID_DPOP_PROOF");
			expect(body.detail).toMatch(/ath claim is required/);
		});

		it("B4: TAB-separated 'DPoP\\ttoken' is not recognized (only space splits)", async () => {
			const { app } = createApp({ requireAccessToken: true });
			const { jwt } = await makeProof();
			// indexOf(" ") returns -1; tab is not space → undefined.
			const res = await app.request("https://localhost/api/me", {
				headers: { DPoP: jwt, Authorization: "DPoP\ttoken" },
			});
			expect(res.status).toBe(401);
			expect(((await res.json()) as { code: string }).code).toBe("MISSING_ACCESS_TOKEN");
		});

		it("B5: 'Bearer xyz' is ignored (non-DPoP scheme)", async () => {
			const { app } = createApp({ requireAccessToken: true });
			const { jwt } = await makeProof();
			const res = await app.request("https://localhost/api/me", {
				headers: { DPoP: jwt, Authorization: "Bearer xyz" },
			});
			expect(res.status).toBe(401);
			expect(((await res.json()) as { code: string }).code).toBe("MISSING_ACCESS_TOKEN");
		});

		// --- C. Custom getAccessToken edge cases ---

		it("C1: getAccessToken returning undefined + requireAccessToken → 401", async () => {
			const { app } = createApp({
				getAccessToken: () => undefined,
				requireAccessToken: true,
			});
			const { jwt } = await makeProof();
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(401);
			expect(((await res.json()) as { code: string }).code).toBe("MISSING_ACCESS_TOKEN");
		});

		it("C2: async getAccessToken returning empty string + requireAccessToken → 401", async () => {
			const { app } = createApp({
				getAccessToken: async () => "",
				requireAccessToken: true,
			});
			const { jwt } = await makeProof();
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			// Empty string is falsy → !accessToken triggers MISSING_ACCESS_TOKEN.
			expect(res.status).toBe(401);
			expect(((await res.json()) as { code: string }).code).toBe("MISSING_ACCESS_TOKEN");
		});

		it("C3: getAccessToken throwing propagates (no try/catch around resolution)", async () => {
			const app = new Hono();
			app.use(
				"/api/*",
				dpop({
					nonceStore: memoryNonceStore(),
					getAccessToken: () => {
						throw new Error("boom-token");
					},
				}),
			);
			app.onError((err, c) => c.json({ error: (err as Error).message }, 500));
			app.get("/api/me", (c) => c.text("ok"));
			const { jwt } = await makeProof();
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(500);
			expect(((await res.json()) as { error: string }).error).toBe("boom-token");
		});

		it("C4: async getAccessToken returning a valid token verifies ath normally", async () => {
			const token = "valid-async-token";
			const ath = await computeAth(token);
			const { app } = createApp({ getAccessToken: async () => token });
			const { jwt } = await makeProof({ ath });
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(200);
		});

		// --- D. Nonce flow boundary: non-string nonce fails parse, NOT use_dpop_nonce ---
		// parseProof rejects non-string `nonce` BEFORE the nonceProvider check runs,
		// so these all surface as INVALID_DPOP_PROOF (characterization of current behavior).

		const nonceProvider: NonceProvider = {
			issueNonce: () => "server-nonce-X",
			isValid: (n) => n === "server-nonce-X",
		};

		async function signWithRawNonce(rawNonce: unknown): Promise<string> {
			const keyPair = await generateKeyPair("ES256");
			return signProof({
				alg: "ES256",
				keyPair,
				payload: {
					jti: freshJti(),
					htm: "GET",
					htu: "https://localhost/api/me",
					iat: nowSeconds(),
					nonce: rawNonce as string | undefined,
				},
			});
		}

		it("D-bnd-1: nonce as number (123) fails parseProof as INVALID_DPOP_PROOF", async () => {
			const { app } = createApp({ nonceProvider });
			const jwt = await signWithRawNonce(123);
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(401);
			const body = (await res.json()) as { code: string; detail: string };
			expect(body.code).toBe("INVALID_DPOP_PROOF");
			expect(body.detail).toMatch(/nonce must be a string/);
		});

		it("D-bnd-2: nonce as null fails parseProof as INVALID_DPOP_PROOF", async () => {
			const { app } = createApp({ nonceProvider });
			const jwt = await signWithRawNonce(null);
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(401);
			const body = (await res.json()) as { code: string; detail: string };
			expect(body.code).toBe("INVALID_DPOP_PROOF");
			expect(body.detail).toMatch(/nonce must be a string/);
		});

		it("D-bnd-3: nonce as object ({}) fails parseProof as INVALID_DPOP_PROOF", async () => {
			const { app } = createApp({ nonceProvider });
			const jwt = await signWithRawNonce({});
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(401);
			const body = (await res.json()) as { code: string; detail: string };
			expect(body.code).toBe("INVALID_DPOP_PROOF");
			expect(body.detail).toMatch(/nonce must be a string/);
		});

		// --- E. htu fine-grained matching (URL normalization semantics) ---

		it("E1: query parameter difference does not affect htu match (search stripped)", async () => {
			const { app } = createApp();
			const { jwt } = await makeProof({ url: "https://localhost/api/me?a=1" });
			const res = await app.request("https://localhost/api/me?b=2", { headers: { DPoP: jwt } });
			expect(res.status).toBe(200);
		});

		it("E2: port mismatch (8080 vs 8081) is rejected", async () => {
			const app = new Hono();
			app.use(
				"/api/*",
				dpop({
					nonceStore: memoryNonceStore(),
					getRequestUrl: () => "https://localhost:8081/api/me",
				}),
			);
			app.get("/api/me", (c) => c.text("ok"));
			const { jwt } = await makeProof({ url: "https://localhost:8080/api/me" });
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(401);
			expect((await res.json()).detail).toMatch(/htu/);
		});

		it("E3: scheme case difference is normalized (HTTPS:// matches https://)", async () => {
			const app = new Hono();
			app.use(
				"/api/*",
				dpop({
					nonceStore: memoryNonceStore(),
					getRequestUrl: () => "HTTPS://localhost/api/me",
				}),
			);
			app.get("/api/me", (c) => c.text("ok"));
			const { jwt } = await makeProof({ url: "https://localhost/api/me" });
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(200);
		});

		it("E4: fragment difference does not affect htu match (hash stripped)", async () => {
			const app = new Hono();
			app.use(
				"/api/*",
				dpop({
					nonceStore: memoryNonceStore(),
					getRequestUrl: () => "https://localhost/api/me#section",
				}),
			);
			app.get("/api/me", (c) => c.text("ok"));
			const { jwt } = await makeProof({ url: "https://localhost/api/me" });
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(200);
		});

		// --- F. clock boundary ---

		it("F1: clock returning epoch 0 + iat 0 + tolerance 60 is accepted", async () => {
			const { app } = createApp({ clock: () => 0, iatTolerance: 60 });
			// Bypass makeProof helper's nowSeconds default by passing iat: 0 explicitly.
			const { jwt } = await makeProof({ iat: 0 });
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(200);
		});

		// --- G. requireAccessToken integration paths ---

		it("G1: requireAccessToken: true happy path with Authorization + matching ath → 200", async () => {
			const token = "happy-path-token";
			const ath = await computeAth(token);
			const { app } = createApp({ requireAccessToken: true });
			const { jwt } = await makeProof({ ath });
			const res = await app.request("https://localhost/api/me", {
				headers: { DPoP: jwt, Authorization: `DPoP ${token}` },
			});
			expect(res.status).toBe(200);
		});

		it("G2: requireAccessToken: false + no Authorization header → 200 (ath skipped)", async () => {
			const { app } = createApp({ requireAccessToken: false });
			const { jwt } = await makeProof();
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(200);
		});
	});

	describe("input boundary hardening (PR-C)", () => {
		// L-2: a whitespace-only token after the DPoP scheme must be normalized to
		// "no token" so that the ath path is never entered with an empty string.
		// Sanity check: the WHATWG Headers API trims trailing whitespace from
		// header values, so "DPoP    " arrives at the middleware as "DPoP" with
		// no space, which `resolveAccessToken` treats as "no DPoP-scheme token
		// present" and returns undefined. This documents the platform behavior
		// the middleware is relying on.
		it('treats Authorization: "DPoP    " (trimmed by Headers API) as missing access token', async () => {
			const { app } = createApp({ requireAccessToken: true });
			const { jwt } = await makeProof();
			const res = await app.request("https://localhost/api/me", {
				headers: { DPoP: jwt, Authorization: "DPoP    " },
			});
			expect(res.status).toBe(401);
			expect(((await res.json()) as { code: string }).code).toBe("MISSING_ACCESS_TOKEN");
		});

		// L-3: removing the short-circuit eliminates a (small) timing oracle that
		// distinguishes "no nonce claim" from "invalid nonce claim".
		it("calls nonceProvider.isValid even when nonce claim is missing", async () => {
			const calls: Array<string> = [];
			const provider: NonceProvider = {
				issueNonce: () => "server-nonce-timing",
				isValid: (n) => {
					calls.push(n);
					return n === "server-nonce-timing";
				},
			};
			const { app } = createApp({ nonceProvider: provider });
			// Proof has no nonce claim. Pre-fix: isValid is short-circuited.
			const { jwt } = await makeProof();
			const res = await app.request("https://localhost/api/me", { headers: { DPoP: jwt } });
			expect(res.status).toBe(401);
			expect(((await res.json()) as { code: string }).code).toBe("USE_NONCE");
			expect(calls.length).toBe(1);
			// Implementation calls isValid with empty string when the claim is missing.
			expect(calls[0]).toBe("");
		});

		// L-4: factory must reject unsupported algorithms synchronously, before any
		// request is ever served. A TypeScript escape hatch (`as any`) must not be
		// silently tolerated until the proof's own alg check at request time.
		it('dpop({ algorithms: ["EvilAlg"] }) throws at factory time', () => {
			expect(() =>
				dpop({
					nonceStore: memoryNonceStore(),
					algorithms: ["EvilAlg" as unknown as never],
				}),
			).toThrow(/EvilAlg/);
		});

		it('dpop({ algorithms: ["ES256"] }) does not throw (regression)', () => {
			expect(() =>
				dpop({
					nonceStore: memoryNonceStore(),
					algorithms: ["ES256"],
				}),
			).not.toThrow();
		});

		// T-1b: extra payload claims (exp, iss, sub, custom) on a valid proof are
		// accepted unchanged. RFC 9449 §4.2 lists required claims but does not
		// forbid extra ones; lock current tolerant behavior in.
		it("accepts proof with extra payload claims (exp, iss, sub, custom)", async () => {
			const keyPair = await generateKeyPair("ES256");
			const url = "https://localhost/api/me";
			const jti = freshJti();
			const iat = nowSeconds();
			// Hand-roll the JWT so we can include claims that ProofPayload doesn't model.
			const headerObj = {
				typ: "dpop+jwt",
				alg: "ES256" as const,
				jwk: await exportPublicJwk(keyPair.publicKey),
			};
			const payloadObj = {
				jti,
				htm: "GET",
				htu: url,
				iat,
				exp: iat + 300,
				iss: "https://issuer.example",
				sub: "user-123",
				custom: { nested: true, list: [1, 2, 3] },
			};
			const headerB64 = base64urlEncode(JSON.stringify(headerObj));
			const payloadB64 = base64urlEncode(JSON.stringify(payloadObj));
			const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
			const sig = await crypto.subtle.sign(
				{ name: "ECDSA", hash: "SHA-256" },
				keyPair.privateKey,
				signingInput,
			);
			const jwt = `${headerB64}.${payloadB64}.${base64urlEncode(new Uint8Array(sig))}`;
			const { app } = createApp();
			const res = await app.request(url, { headers: { DPoP: jwt } });
			expect(res.status).toBe(200);
			const body = (await res.json()) as { jkt?: string; jti?: string };
			expect(body.jti).toBe(jti);
		});
	});
});
