import { describe, expect, it } from "vitest";
import {
	SUPPORTED_ALGORITHMS,
	assertAlgMatchesJwk,
	assertPublicJwk,
	importPublicJwk,
	isSupportedAlgorithm,
	jwkThumbprint,
	verifyParamsFor,
} from "../src/jwk.js";
import { exportPublicJwk, generateKeyPair } from "./helpers.js";

describe("isSupportedAlgorithm", () => {
	it("recognizes all supported algorithms", () => {
		for (const a of SUPPORTED_ALGORITHMS) expect(isSupportedAlgorithm(a)).toBe(true);
	});

	it("rejects insecure algorithms", () => {
		expect(isSupportedAlgorithm("none")).toBe(false);
		expect(isSupportedAlgorithm("HS256")).toBe(false);
		expect(isSupportedAlgorithm("HS512")).toBe(false);
	});
});

describe("assertPublicJwk", () => {
	it("rejects null and non-object", () => {
		expect(() => assertPublicJwk(null)).toThrow(TypeError);
		expect(() => assertPublicJwk("string")).toThrow(TypeError);
		expect(() => assertPublicJwk(undefined)).toThrow(TypeError);
	});

	it("rejects private key fields", () => {
		const ec = { kty: "EC", crv: "P-256", x: "x", y: "y", d: "private" };
		expect(() => assertPublicJwk(ec)).toThrow(/private field "d"/);

		const rsa = { kty: "RSA", n: "n", e: "e", p: "private" };
		expect(() => assertPublicJwk(rsa)).toThrow(/private field "p"/);
	});

	it("EC requires supported crv and x/y", () => {
		expect(() => assertPublicJwk({ kty: "EC", crv: "secp256k1", x: "x", y: "y" })).toThrow(
			/unsupported crv/,
		);
		expect(() => assertPublicJwk({ kty: "EC", crv: "P-256" })).toThrow(/x and y/);
		expect(() => assertPublicJwk({ kty: "EC", crv: "P-256", x: "x", y: "y" })).not.toThrow();
	});

	it("RSA requires n and e", () => {
		expect(() => assertPublicJwk({ kty: "RSA" })).toThrow(/n and e/);
		expect(() => assertPublicJwk({ kty: "RSA", n: "n", e: "e" })).not.toThrow();
	});

	it("OKP requires Ed25519 crv and x", () => {
		expect(() => assertPublicJwk({ kty: "OKP", crv: "X25519", x: "x" })).toThrow(
			/only supports Ed25519/,
		);
		expect(() => assertPublicJwk({ kty: "OKP", crv: "Ed25519" })).toThrow(/requires x/);
		expect(() => assertPublicJwk({ kty: "OKP", crv: "Ed25519", x: "x" })).not.toThrow();
	});

	it("rejects unknown kty", () => {
		expect(() => assertPublicJwk({ kty: "Unknown" })).toThrow(/unsupported kty/);
		expect(() => assertPublicJwk({})).toThrow(/unsupported kty/);
	});
});

describe("assertAlgMatchesJwk", () => {
	it("ES256 requires P-256 EC jwk", () => {
		expect(() => assertAlgMatchesJwk("ES256", { kty: "RSA", n: "n", e: "e" })).toThrow();
		expect(() => assertAlgMatchesJwk("ES256", { kty: "EC", crv: "P-384", x: "x", y: "y" })).toThrow(
			/requires crv P-256/,
		);
		expect(() =>
			assertAlgMatchesJwk("ES256", { kty: "EC", crv: "P-256", x: "x", y: "y" }),
		).not.toThrow();
	});

	it("ES384 requires P-384", () => {
		expect(() => assertAlgMatchesJwk("ES384", { kty: "EC", crv: "P-256", x: "x", y: "y" })).toThrow(
			/requires crv P-384/,
		);
	});

	it("ES512 requires P-521", () => {
		expect(() => assertAlgMatchesJwk("ES512", { kty: "EC", crv: "P-256", x: "x", y: "y" })).toThrow(
			/requires crv P-521/,
		);
	});

	it("RS* and PS* require RSA", () => {
		const ec = { kty: "EC" as const, crv: "P-256" as const, x: "x", y: "y" };
		expect(() => assertAlgMatchesJwk("RS256", ec)).toThrow(/requires RSA/);
		expect(() => assertAlgMatchesJwk("PS256", ec)).toThrow(/requires RSA/);
		const rsa = { kty: "RSA" as const, n: "n", e: "e" };
		expect(() => assertAlgMatchesJwk("RS512", rsa)).not.toThrow();
		expect(() => assertAlgMatchesJwk("PS512", rsa)).not.toThrow();
	});

	it("EdDSA requires OKP", () => {
		expect(() => assertAlgMatchesJwk("EdDSA", { kty: "RSA", n: "n", e: "e" })).toThrow(
			/requires OKP/,
		);
		expect(() =>
			assertAlgMatchesJwk("EdDSA", { kty: "OKP", crv: "Ed25519", x: "x" }),
		).not.toThrow();
	});
});

describe("jwkThumbprint", () => {
	it("matches RFC 7638 §3.1 example", async () => {
		const jwk = {
			kty: "RSA",
			n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			e: "AQAB",
		} as const;
		expect(await jwkThumbprint(jwk)).toBe("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
	});

	it("EC P-256 thumbprint is deterministic", async () => {
		const { publicKey } = await generateKeyPair("ES256");
		const jwk = await exportPublicJwk(publicKey);
		const a = await jwkThumbprint(jwk);
		const b = await jwkThumbprint(jwk);
		expect(a).toBe(b);
		expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
		expect(a).toHaveLength(43);
	});

	it("OKP Ed25519 thumbprint format", async () => {
		const { publicKey } = await generateKeyPair("EdDSA");
		const jwk = await exportPublicJwk(publicKey);
		expect(await jwkThumbprint(jwk)).toMatch(/^[A-Za-z0-9_-]{43}$/);
	});
});

describe("importPublicJwk + verifyParamsFor", () => {
	it.each(SUPPORTED_ALGORITHMS)("imports a generated %s public key", async (alg) => {
		const { publicKey } = await generateKeyPair(alg);
		const jwk = await exportPublicJwk(publicKey);
		const key = await importPublicJwk(jwk, alg);
		expect(key.type).toBe("public");
		expect(verifyParamsFor(alg)).toBeDefined();
	});
});

describe("assertPublicJwk — kty case sensitivity (boundary)", () => {
	it.each(["ec", "Ec", "EC ", "", "oct"])("rejects kty %j", (kty) => {
		expect(() => assertPublicJwk({ kty, crv: "P-256", x: "x", y: "y" })).toThrow(/unsupported kty/);
	});
});

describe("assertPublicJwk — missing required members per kty (boundary)", () => {
	it("EC: rejects missing crv", () => {
		expect(() => assertPublicJwk({ kty: "EC", x: "x", y: "y" })).toThrow(/unsupported crv/);
	});
	it("EC: rejects empty crv", () => {
		expect(() => assertPublicJwk({ kty: "EC", crv: "", x: "x", y: "y" })).toThrow(
			/unsupported crv/,
		);
	});
	it("EC: rejects missing x", () => {
		expect(() => assertPublicJwk({ kty: "EC", crv: "P-256", y: "y" })).toThrow(/x and y/);
	});
	it("EC: rejects missing y", () => {
		expect(() => assertPublicJwk({ kty: "EC", crv: "P-256", x: "x" })).toThrow(/x and y/);
	});
	it("RSA: rejects missing n", () => {
		expect(() => assertPublicJwk({ kty: "RSA", e: "AQAB" })).toThrow(/n and e/);
	});
	it("RSA: rejects missing e", () => {
		expect(() => assertPublicJwk({ kty: "RSA", n: "abc" })).toThrow(/n and e/);
	});
	it("OKP: rejects missing crv", () => {
		expect(() => assertPublicJwk({ kty: "OKP", x: "x" })).toThrow(/only supports Ed25519/);
	});
	it("OKP: rejects missing x", () => {
		expect(() => assertPublicJwk({ kty: "OKP", crv: "Ed25519" })).toThrow(/requires x/);
	});
});

describe("assertPublicJwk — private key detection (boundary)", () => {
	it("EC with d field is rejected", () => {
		expect(() => assertPublicJwk({ kty: "EC", crv: "P-256", x: "x", y: "y", d: "secret" })).toThrow(
			/private field "d"/,
		);
	});
	it("RSA with d field is rejected", () => {
		expect(() => assertPublicJwk({ kty: "RSA", n: "n", e: "AQAB", d: "secret" })).toThrow(
			/private field "d"/,
		);
	});
	it("OKP with d field is rejected", () => {
		expect(() => assertPublicJwk({ kty: "OKP", crv: "Ed25519", x: "x", d: "secret" })).toThrow(
			/private field "d"/,
		);
	});
	it.each(["p", "q", "dp", "dq", "qi", "oth", "k"])("RSA with %s field is rejected", (field) => {
		expect(() => assertPublicJwk({ kty: "RSA", n: "n", e: "AQAB", [field]: "x" })).toThrow(
			new RegExp(`private field "${field}"`),
		);
	});
});

describe("assertAlgMatchesJwk — exhaustive EC crv mismatch (boundary)", () => {
	const ec = (crv: "P-256" | "P-384" | "P-521") => ({ kty: "EC", crv, x: "x", y: "y" }) as const;
	const cases = [
		{ alg: "ES256", crv: "P-384", expected: /requires crv P-256/ },
		{ alg: "ES256", crv: "P-521", expected: /requires crv P-256/ },
		{ alg: "ES384", crv: "P-256", expected: /requires crv P-384/ },
		{ alg: "ES384", crv: "P-521", expected: /requires crv P-384/ },
		{ alg: "ES512", crv: "P-256", expected: /requires crv P-521/ },
		{ alg: "ES512", crv: "P-384", expected: /requires crv P-521/ },
	] as const;
	it.each(cases)("rejects ($alg, $crv)", ({ alg, crv, expected }) => {
		expect(() => assertAlgMatchesJwk(alg, ec(crv))).toThrow(expected);
	});

	const happy = [
		{ alg: "ES256", crv: "P-256" },
		{ alg: "ES384", crv: "P-384" },
		{ alg: "ES512", crv: "P-521" },
	] as const;
	it.each(happy)("accepts ($alg, $crv)", ({ alg, crv }) => {
		expect(() => assertAlgMatchesJwk(alg, ec(crv))).not.toThrow();
	});
});

describe("importPublicJwk — WebCrypto rejection (boundary)", () => {
	// Note: Node's WebCrypto silently accepts some malformed RSA n (e.g. base64url
	// chars that decode to a too-short modulus), so we exercise EC where the
	// runtime reliably rejects truncated curve points.
	it("rejects EC jwk with truncated coordinates", async () => {
		await expect(
			importPublicJwk({ kty: "EC", crv: "P-256", x: "AA", y: "AA" }, "ES256"),
		).rejects.toThrow();
	});
	it("rejects EC jwk with mismatched curve material for ES384", async () => {
		await expect(
			importPublicJwk({ kty: "EC", crv: "P-384", x: "AA", y: "AA" }, "ES384"),
		).rejects.toThrow();
	});
});

describe("verifyParamsFor — exact value assertions (boundary)", () => {
	it("PS256 -> RSA-PSS saltLength 32", () => {
		expect(verifyParamsFor("PS256")).toEqual({ name: "RSA-PSS", saltLength: 32 });
	});
	it("PS384 -> RSA-PSS saltLength 48", () => {
		expect(verifyParamsFor("PS384")).toEqual({ name: "RSA-PSS", saltLength: 48 });
	});
	it("PS512 -> RSA-PSS saltLength 64", () => {
		expect(verifyParamsFor("PS512")).toEqual({ name: "RSA-PSS", saltLength: 64 });
	});
	it("ES256 -> ECDSA SHA-256", () => {
		expect(verifyParamsFor("ES256")).toEqual({ name: "ECDSA", hash: "SHA-256" });
	});
	it("ES384 -> ECDSA SHA-384", () => {
		expect(verifyParamsFor("ES384")).toEqual({ name: "ECDSA", hash: "SHA-384" });
	});
	it("ES512 -> ECDSA SHA-512", () => {
		expect(verifyParamsFor("ES512")).toEqual({ name: "ECDSA", hash: "SHA-512" });
	});
	it.each(["RS256", "RS384", "RS512"] as const)("%s -> RSASSA-PKCS1-v1_5", (alg) => {
		expect(verifyParamsFor(alg)).toEqual({ name: "RSASSA-PKCS1-v1_5" });
	});
	it("EdDSA -> Ed25519", () => {
		expect(verifyParamsFor("EdDSA")).toEqual({ name: "Ed25519" });
	});
});

describe("jwkThumbprint — RFC 7638 robustness (boundary)", () => {
	it("is invariant under JWK member ordering", async () => {
		const { publicKey } = await generateKeyPair("ES256");
		const jwk = await exportPublicJwk(publicKey);
		const reordered = { y: jwk.y, x: jwk.x, crv: jwk.crv, kty: jwk.kty } as typeof jwk;
		expect(await jwkThumbprint(reordered)).toBe(await jwkThumbprint(jwk));
	});

	it("ignores non-canonical members (alg, kid, use)", async () => {
		const { publicKey } = await generateKeyPair("ES256");
		const jwk = await exportPublicJwk(publicKey);
		const withExtras = { ...jwk, alg: "ES256", kid: "key-1", use: "sig" };
		expect(await jwkThumbprint(withExtras)).toBe(await jwkThumbprint(jwk));
	});

	it("ignores extras for RSA thumbprint (RFC 7638 §3.1 vector)", async () => {
		const jwk = {
			kty: "RSA",
			n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			e: "AQAB",
			alg: "RS256",
			kid: "2011-04-29",
			use: "sig",
		} as const;
		expect(await jwkThumbprint(jwk)).toBe("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
	});
});
