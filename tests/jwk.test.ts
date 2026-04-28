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
