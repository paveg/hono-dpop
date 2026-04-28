import { describe, expect, it } from "vitest";
import { base64urlEncode } from "../src/base64url.js";
import { DPoPProofError } from "../src/errors.js";
import { SUPPORTED_ALGORITHMS } from "../src/jwk.js";
import {
	computeAth,
	normalizeHtu,
	parseProof,
	timingSafeEqual,
	verifyProofClaims,
	verifyProofSignature,
} from "../src/verify.js";
import { freshJti, generateKeyPair, nowSeconds, signProof } from "./helpers.js";

const ALL = new Set(SUPPORTED_ALGORITHMS);
const ES_ONLY = new Set<(typeof SUPPORTED_ALGORITHMS)[number]>(["ES256"]);

const GOOD_HEADER = base64urlEncode(
	JSON.stringify({
		typ: "dpop+jwt",
		alg: "ES256",
		jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
	}),
);

async function makeValidProof(
	opts: {
		now?: number;
		htm?: string;
		htu?: string;
		ath?: string;
		jti?: string;
	} = {},
) {
	const keyPair = await generateKeyPair("ES256");
	const jwt = await signProof({
		alg: "ES256",
		keyPair,
		payload: {
			jti: opts.jti ?? freshJti(),
			htm: opts.htm ?? "POST",
			htu: opts.htu ?? "https://api.example.com/resource",
			iat: opts.now ?? nowSeconds(),
			ath: opts.ath,
		},
	});
	return { jwt, keyPair };
}

describe("parseProof — structural failures", () => {
	it("rejects empty string", () => {
		expect(() => parseProof("", ALL)).toThrow(DPoPProofError);
	});

	it("rejects non-three-part JWT", () => {
		expect(() => parseProof("a.b", ALL)).toThrow(/not a JWT/);
		expect(() => parseProof("a.b.c.d", ALL)).toThrow(/not a JWT/);
	});

	it("rejects non-JSON header", () => {
		const jwt = `${base64urlEncode("not-json")}.${base64urlEncode("{}")}.x`;
		expect(() => parseProof(jwt, ALL)).toThrow(/header section is not valid JSON/);
	});

	it("rejects non-JSON payload", () => {
		const jwt = `${GOOD_HEADER}.${base64urlEncode("not-json")}.x`;
		expect(() => parseProof(jwt, ALL)).toThrow(/payload section is not valid JSON/);
	});

	it("rejects non-object header/payload", () => {
		expect(() => parseProof(`${base64urlEncode("[1,2]")}.${base64urlEncode("{}")}.x`, ALL)).toThrow(
			/header section is not a JSON object/,
		);
		expect(() => parseProof(`${GOOD_HEADER}.${base64urlEncode("[1,2]")}.x`, ALL)).toThrow(
			/payload section is not a JSON object/,
		);
	});
});

describe("parseProof — header failures", () => {
	it("rejects wrong typ", async () => {
		const { keyPair } = await makeValidProof();
		const jwt = await signProof({
			alg: "ES256",
			keyPair,
			payload: { jti: freshJti(), htm: "POST", htu: "https://x/y", iat: nowSeconds() },
			typ: "JWT",
		});
		expect(() => parseProof(jwt, ALL)).toThrow(/typ must/);
	});

	it("rejects missing alg", () => {
		const headerB64 = base64urlEncode(JSON.stringify({ typ: "dpop+jwt", jwk: {} }));
		const jwt = `${headerB64}.${base64urlEncode('{"jti":"a","htm":"GET","htu":"https://x","iat":0}')}.x`;
		expect(() => parseProof(jwt, ALL)).toThrow(/alg must be a string/);
	});

	it("rejects unsupported alg", () => {
		const headerB64 = base64urlEncode(JSON.stringify({ typ: "dpop+jwt", alg: "HS256", jwk: {} }));
		const jwt = `${headerB64}.${base64urlEncode('{"jti":"a","htm":"GET","htu":"https://x","iat":0}')}.x`;
		expect(() => parseProof(jwt, ALL)).toThrow(/unsupported alg/);
	});

	it("rejects alg not in allowed set", () => {
		const headerB64 = base64urlEncode(
			JSON.stringify({
				typ: "dpop+jwt",
				alg: "RS256",
				jwk: { kty: "RSA", n: "n", e: "e" },
			}),
		);
		const jwt = `${headerB64}.${base64urlEncode('{"jti":"a","htm":"GET","htu":"https://x","iat":0}')}.x`;
		expect(() => parseProof(jwt, ES_ONLY)).toThrow(/not in the allowed set/);
	});

	it("rejects missing jwk", () => {
		const headerB64 = base64urlEncode(JSON.stringify({ typ: "dpop+jwt", alg: "ES256" }));
		const jwt = `${headerB64}.${base64urlEncode('{"jti":"a","htm":"GET","htu":"https://x","iat":0}')}.x`;
		expect(() => parseProof(jwt, ALL)).toThrow(/jwk header is missing/);
	});

	it("rejects alg/jwk mismatch", () => {
		const headerB64 = base64urlEncode(
			JSON.stringify({
				typ: "dpop+jwt",
				alg: "ES256",
				jwk: { kty: "RSA", n: "n", e: "e" },
			}),
		);
		const jwt = `${headerB64}.${base64urlEncode('{"jti":"a","htm":"GET","htu":"https://x","iat":0}')}.x`;
		expect(() => parseProof(jwt, ALL)).toThrow(/requires EC jwk/);
	});

	it("rejects jwk with private field", () => {
		const headerB64 = base64urlEncode(
			JSON.stringify({
				typ: "dpop+jwt",
				alg: "ES256",
				jwk: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "private" },
			}),
		);
		const jwt = `${headerB64}.${base64urlEncode('{"jti":"a","htm":"GET","htu":"https://x","iat":0}')}.x`;
		expect(() => parseProof(jwt, ALL)).toThrow(/private field/);
	});
});

describe("parseProof — payload failures", () => {
	const valid = (extra: object) => `${GOOD_HEADER}.${base64urlEncode(JSON.stringify(extra))}.x`;

	it("rejects missing jti / htm / htu / iat", () => {
		expect(() => parseProof(valid({}), ALL)).toThrow(/jti is missing/);
		expect(() => parseProof(valid({ jti: "a" }), ALL)).toThrow(/htm/);
		expect(() => parseProof(valid({ jti: "a", htm: "GET" }), ALL)).toThrow(/htu/);
		expect(() => parseProof(valid({ jti: "a", htm: "GET", htu: "u" }), ALL)).toThrow(/iat/);
	});

	it("rejects empty jti", () => {
		expect(() => parseProof(valid({ jti: "" }), ALL)).toThrow(/jti is missing/);
	});

	it("rejects non-finite iat", () => {
		const jwt = valid({
			jti: "a",
			htm: "GET",
			htu: "u",
			iat: Number.POSITIVE_INFINITY,
		});
		expect(() => parseProof(jwt, ALL)).toThrow(/iat/);
	});

	it("rejects wrong-typed ath/nonce", () => {
		expect(() =>
			parseProof(valid({ jti: "a", htm: "GET", htu: "u", iat: 0, ath: 1 }), ALL),
		).toThrow(/ath/);
		expect(() =>
			parseProof(valid({ jti: "a", htm: "GET", htu: "u", iat: 0, nonce: 1 }), ALL),
		).toThrow(/nonce/);
	});

	it("rejects non-base64url signature", () => {
		const goodPayload = base64urlEncode('{"jti":"a","htm":"GET","htu":"u","iat":0}');
		expect(() => parseProof(`${GOOD_HEADER}.${goodPayload}.with=eq`, ALL)).toThrow(/signature/);
	});
});

describe("parseProof — happy path", () => {
	it("parses a valid proof", async () => {
		const { jwt } = await makeValidProof();
		const parsed = parseProof(jwt, ALL);
		expect(parsed.header.typ).toBe("dpop+jwt");
		expect(parsed.header.alg).toBe("ES256");
		expect(parsed.payload.jti).toBeTruthy();
	});
});

describe("verifyProofClaims", () => {
	it("rejects htm mismatch", async () => {
		const { jwt } = await makeValidProof({ htm: "POST" });
		const parsed = parseProof(jwt, ALL);
		expect(() =>
			verifyProofClaims(parsed, {
				htm: "GET",
				htu: parsed.payload.htu,
				now: nowSeconds(),
				iatTolerance: 60,
			}),
		).toThrow(/htm/);
	});

	it("rejects htu mismatch", async () => {
		const { jwt } = await makeValidProof({ htu: "https://api.example.com/x" });
		const parsed = parseProof(jwt, ALL);
		expect(() =>
			verifyProofClaims(parsed, {
				htm: "POST",
				htu: "https://other.example.com/x",
				now: nowSeconds(),
				iatTolerance: 60,
			}),
		).toThrow(/htu/);
	});

	it("ignores query and fragment in htu", async () => {
		const { jwt } = await makeValidProof({ htu: "https://api.example.com/x?a=1#f" });
		const parsed = parseProof(jwt, ALL);
		expect(() =>
			verifyProofClaims(parsed, {
				htm: "POST",
				htu: "https://api.example.com/x?b=2",
				now: nowSeconds(),
				iatTolerance: 60,
			}),
		).not.toThrow();
	});

	it("rejects iat outside tolerance", async () => {
		const past = nowSeconds() - 1000;
		const { jwt } = await makeValidProof({ now: past });
		const parsed = parseProof(jwt, ALL);
		expect(() =>
			verifyProofClaims(parsed, {
				htm: "POST",
				htu: parsed.payload.htu,
				now: nowSeconds(),
				iatTolerance: 60,
			}),
		).toThrow(/iat/);
	});

	it("accepts iat within tolerance", async () => {
		const { jwt } = await makeValidProof();
		const parsed = parseProof(jwt, ALL);
		expect(() =>
			verifyProofClaims(parsed, {
				htm: parsed.payload.htm,
				htu: parsed.payload.htu,
				now: nowSeconds(),
				iatTolerance: 60,
			}),
		).not.toThrow();
	});
});

describe("normalizeHtu", () => {
	it("strips query and fragment", () => {
		expect(normalizeHtu("https://api.example.com/x?q=1#f")).toBe("https://api.example.com/x");
	});

	it("preserves URL default-port stripping", () => {
		expect(normalizeHtu("https://api.example.com:443/x")).toBe("https://api.example.com/x");
	});

	it("rejects malformed URL", () => {
		expect(() => normalizeHtu("not a url")).toThrow(DPoPProofError);
	});
});

describe("verifyProofSignature", () => {
	const ALGS_TO_TEST = ["ES256", "ES384", "ES512", "RS256", "PS256", "EdDSA"] as const;

	it.each(ALGS_TO_TEST)("verifies a valid %s proof", async (alg) => {
		const keyPair = await generateKeyPair(alg);
		const jwt = await signProof({
			alg,
			keyPair,
			payload: { jti: freshJti(), htm: "POST", htu: "https://x/y", iat: nowSeconds() },
		});
		const parsed = parseProof(jwt, ALL);
		await expect(verifyProofSignature(parsed)).resolves.toBeUndefined();
	});

	it("rejects tampered signature", async () => {
		const { jwt } = await makeValidProof();
		const parts = jwt.split(".");
		// Tamper signature, not payload — keeps it a structurally-valid JWT and
		// guarantees the failure mode is a signature mismatch (not a JSON parse error).
		const tampered = `${parts[0]}.${parts[1]}.${parts[2].slice(0, -2)}AA`;
		const parsed = parseProof(tampered, ALL);
		await expect(verifyProofSignature(parsed)).rejects.toThrow(/signature/);
	});
});

describe("computeAth", () => {
	it("is deterministic and 43-char base64url", async () => {
		const a = await computeAth("token");
		const b = await computeAth("token");
		expect(a).toBe(b);
		expect(a).toHaveLength(43);
		expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
	});

	it("differs for different tokens", async () => {
		expect(await computeAth("a")).not.toBe(await computeAth("b"));
	});
});

describe("timingSafeEqual", () => {
	it("returns true for equal", () => {
		expect(timingSafeEqual("abc", "abc")).toBe(true);
		expect(timingSafeEqual("", "")).toBe(true);
	});

	it("returns false for different content of same length", () => {
		expect(timingSafeEqual("abc", "abd")).toBe(false);
	});

	it("returns false for different lengths", () => {
		expect(timingSafeEqual("abc", "ab")).toBe(false);
	});
});
