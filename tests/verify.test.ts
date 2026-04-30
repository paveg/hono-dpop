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
		// Use a 2048-bit RSA modulus stub so that assertPublicJwk's length policy
		// passes and the alg/jwk mismatch from assertAlgMatchesJwk is what triggers.
		const validN = base64urlEncode(new Uint8Array(256).fill(0xff));
		const headerB64 = base64urlEncode(
			JSON.stringify({
				typ: "dpop+jwt",
				alg: "ES256",
				jwk: { kty: "RSA", n: validN, e: "AQAB" },
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

	it("rejects iat above MAX_IAT", () => {
		// 1e15 is far past the safe upper bound; without a cap, iat * 1000 in
		// downstream jti expiry math overflows Number.MAX_SAFE_INTEGER and the
		// jti becomes effectively immortal.
		const jwt = valid({ jti: "a", htm: "GET", htu: "u", iat: 1e15 });
		expect(() => parseProof(jwt, ALL)).toThrow(/iat/);
	});

	it("rejects negative iat", () => {
		const jwt = valid({ jti: "a", htm: "GET", htu: "u", iat: -1 });
		expect(() => parseProof(jwt, ALL)).toThrow(/iat/);
	});

	it("rejects non-integer iat (e.g., 1234.5)", () => {
		const jwt = valid({ jti: "a", htm: "GET", htu: "u", iat: 1234.5 });
		expect(() => parseProof(jwt, ALL)).toThrow(/iat/);
	});

	it("accepts iat=0 boundary", async () => {
		// 0 is a non-negative integer; the freshness window check happens later
		// in verifyProofClaims, not here in parseProof.
		const { jwt } = await makeValidProof({ now: 0 });
		expect(() => parseProof(jwt, ALL)).not.toThrow();
	});

	it("accepts iat at MAX_IAT boundary", async () => {
		const { jwt } = await makeValidProof({ now: 1e10 });
		expect(() => parseProof(jwt, ALL)).not.toThrow();
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

	it("strict policy preserves trailing slash on non-root paths", () => {
		expect(normalizeHtu("https://api.example.com/x/")).toBe("https://api.example.com/x/");
		expect(normalizeHtu("https://api.example.com/x")).toBe("https://api.example.com/x");
	});

	it("trailing-slash-insensitive policy strips trailing slash from non-root paths", () => {
		expect(normalizeHtu("https://api.example.com/x/", "trailing-slash-insensitive")).toBe(
			"https://api.example.com/x",
		);
		expect(normalizeHtu("https://api.example.com/x", "trailing-slash-insensitive")).toBe(
			"https://api.example.com/x",
		);
	});

	it("trailing-slash-insensitive preserves the root slash", () => {
		expect(normalizeHtu("https://api.example.com", "trailing-slash-insensitive")).toBe(
			"https://api.example.com/",
		);
		expect(normalizeHtu("https://api.example.com/", "trailing-slash-insensitive")).toBe(
			"https://api.example.com/",
		);
	});
});

describe("verifyProofClaims — iat windows", () => {
	it("rejects iat in the future by default (symmetric window)", async () => {
		const future = nowSeconds() + 1000;
		const { jwt } = await makeValidProof({ now: future });
		const parsed = parseProof(jwt, ALL);
		expect(() =>
			verifyProofClaims(parsed, {
				htm: parsed.payload.htm,
				htu: parsed.payload.htu,
				now: nowSeconds(),
				iatTolerance: 60,
			}),
		).toThrow(/iat/);
	});

	it("allowFutureIat: accepts arbitrarily future iat", async () => {
		const future = nowSeconds() + 100_000;
		const { jwt } = await makeValidProof({ now: future });
		const parsed = parseProof(jwt, ALL);
		expect(() =>
			verifyProofClaims(parsed, {
				htm: parsed.payload.htm,
				htu: parsed.payload.htu,
				now: nowSeconds(),
				iatTolerance: 60,
				allowFutureIat: true,
			}),
		).not.toThrow();
	});

	it("allowFutureIat: still rejects iat too old", async () => {
		const past = nowSeconds() - 1000;
		const { jwt } = await makeValidProof({ now: past });
		const parsed = parseProof(jwt, ALL);
		expect(() =>
			verifyProofClaims(parsed, {
				htm: parsed.payload.htm,
				htu: parsed.payload.htu,
				now: nowSeconds(),
				iatTolerance: 60,
				allowFutureIat: true,
			}),
		).toThrow(/iat/);
	});

	it("htuComparison trailing-slash-insensitive: matches across trailing slash", async () => {
		const { jwt } = await makeValidProof({ htu: "https://api.example.com/x" });
		const parsed = parseProof(jwt, ALL);
		expect(() =>
			verifyProofClaims(parsed, {
				htm: parsed.payload.htm,
				htu: "https://api.example.com/x/",
				now: nowSeconds(),
				iatTolerance: 60,
				htuComparison: "trailing-slash-insensitive",
			}),
		).not.toThrow();
	});

	it("htuComparison strict (default): rejects across trailing slash", async () => {
		const { jwt } = await makeValidProof({ htu: "https://api.example.com/x" });
		const parsed = parseProof(jwt, ALL);
		expect(() =>
			verifyProofClaims(parsed, {
				htm: parsed.payload.htm,
				htu: "https://api.example.com/x/",
				now: nowSeconds(),
				iatTolerance: 60,
			}),
		).toThrow(/htu/);
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

	it("returns false for length mismatch (b longer)", () => {
		expect(timingSafeEqual("abc", "abcd")).toBe(false);
	});

	it("returns false for length mismatch (a longer)", () => {
		expect(timingSafeEqual("abcd", "abc")).toBe(false);
	});

	it("returns false for empty vs non-empty", () => {
		expect(timingSafeEqual("", "x")).toBe(false);
		expect(timingSafeEqual("x", "")).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Boundary characterization tests
//
// These pin down the exact off-by-one and edge behaviors of verify.ts so
// future refactors can't silently shift the boundary. They intentionally
// exercise both sides of every "<=" / "<" / ">" comparison.
// ---------------------------------------------------------------------------

describe("verifyProofClaims — iat tolerance boundaries (off-by-one)", () => {
	const FIXED_NOW = 1_700_000_000;
	const TOLERANCE = 60;

	async function parsedAt(iat: number) {
		const { jwt } = await makeValidProof({ now: iat });
		return parseProof(jwt, ALL);
	}

	it("accepts delta = +iatTolerance exactly (boundary uses '>' not '>=')", async () => {
		const parsed = await parsedAt(FIXED_NOW - TOLERANCE);
		expect(() =>
			verifyProofClaims(parsed, {
				htm: parsed.payload.htm,
				htu: parsed.payload.htu,
				now: FIXED_NOW,
				iatTolerance: TOLERANCE,
			}),
		).not.toThrow();
	});

	it("rejects delta = +iatTolerance + 1 (just past the past edge)", async () => {
		const parsed = await parsedAt(FIXED_NOW - TOLERANCE - 1);
		expect(() =>
			verifyProofClaims(parsed, {
				htm: parsed.payload.htm,
				htu: parsed.payload.htu,
				now: FIXED_NOW,
				iatTolerance: TOLERANCE,
			}),
		).toThrow(/iat/);
	});

	it("accepts delta = -iatTolerance exactly with allowFutureIat: false", async () => {
		const parsed = await parsedAt(FIXED_NOW + TOLERANCE);
		expect(() =>
			verifyProofClaims(parsed, {
				htm: parsed.payload.htm,
				htu: parsed.payload.htu,
				now: FIXED_NOW,
				iatTolerance: TOLERANCE,
				allowFutureIat: false,
			}),
		).not.toThrow();
	});

	it("rejects delta = -iatTolerance - 1 with allowFutureIat: false", async () => {
		const parsed = await parsedAt(FIXED_NOW + TOLERANCE + 1);
		expect(() =>
			verifyProofClaims(parsed, {
				htm: parsed.payload.htm,
				htu: parsed.payload.htu,
				now: FIXED_NOW,
				iatTolerance: TOLERANCE,
				allowFutureIat: false,
			}),
		).toThrow(/iat/);
	});

	it("accepts delta = -iatTolerance - 1 with allowFutureIat: true (only past staleness gated)", async () => {
		const parsed = await parsedAt(FIXED_NOW + TOLERANCE + 1);
		expect(() =>
			verifyProofClaims(parsed, {
				htm: parsed.payload.htm,
				htu: parsed.payload.htu,
				now: FIXED_NOW,
				iatTolerance: TOLERANCE,
				allowFutureIat: true,
			}),
		).not.toThrow();
	});

	it("rejects delta = +iatTolerance + 1 even with allowFutureIat: true (tooOld still enforced)", async () => {
		const parsed = await parsedAt(FIXED_NOW - TOLERANCE - 1);
		expect(() =>
			verifyProofClaims(parsed, {
				htm: parsed.payload.htm,
				htu: parsed.payload.htu,
				now: FIXED_NOW,
				iatTolerance: TOLERANCE,
				allowFutureIat: true,
			}),
		).toThrow(/iat/);
	});
});

describe("parseProof — iat numeric boundaries", () => {
	// Use "AA" (a 2-char string that decodes cleanly) for the signature segment
	// because parseProof eagerly validates base64url shape on the sig — happy-path
	// boundaries must clear that gate to actually reach the iat checks.
	const valid = (extra: object) => `${GOOD_HEADER}.${base64urlEncode(JSON.stringify(extra))}.AA`;

	it("accepts iat = 0 (lower inclusive boundary)", () => {
		const jwt = valid({ jti: "a", htm: "GET", htu: "https://x", iat: 0 });
		expect(() => parseProof(jwt, ALL)).not.toThrow();
	});

	it("rejects iat = -1 (just below the lower bound)", () => {
		const jwt = valid({ jti: "a", htm: "GET", htu: "https://x", iat: -1 });
		expect(() => parseProof(jwt, ALL)).toThrow(/iat/);
	});

	it("accepts iat = MAX_IAT (1e10, upper inclusive boundary)", () => {
		const jwt = valid({ jti: "a", htm: "GET", htu: "https://x", iat: 1e10 });
		expect(() => parseProof(jwt, ALL)).not.toThrow();
	});

	it("rejects iat = 1e10 + 1 (just above MAX_IAT)", () => {
		const jwt = valid({ jti: "a", htm: "GET", htu: "https://x", iat: 1e10 + 1 });
		expect(() => parseProof(jwt, ALL)).toThrow(/iat/);
	});

	it("rejects iat = 1.5 (non-integer)", () => {
		const jwt = valid({ jti: "a", htm: "GET", htu: "https://x", iat: 1.5 });
		expect(() => parseProof(jwt, ALL)).toThrow(/iat/);
	});

	it("rejects iat = NaN (JSON.stringify normalizes to null → fails 'must be number')", () => {
		// JSON has no NaN literal; JSON.stringify({iat: NaN}) emits {"iat":null},
		// which parseProof rejects via the typeof check before hitting MAX_IAT.
		const jwt = valid({ jti: "a", htm: "GET", htu: "https://x", iat: Number.NaN });
		expect(() => parseProof(jwt, ALL)).toThrow(/iat/);
	});

	it("rejects iat = Infinity (JSON.stringify normalizes to null)", () => {
		const jwt = valid({ jti: "a", htm: "GET", htu: "https://x", iat: Number.POSITIVE_INFINITY });
		expect(() => parseProof(jwt, ALL)).toThrow(/iat/);
	});
});

describe("normalizeHtu — trailing-slash-insensitive specifics", () => {
	const TSI = "trailing-slash-insensitive" as const;

	it("treats https://x/api and https://x/api/ as equal (both directions)", () => {
		expect(normalizeHtu("https://x/api", TSI)).toBe(normalizeHtu("https://x/api/", TSI));
		expect(normalizeHtu("https://x/api/", TSI)).toBe(normalizeHtu("https://x/api", TSI));
	});

	it("preserves the lone root slash on https://x/", () => {
		expect(normalizeHtu("https://x/", TSI)).toBe("https://x/");
	});

	it("URL parser supplies the root slash for https://x (no slash) and TSI keeps it", () => {
		// new URL("https://x").toString() → "https://x/", which TSI must NOT strip.
		expect(normalizeHtu("https://x", TSI)).toBe("https://x/");
	});

	it("strips exactly one trailing slash from https://x/api// (leaves the inner '/')", () => {
		// Documents single-strip behavior — the loop is a single slice(0,-1), not a
		// while-loop, so consecutive trailing slashes collapse by one only.
		expect(normalizeHtu("https://x/api//", TSI)).toBe("https://x/api/");
	});

	it("strips search and fragment under TSI policy", () => {
		expect(normalizeHtu("https://x/path?q=1#frag", TSI)).toBe("https://x/path");
	});
});

describe("parseProof — segment count and emptiness", () => {
	it("rejects a string with zero periods", () => {
		expect(() => parseProof("abc", ALL)).toThrow(/not a JWT/);
	});

	it("rejects a string with exactly one period", () => {
		expect(() => parseProof("a.b", ALL)).toThrow(/not a JWT/);
	});

	it("rejects a string with four periods", () => {
		expect(() => parseProof("a.b.c.d.e", ALL)).toThrow(/not a JWT/);
	});

	it("rejects a trailing period (a.b.c.) — split yields 4 parts", () => {
		expect(() => parseProof("a.b.c.", ALL)).toThrow(/not a JWT/);
	});

	it("rejects a leading period (.a.b) — empty header decodes to '' → JSON.parse fails", () => {
		// split(".a.b") = ["", "a", "b"] (length 3, passes the parts check),
		// then base64urlDecode("") returns 0 bytes, and JSON.parse("") throws.
		expect(() => parseProof(".a.b", ALL)).toThrow(/header section is not valid JSON/);
	});

	it("rejects fully empty between separators (..)", () => {
		// split("..") = ["", "", ""] — three empty parts, header JSON.parse fails first.
		expect(() => parseProof("..", ALL)).toThrow(/header section is not valid JSON/);
	});
});

describe("parseProof — payload base64url valid but JSON invalid", () => {
	it("rejects payload that decodes to non-JSON bytes", () => {
		// 'not-json' is base64url-encodable; its decoded bytes are not valid JSON.
		const jwt = `${GOOD_HEADER}.${base64urlEncode("not-json")}.x`;
		expect(() => parseProof(jwt, ALL)).toThrow(/payload section is not valid JSON/);
	});
});

describe("timingSafeEqual — additional UTF-8 boundaries", () => {
	it("returns true for identical 4-byte UTF-8 sequence (😀)", () => {
		expect(timingSafeEqual("😀", "😀")).toBe(true);
	});

	it("returns false for two different 4-byte UTF-8 emoji (😀 vs 🚀)", () => {
		expect(timingSafeEqual("😀", "🚀")).toBe(false);
	});

	it("returns true for identical 2-byte UTF-8 sequence (ÿ)", () => {
		// 'ÿ' (U+00FF) encodes to two UTF-8 bytes [0xC3, 0xBF].
		expect(timingSafeEqual("ÿ", "ÿ")).toBe(true);
	});
});

describe("computeAth — empty input boundary", () => {
	it("returns the SHA-256 base64url digest of the empty string", async () => {
		// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
		// → base64url (no pad): "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
		const digest = await computeAth("");
		expect(digest).toBe("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
		expect(digest).toHaveLength(43);
	});
});

describe("parseProof — typ and alg fine boundaries", () => {
	const valid = (header: object, extra: object = { jti: "a", htm: "GET", htu: "u", iat: 0 }) =>
		`${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(JSON.stringify(extra))}.x`;

	it("rejects typ = 'DPOP+JWT' (case-strict)", () => {
		const jwt = valid({
			typ: "DPOP+JWT",
			alg: "ES256",
			jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
		});
		expect(() => parseProof(jwt, ALL)).toThrow(/typ must/);
	});

	it("rejects typ = 'dpop+jwt ' (trailing whitespace)", () => {
		const jwt = valid({
			typ: "dpop+jwt ",
			alg: "ES256",
			jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
		});
		expect(() => parseProof(jwt, ALL)).toThrow(/typ must/);
	});

	it("rejects alg = '' (empty string passes typeof but fails the supported check)", () => {
		const jwt = valid({
			typ: "dpop+jwt",
			alg: "",
			jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
		});
		expect(() => parseProof(jwt, ALL)).toThrow(/unsupported alg/);
	});

	it("rejects alg = 'none'", () => {
		const jwt = valid({
			typ: "dpop+jwt",
			alg: "none",
			jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
		});
		expect(() => parseProof(jwt, ALL)).toThrow(/unsupported alg/);
	});

	it("rejects alg = 'HS256' (symmetric algs are always disallowed)", () => {
		const jwt = valid({
			typ: "dpop+jwt",
			alg: "HS256",
			jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
		});
		expect(() => parseProof(jwt, ALL)).toThrow(/unsupported alg/);
	});
});
