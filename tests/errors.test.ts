import { describe, expect, it, vi } from "vitest";
import {
	DPoPErrors,
	DPoPProofError,
	clampHttpStatus,
	problemResponse,
	wwwAuthenticateHeader,
} from "../src/errors.js";

describe("clampHttpStatus", () => {
	it("returns valid status as-is", () => {
		expect(clampHttpStatus(200)).toBe(200);
		expect(clampHttpStatus(401)).toBe(401);
		expect(clampHttpStatus(599)).toBe(599);
	});

	it("returns 500 for out-of-range", () => {
		expect(clampHttpStatus(99)).toBe(500);
		expect(clampHttpStatus(600)).toBe(500);
		expect(clampHttpStatus(0)).toBe(500);
	});

	it("returns 500 for non-integer or non-finite", () => {
		expect(clampHttpStatus(200.5)).toBe(500);
		expect(clampHttpStatus(Number.NaN)).toBe(500);
		expect(clampHttpStatus(Number.POSITIVE_INFINITY)).toBe(500);
	});
});

describe("wwwAuthenticateHeader", () => {
	it("formats with single error param", () => {
		expect(wwwAuthenticateHeader("invalid_dpop_proof")).toBe('DPoP error="invalid_dpop_proof"');
	});

	it("includes extras", () => {
		expect(wwwAuthenticateHeader("invalid_dpop_proof", { realm: "api" })).toBe(
			'DPoP error="invalid_dpop_proof", realm="api"',
		);
	});

	it("escapes embedded quotes", () => {
		expect(wwwAuthenticateHeader("invalid_token", { error_description: 'has "quote"' })).toBe(
			'DPoP error="invalid_token", error_description="has \\"quote\\""',
		);
	});

	it("escapes backslash in extras values", () => {
		// Input value: a\b (3 chars). RFC 7230 §3.2.6 requires \ -> \\.
		// In source: "abc\\def" represents `abc\def` (8 chars).
		// Expected fragment in header: realm="abc\\def" — the value `abc\\def` (9 chars,
		// double-backslash). In source string: 'realm="abc\\\\def"' (4 backslashes
		// in source = 2 backslashes in the actual string).
		expect(wwwAuthenticateHeader("invalid_dpop_proof", { realm: "abc\\def" })).toBe(
			'DPoP error="invalid_dpop_proof", realm="abc\\\\def"',
		);
	});

	it("escapes both backslash and quote in correct order", () => {
		// Input value (3 chars): backslash, quote, b — written in source as 'a\\"b'
		// Wait — 'a\\"b' would terminate the string at the unescaped ". Use double-quoted
		// JS string: "a\\\"b" represents (4 chars): a, \, ", b.
		// Expected escape: \ -> \\, " -> \" — net (6 chars): a, \, \, \, ", b.
		// In source: "a\\\\\\\"b" (a + 4 backslashes = \\ + 2 backslashes = \" + b).
		const input = 'a\\"b'; // a, \, ", b
		const output = wwwAuthenticateHeader("invalid_dpop_proof", { x: input });
		// The header fragment should be: x="a\\\"b"
		// In source: 'x="a\\\\\\"b"' = x=" + a + \\ + \" + b + "
		expect(output).toBe('DPoP error="invalid_dpop_proof", x="a\\\\\\"b"');
	});

	it("escapes backslash in wwwAuthError too", () => {
		// Input wwwAuthError: "evil\hack" (source: "evil\\hack").
		// Expected: error="evil\\hack" (source: 'error="evil\\\\hack"').
		expect(wwwAuthenticateHeader("evil\\hack")).toBe('DPoP error="evil\\\\hack"');
	});
});

describe("problemResponse", () => {
	it("returns application/problem+json with WWW-Authenticate", () => {
		const res = problemResponse(DPoPErrors.invalidProof("reason"));
		expect(res.status).toBe(401);
		expect(res.headers.get("Content-Type")).toContain("application/problem+json");
		expect(res.headers.get("WWW-Authenticate")).toBe('DPoP error="invalid_dpop_proof"');
	});

	it("falls back to 500 when JSON.stringify throws", () => {
		vi.spyOn(JSON, "stringify").mockImplementationOnce(() => {
			throw new TypeError("circular");
		});
		const res = problemResponse(DPoPErrors.invalidProof("x"));
		expect(res.status).toBe(500);
		vi.restoreAllMocks();
	});

	it("clamps out-of-range status", () => {
		const bad = { ...DPoPErrors.invalidProof("x"), status: 999 };
		expect(problemResponse(bad).status).toBe(500);
	});

	it("merges wwwAuthExtras and extraHeaders", () => {
		const res = problemResponse(DPoPErrors.invalidProof("x"), {
			wwwAuthExtras: { error_description: "details" },
			extraHeaders: { "Cache-Control": "no-store" },
		});
		expect(res.headers.get("WWW-Authenticate")).toContain('error_description="details"');
		expect(res.headers.get("Cache-Control")).toBe("no-store");
	});
});

describe("DPoPProofError", () => {
	it("carries the ProblemDetail", () => {
		const problem = DPoPErrors.invalidProof("bad");
		const err = new DPoPProofError(problem);
		expect(err).toBeInstanceOf(Error);
		expect(err.problem).toBe(problem);
		expect(err.message).toBe("bad");
		expect(err.name).toBe("DPoPProofError");
	});
});

describe("DPoPErrors registry", () => {
	it("all entries have required fields and 401 status", () => {
		const all = [
			DPoPErrors.invalidProof("x"),
			DPoPErrors.missingAccessToken(),
			DPoPErrors.athMismatch(),
			DPoPErrors.jtiReplay(),
			DPoPErrors.useNonce("nonce-value"),
		];
		for (const p of all) {
			expect(p.type).toMatch(/^https:\/\//);
			expect(p.title.length).toBeGreaterThan(0);
			expect(p.status).toBe(401);
			expect(p.code.length).toBeGreaterThan(0);
			expect(p.wwwAuthError.length).toBeGreaterThan(0);
		}
	});
});

describe("DPoPErrors.useNonce", () => {
	it("carries nonce in WWW-Authenticate extras and DPoP-Nonce header", () => {
		const problem = DPoPErrors.useNonce("the-nonce");
		expect(problem.code).toBe("USE_NONCE");
		expect(problem.wwwAuthError).toBe("use_dpop_nonce");
		expect(problem.wwwAuthExtras).toEqual({ nonce: "the-nonce" });
		expect(problem.additionalHeaders).toEqual({ "DPoP-Nonce": "the-nonce" });
	});

	it("problemResponse echoes both headers", () => {
		const res = problemResponse(DPoPErrors.useNonce("abc"));
		expect(res.headers.get("WWW-Authenticate")).toContain('error="use_dpop_nonce"');
		expect(res.headers.get("WWW-Authenticate")).toContain('nonce="abc"');
		expect(res.headers.get("DPoP-Nonce")).toBe("abc");
	});
});

describe("DPoPErrors.invalidProof — detail sanitization", () => {
	it("strips CR/LF from detail", () => {
		const p = DPoPErrors.invalidProof("evil\r\nFAKE LOG LINE");
		expect(p.detail).not.toContain("\r");
		expect(p.detail).not.toContain("\n");
		expect(p.detail).toBe("evilFAKE LOG LINE");
	});

	it("strips ANSI escape sequences (ESC chars)", () => {
		const p = DPoPErrors.invalidProof("\x1B[31mred\x1B[0m text");
		expect(p.detail).not.toContain("\x1B");
		expect(p.detail).toBe("[31mred[0m text");
	});

	it("strips NUL bytes", () => {
		const p = DPoPErrors.invalidProof("a\x00b");
		expect(p.detail).toBe("ab");
	});

	it("strips C1 control range (0x80-0x9F)", () => {
		const p = DPoPErrors.invalidProof("a\x85b\x9Fc");
		expect(p.detail).toBe("abc");
	});

	it("truncates detail above 256 chars with ellipsis", () => {
		const long = "x".repeat(500);
		const p = DPoPErrors.invalidProof(long);
		// Truncation: 256 chars + single ellipsis "…" character.
		expect(p.detail.length).toBe(257);
		expect(p.detail.endsWith("…")).toBe(true);
		expect(p.detail.startsWith("x".repeat(256))).toBe(true);
	});

	it("does not append ellipsis when detail is exactly 256 chars", () => {
		const exact = "x".repeat(256);
		const p = DPoPErrors.invalidProof(exact);
		expect(p.detail).toBe(exact);
		expect(p.detail.endsWith("…")).toBe(false);
	});

	it("preserves printable Unicode (e.g., Japanese characters)", () => {
		const jp = "アルゴリズム不正";
		const p = DPoPErrors.invalidProof(jp);
		expect(p.detail).toBe(jp);
	});
});

describe("problemResponse — additionalHeaders + wwwAuthExtras from ProblemDetail", () => {
	it("propagates ProblemDetail.additionalHeaders into the response", () => {
		const problem = {
			...DPoPErrors.invalidProof("x"),
			additionalHeaders: { "X-Foo": "bar" },
		};
		const res = problemResponse(problem);
		expect(res.headers.get("X-Foo")).toBe("bar");
	});

	it("merges ProblemDetail.wwwAuthExtras with caller-supplied extras", () => {
		const problem = { ...DPoPErrors.invalidProof("x"), wwwAuthExtras: { algs: "ES256" } };
		const res = problemResponse(problem, { wwwAuthExtras: { realm: "api" } });
		const auth = res.headers.get("WWW-Authenticate");
		expect(auth).toContain('algs="ES256"');
		expect(auth).toContain('realm="api"');
	});
});
