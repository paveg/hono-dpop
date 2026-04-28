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
