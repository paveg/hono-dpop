import { describe, expect, it } from "vitest";
import { DPoPProofError } from "../src/errors.js";
import { assertJktBinding, verifyJktBinding } from "../src/jkt-binding.js";

describe("verifyJktBinding", () => {
	it("returns true for matching cnf.jkt", () => {
		expect(verifyJktBinding({ cnf: { jkt: "abc" } }, "abc")).toBe(true);
	});

	it("returns false for mismatched cnf.jkt", () => {
		expect(verifyJktBinding({ cnf: { jkt: "abc" } }, "xyz")).toBe(false);
	});

	it("returns false when cnf is missing", () => {
		expect(verifyJktBinding({}, "abc")).toBe(false);
	});

	it("returns false when cnf.jkt is missing", () => {
		expect(verifyJktBinding({ cnf: {} }, "abc")).toBe(false);
	});

	it("returns false when cnf.jkt is not a string", () => {
		expect(verifyJktBinding({ cnf: { jkt: 123 as unknown as string } }, "abc")).toBe(false);
	});
});

describe("assertJktBinding", () => {
	it("does not throw on matching binding", () => {
		expect(() => assertJktBinding({ cnf: { jkt: "abc" } }, "abc")).not.toThrow();
	});

	it("throws DPoPProofError on mismatch", () => {
		expect(() => assertJktBinding({ cnf: { jkt: "abc" } }, "xyz")).toThrow(DPoPProofError);
	});

	it("throws with invalid_dpop_proof error code", () => {
		try {
			assertJktBinding({ cnf: { jkt: "abc" } }, "xyz");
			throw new Error("did not throw");
		} catch (e) {
			expect(e).toBeInstanceOf(DPoPProofError);
			expect((e as DPoPProofError).problem.wwwAuthError).toBe("invalid_dpop_proof");
			expect((e as DPoPProofError).problem.status).toBe(401);
		}
	});

	it("throws when cnf is missing", () => {
		expect(() => assertJktBinding({}, "abc")).toThrow(DPoPProofError);
	});
});
