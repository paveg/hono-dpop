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

describe("verifyJktBinding — case sensitivity", () => {
	it("returns false when stored jkt is uppercase but proof is lowercase", () => {
		expect(verifyJktBinding({ cnf: { jkt: "ABC" } }, "abc")).toBe(false);
	});

	it("returns false when stored jkt is lowercase but proof is uppercase", () => {
		expect(verifyJktBinding({ cnf: { jkt: "abc" } }, "ABC")).toBe(false);
	});

	it("returns true on exact-case match", () => {
		expect(verifyJktBinding({ cnf: { jkt: "abc" } }, "abc")).toBe(true);
	});

	it("assertJktBinding throws on case mismatch", () => {
		expect(() => assertJktBinding({ cnf: { jkt: "ABC" } }, "abc")).toThrow(DPoPProofError);
	});
});

describe("verifyJktBinding — empty/null/undefined handling", () => {
	it("returns true when both stored jkt and proof are empty strings", () => {
		// Both sides are typeof "string" and equal — implementation treats this as a match.
		// Documented here as a characterization test; callers should never pass empty thumbprints.
		expect(verifyJktBinding({ cnf: { jkt: "" } }, "")).toBe(true);
	});

	it("returns false when stored jkt is empty but proof is non-empty", () => {
		expect(verifyJktBinding({ cnf: { jkt: "" } }, "abc")).toBe(false);
	});

	it("returns false when stored jkt is non-empty but proof is empty", () => {
		expect(verifyJktBinding({ cnf: { jkt: "abc" } }, "")).toBe(false);
	});

	it("returns false when cnf is absent", () => {
		expect(verifyJktBinding({}, "abc")).toBe(false);
	});

	it("returns false when cnf is present but jkt is absent", () => {
		expect(verifyJktBinding({ cnf: {} }, "abc")).toBe(false);
	});

	it("returns false when cnf is explicitly undefined", () => {
		expect(verifyJktBinding({ cnf: undefined } as { cnf?: { jkt?: string } }, "abc")).toBe(false);
	});

	it("returns false when cnf is null (optional-chain short-circuits)", () => {
		expect(verifyJktBinding({ cnf: null } as unknown as { cnf?: { jkt?: string } }, "abc")).toBe(
			false,
		);
	});
});

describe("verifyJktBinding ⇔ assertJktBinding consistency", () => {
	const cases: Array<{
		name: string;
		claims: { cnf?: { jkt?: string } };
		thumbprint: string;
		expected: boolean;
	}> = [
		{ name: "exact match", claims: { cnf: { jkt: "abc" } }, thumbprint: "abc", expected: true },
		{
			name: "case mismatch",
			claims: { cnf: { jkt: "ABC" } },
			thumbprint: "abc",
			expected: false,
		},
		{
			name: "value mismatch",
			claims: { cnf: { jkt: "abc" } },
			thumbprint: "xyz",
			expected: false,
		},
		{ name: "missing cnf", claims: {}, thumbprint: "abc", expected: false },
		{ name: "missing jkt", claims: { cnf: {} }, thumbprint: "abc", expected: false },
	];

	for (const { name, claims, thumbprint, expected } of cases) {
		it(`is consistent for: ${name}`, () => {
			expect(verifyJktBinding(claims, thumbprint)).toBe(expected);
			if (expected) {
				expect(() => assertJktBinding(claims, thumbprint)).not.toThrow();
			} else {
				expect(() => assertJktBinding(claims, thumbprint)).toThrow(DPoPProofError);
			}
		});
	}
});
