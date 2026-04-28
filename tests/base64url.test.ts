import { describe, expect, it } from "vitest";
import { base64urlDecode, base64urlDecodeToString, base64urlEncode } from "../src/base64url.js";

describe("base64urlEncode", () => {
	it("encodes bytes without padding", () => {
		expect(base64urlEncode(new Uint8Array([0xff, 0xfe, 0xfd]))).toBe("__79");
	});

	it("encodes strings as UTF-8", () => {
		expect(base64urlEncode("hello")).toBe("aGVsbG8");
	});

	it("encodes empty input", () => {
		expect(base64urlEncode(new Uint8Array())).toBe("");
		expect(base64urlEncode("")).toBe("");
	});

	it("uses url-safe alphabet", () => {
		expect(base64urlEncode(new Uint8Array([0xfb, 0xff, 0xff]))).toBe("-___");
	});
});

describe("base64urlDecode", () => {
	it("roundtrips bytes", () => {
		const bytes = new Uint8Array([0xff, 0xfe, 0xfd]);
		expect(base64urlDecode(base64urlEncode(bytes))).toEqual(bytes);
	});

	it("decodes empty", () => {
		expect(base64urlDecode("")).toEqual(new Uint8Array());
	});

	it("rejects non-base64url characters", () => {
		expect(() => base64urlDecode("abc!")).toThrow(TypeError);
		expect(() => base64urlDecode("abc=")).toThrow(TypeError);
		expect(() => base64urlDecode("abc+")).toThrow(TypeError);
	});

	it("handles all padding lengths", () => {
		for (const len of [1, 2, 3, 4, 5]) {
			const bytes = new Uint8Array(Array.from({ length: len }, (_, i) => i + 1));
			expect(base64urlDecode(base64urlEncode(bytes))).toEqual(bytes);
		}
	});
});

describe("base64urlDecodeToString", () => {
	it("decodes UTF-8 with multibyte chars", () => {
		expect(base64urlDecodeToString(base64urlEncode("héllo"))).toBe("héllo");
	});
});
