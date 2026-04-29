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

describe("base64urlEncode — byte-length boundaries", () => {
	it("0 byte -> empty string", () => {
		expect(base64urlEncode(new Uint8Array(0))).toBe("");
	});

	it("1 byte [0xAA] -> 'qg' (2 chars, no padding)", () => {
		expect(base64urlEncode(new Uint8Array([0xaa]))).toBe("qg");
	});

	it("2 byte [0xAA, 0xBB] -> 'qrs' (3 chars, no padding)", () => {
		expect(base64urlEncode(new Uint8Array([0xaa, 0xbb]))).toBe("qrs");
	});

	it("3 byte [0xAA, 0xBB, 0xCC] -> 'qrvM' (4 chars)", () => {
		expect(base64urlEncode(new Uint8Array([0xaa, 0xbb, 0xcc]))).toBe("qrvM");
	});

	it("256 bytes of 0xff -> URL-safe alphabet only", () => {
		const out = base64urlEncode(new Uint8Array(256).fill(0xff));
		expect(out).toMatch(/^[A-Za-z0-9_-]+$/);
		expect(out).not.toMatch(/[+/=]/);
	});

	it("256 bytes of 0x00 -> all 'A' chars (no padding)", () => {
		const out = base64urlEncode(new Uint8Array(256));
		// 256 bytes -> ceil(256*4/3) = 342, then trailing '=' stripped: 256*8 = 2048 bits / 6 = 341.33
		// Actually btoa produces 344 chars (with '=='); we strip '=' so 342 chars remain.
		expect(out).toBe("A".repeat(342));
	});
});

describe("base64urlDecode — short-input boundaries", () => {
	it("'' -> 0 byte", () => {
		expect(base64urlDecode("")).toEqual(new Uint8Array(0));
	});

	it("'A' (1 char) is invalid base64 and rejected", () => {
		// 1 char base64url cannot represent any byte; padded form 'A===' is malformed.
		expect(() => base64urlDecode("A")).toThrow();
	});

	it("'AB' (2 chars) -> 1 byte", () => {
		expect(base64urlDecode("AB")).toEqual(new Uint8Array([0x00]));
	});

	it("'ABC' (3 chars) -> 2 bytes", () => {
		expect(base64urlDecode("ABC")).toEqual(new Uint8Array([0x00, 0x10]));
	});

	it("'ABCD' (4 chars) -> 3 bytes", () => {
		expect(base64urlDecode("ABCD")).toEqual(new Uint8Array([0x00, 0x10, 0x83]));
	});

	it("rejects '+' character", () => {
		expect(() => base64urlDecode("ab+c")).toThrow(TypeError);
	});

	it("rejects '/' character", () => {
		expect(() => base64urlDecode("ab/c")).toThrow(TypeError);
	});

	it("rejects '=' character (no padding allowed)", () => {
		expect(() => base64urlDecode("AB==")).toThrow(TypeError);
	});
});

describe("base64urlEncode/Decode — round-trip", () => {
	for (let len = 0; len <= 16; len++) {
		it(`round-trips ${len} bytes of 0x00`, () => {
			const bytes = new Uint8Array(len);
			expect(base64urlDecode(base64urlEncode(bytes))).toEqual(bytes);
		});
		it(`round-trips ${len} bytes of 0xff`, () => {
			const bytes = new Uint8Array(len).fill(0xff);
			expect(base64urlDecode(base64urlEncode(bytes))).toEqual(bytes);
		});
	}

	it("round-trips random bytes", () => {
		for (let i = 0; i < 8; i++) {
			const bytes = crypto.getRandomValues(new Uint8Array(64 + i));
			expect(base64urlDecode(base64urlEncode(bytes))).toEqual(bytes);
		}
	});
});

describe("base64urlDecodeToString — invalid UTF-8 (boundary)", () => {
	it("throws on invalid UTF-8 sequence (fatal decoder)", () => {
		// 0xFF 0xFE alone is not a valid UTF-8 sequence.
		const encoded = base64urlEncode(new Uint8Array([0xff, 0xfe]));
		// Node's fatal TextDecoder throws TypeError; the spec name varies by runtime,
		// so we only assert that some Error is thrown.
		expect(() => base64urlDecodeToString(encoded)).toThrow();
	});

	it("round-trips multibyte UTF-8 ('héllo')", () => {
		const encoded = base64urlEncode(new TextEncoder().encode("héllo"));
		expect(base64urlDecodeToString(encoded)).toBe("héllo");
	});
});
