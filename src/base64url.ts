const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const BASE64URL_RE = /^[A-Za-z0-9_-]*$/;

export function base64urlEncode(input: Uint8Array | string): string {
	const bytes = typeof input === "string" ? encoder.encode(input) : input;
	let binary = "";
	for (let i = 0; i < bytes.length; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlDecode(input: string): Uint8Array<ArrayBuffer> {
	if (!BASE64URL_RE.test(input)) {
		throw new TypeError("invalid base64url");
	}
	const padLen = (4 - (input.length % 4)) % 4;
	const padded = input.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padLen);
	const binary = atob(padded);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

export function base64urlDecodeToString(input: string): string {
	return decoder.decode(base64urlDecode(input));
}
