import { base64urlDecode, base64urlDecodeToString, base64urlEncode } from "./base64url.js";
import { DPoPErrors, DPoPProofError } from "./errors.js";
import {
	type JwsAlgorithm,
	type PublicJwk,
	assertAlgMatchesJwk,
	assertPublicJwk,
	importPublicJwk,
	isSupportedAlgorithm,
	verifyParamsFor,
} from "./jwk.js";

export interface ParsedProof {
	header: { typ: "dpop+jwt"; alg: JwsAlgorithm; jwk: PublicJwk };
	payload: {
		jti: string;
		htm: string;
		htu: string;
		iat: number;
		ath?: string;
		nonce?: string;
	};
	raw: string;
}

const encoder = new TextEncoder();

function fail(detail: string): never {
	throw new DPoPProofError(DPoPErrors.invalidProof(detail));
}

export function parseProof(jwt: string, allowed: ReadonlySet<JwsAlgorithm>): ParsedProof {
	if (typeof jwt !== "string" || jwt.length === 0) fail("DPoP header is missing");
	const parts = jwt.split(".");
	if (parts.length !== 3) fail("DPoP header is not a JWT");
	const [encHeader, encPayload, encSig] = parts;

	let header: unknown;
	let payload: unknown;
	try {
		header = JSON.parse(base64urlDecodeToString(encHeader));
	} catch {
		fail("DPoP header section is not valid JSON");
	}
	try {
		payload = JSON.parse(base64urlDecodeToString(encPayload));
	} catch {
		fail("DPoP payload section is not valid JSON");
	}
	if (!header || typeof header !== "object" || Array.isArray(header)) {
		fail("DPoP header section is not a JSON object");
	}
	if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
		fail("DPoP payload section is not a JSON object");
	}

	const h = header as Record<string, unknown>;
	const p = payload as Record<string, unknown>;

	if (h.typ !== "dpop+jwt") fail('typ must be "dpop+jwt"');
	if (typeof h.alg !== "string") fail("alg must be a string");
	if (!isSupportedAlgorithm(h.alg)) fail(`unsupported alg: ${h.alg}`);
	if (!allowed.has(h.alg)) fail(`alg "${h.alg}" is not in the allowed set`);
	if (!h.jwk || typeof h.jwk !== "object") fail("jwk header is missing");

	let jwk: PublicJwk;
	try {
		assertPublicJwk(h.jwk);
		jwk = h.jwk;
		assertAlgMatchesJwk(h.alg, jwk);
	} catch (err) {
		fail((err as Error).message);
	}

	if (typeof p.jti !== "string" || p.jti.length === 0) fail("jti is missing");
	if (typeof p.htm !== "string") fail("htm must be a string");
	if (typeof p.htu !== "string") fail("htu must be a string");
	if (typeof p.iat !== "number" || !Number.isFinite(p.iat)) fail("iat must be a finite number");
	if (p.ath !== undefined && typeof p.ath !== "string") fail("ath must be a string");
	if (p.nonce !== undefined && typeof p.nonce !== "string") fail("nonce must be a string");

	// Validate base64url shape now so verifyProofSignature can decode without re-validating.
	try {
		base64urlDecode(encSig);
	} catch {
		fail("signature is not valid base64url");
	}

	return {
		header: { typ: "dpop+jwt", alg: h.alg, jwk },
		payload: {
			jti: p.jti,
			htm: p.htm,
			htu: p.htu,
			iat: p.iat,
			ath: p.ath as string | undefined,
			nonce: p.nonce as string | undefined,
		},
		raw: jwt,
	};
}

export type HtuComparison = "strict" | "trailing-slash-insensitive";

export interface ClaimVerifyOptions {
	htm: string;
	htu: string;
	/** Current time in seconds. */
	now: number;
	/** Allowed clock skew on iat in seconds. */
	iatTolerance: number;
	/** htu comparison policy (default: "strict"). */
	htuComparison?: HtuComparison;
	/** Allow proofs with iat in the future (default: false). */
	allowFutureIat?: boolean;
}

/**
 * RFC 9449 §4.3 server checks for htm / htu / iat. Throws DPoPProofError on failure.
 */
export function verifyProofClaims(parsed: ParsedProof, opts: ClaimVerifyOptions): void {
	if (parsed.payload.htm !== opts.htm) {
		throw new DPoPProofError(
			DPoPErrors.invalidProof(
				`htm "${parsed.payload.htm}" does not match request method "${opts.htm}"`,
			),
		);
	}
	const policy = opts.htuComparison ?? "strict";
	const expectedHtu = normalizeHtu(opts.htu, policy);
	const actualHtu = normalizeHtu(parsed.payload.htu, policy);
	if (expectedHtu !== actualHtu) {
		throw new DPoPProofError(DPoPErrors.invalidProof("htu does not match request URL"));
	}
	const delta = opts.now - parsed.payload.iat;
	const tooOld = delta > opts.iatTolerance;
	const tooNew = !opts.allowFutureIat && delta < -opts.iatTolerance;
	if (tooOld || tooNew) {
		throw new DPoPProofError(
			DPoPErrors.invalidProof(`iat is outside the ${opts.iatTolerance}s window`),
		);
	}
}

/**
 * Normalize a URL for htu comparison: strip query and fragment.
 * RFC 9449 §4.3 step 11: "ignoring any query and fragment parts".
 *
 * When `policy` is `"trailing-slash-insensitive"`, a trailing `/` is stripped
 * from non-root paths so `https://x/api` and `https://x/api/` compare equal.
 */
export function normalizeHtu(input: string, policy: HtuComparison = "strict"): string {
	let url: URL;
	try {
		url = new URL(input);
	} catch {
		throw new DPoPProofError(DPoPErrors.invalidProof("URL is not parseable"));
	}
	url.hash = "";
	url.search = "";
	let s = url.toString();
	if (policy === "trailing-slash-insensitive") {
		// Only strip trailing slash from non-root paths. URL.toString() always
		// emits at least "scheme://host/", so the shortest possible form ends
		// in exactly one "/" — leave that alone, strip any deeper trailing one.
		if (url.pathname !== "/" && s.endsWith("/")) s = s.slice(0, -1);
	}
	return s;
}

export async function verifyProofSignature(parsed: ParsedProof): Promise<void> {
	const [encHeader, encPayload, encSig] = parsed.raw.split(".");
	const signingInput = encoder.encode(`${encHeader}.${encPayload}`);
	const signature = base64urlDecode(encSig);
	const key = await importPublicJwk(parsed.header.jwk, parsed.header.alg);
	const ok = await crypto.subtle.verify(
		verifyParamsFor(parsed.header.alg),
		key,
		signature,
		signingInput,
	);
	if (!ok) {
		throw new DPoPProofError(DPoPErrors.invalidProof("signature verification failed"));
	}
}

export async function computeAth(accessToken: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", encoder.encode(accessToken));
	return base64urlEncode(new Uint8Array(digest));
}

/** Constant-time string comparison to avoid timing leaks on ath comparisons. */
export function timingSafeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	const aBytes = encoder.encode(a);
	const bBytes = encoder.encode(b);
	let diff = 0;
	for (let i = 0; i < aBytes.length; i++) {
		diff |= aBytes[i] ^ bBytes[i];
	}
	return diff === 0;
}
