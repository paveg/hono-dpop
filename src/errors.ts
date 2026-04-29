export type DPoPErrorCode =
	| "INVALID_DPOP_PROOF"
	| "MISSING_ACCESS_TOKEN"
	| "ATH_MISMATCH"
	| "JTI_REPLAY"
	| "USE_NONCE";

export interface ProblemDetail {
	type: string;
	title: string;
	status: number;
	detail: string;
	code: DPoPErrorCode;
	/** Value for the `error` parameter of the WWW-Authenticate: DPoP header (RFC 9449 §7.1). */
	wwwAuthError: string;
	/** Extra parameters merged into the WWW-Authenticate header (e.g., `nonce`, `algs`). */
	wwwAuthExtras?: Record<string, string>;
	/** Extra response headers to set on the error response (e.g., `DPoP-Nonce`). */
	additionalHeaders?: Record<string, string>;
}

/** Clamp HTTP status to 200-599 integer range; returns 500 for out-of-range or non-integer values. */
export function clampHttpStatus(status: number): number {
	return Number.isInteger(status) && status >= 200 && status <= 599 ? status : 500;
}

const PROBLEM_CONTENT_TYPE = "application/problem+json; charset=utf-8";
const BASE_URL = "https://hono-dpop.dev/errors";

// RFC 7230 §3.2.6 quoted-string: quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text ).
// Both backslash and double-quote must be backslash-escaped. Order matters —
// escape backslashes BEFORE introducing new ones via the quote escape.
function quoteString(v: string): string {
	return v.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

/** Build an `WWW-Authenticate: DPoP error="...", key="value", ...` header value. */
export function wwwAuthenticateHeader(
	wwwAuthError: string,
	extras?: Record<string, string>,
): string {
	const params: string[] = [`error="${quoteString(wwwAuthError)}"`];
	if (extras) {
		for (const [k, v] of Object.entries(extras)) {
			params.push(`${k}="${quoteString(v)}"`);
		}
	}
	return `DPoP ${params.join(", ")}`;
}

export interface ProblemResponseExtras {
	wwwAuthExtras?: Record<string, string>;
	extraHeaders?: Record<string, string>;
}

export function problemResponse(problem: ProblemDetail, extras?: ProblemResponseExtras): Response {
	let body: string;
	let status: number;
	try {
		body = JSON.stringify(problem);
		status = clampHttpStatus(problem.status);
	} catch {
		body = '{"title":"Internal Server Error","status":500}';
		status = 500;
	}
	const mergedAuthExtras = { ...problem.wwwAuthExtras, ...extras?.wwwAuthExtras };
	const headers: Record<string, string> = {
		"Content-Type": PROBLEM_CONTENT_TYPE,
		"WWW-Authenticate": wwwAuthenticateHeader(
			problem.wwwAuthError,
			Object.keys(mergedAuthExtras).length > 0 ? mergedAuthExtras : undefined,
		),
		...problem.additionalHeaders,
		...extras?.extraHeaders,
	};
	return new Response(body, { status, headers });
}

/** Thrown by verification helpers; carries the ProblemDetail that should be sent to the client. */
export class DPoPProofError extends Error {
	readonly problem: ProblemDetail;

	constructor(problem: ProblemDetail) {
		// Use detail (specific) rather than title (generic) so error.message is
		// informative for logs and `toThrow(/specific/)` matches in tests.
		super(problem.detail);
		this.name = "DPoPProofError";
		this.problem = problem;
	}
}

/** Strip control characters (CR, LF, ESC, NUL, C1 range) and cap length.
 *  `invalidProof` detail is built from attacker-controlled proof claims (alg,
 *  typ, htm, htu) and is echoed in JSON response bodies AND often in operator
 *  logs verbatim. Sanitization prevents log/terminal injection (CRLF log
 *  forging, ANSI escape spoofing). */
function sanitizeDetail(detail: string): string {
	// biome-ignore lint/suspicious/noControlCharactersInRegex: deliberate stripping of control chars.
	const cleaned = detail.replace(/[\x00-\x1F\x7F-\x9F]/g, "");
	const MAX_DETAIL_LEN = 256;
	return cleaned.length > MAX_DETAIL_LEN ? `${cleaned.slice(0, MAX_DETAIL_LEN)}…` : cleaned;
}

export const DPoPErrors = {
	invalidProof(detail: string): ProblemDetail {
		return {
			type: `${BASE_URL}/invalid-dpop-proof`,
			title: "Invalid DPoP proof",
			status: 401,
			detail: sanitizeDetail(detail),
			code: "INVALID_DPOP_PROOF",
			wwwAuthError: "invalid_dpop_proof",
		};
	},
	missingAccessToken(): ProblemDetail {
		return {
			type: `${BASE_URL}/missing-access-token`,
			title: "Access token is required",
			status: 401,
			detail: "Authorization: DPoP <token> header is required",
			code: "MISSING_ACCESS_TOKEN",
			wwwAuthError: "invalid_token",
		};
	},
	athMismatch(): ProblemDetail {
		return {
			type: `${BASE_URL}/ath-mismatch`,
			title: "Access token hash mismatch",
			status: 401,
			detail: "The DPoP proof's ath claim does not match the access token",
			code: "ATH_MISMATCH",
			wwwAuthError: "invalid_token",
		};
	},
	jtiReplay(): ProblemDetail {
		return {
			type: `${BASE_URL}/jti-replay`,
			title: "DPoP proof replayed",
			status: 401,
			detail: "The jti has been used within the replay window",
			code: "JTI_REPLAY",
			wwwAuthError: "invalid_dpop_proof",
		};
	},
	useNonce(freshNonce: string): ProblemDetail {
		return {
			type: `${BASE_URL}/use-nonce`,
			title: "DPoP nonce required",
			status: 401,
			detail: "Resource server requires a server-issued nonce in the DPoP proof",
			code: "USE_NONCE",
			wwwAuthError: "use_dpop_nonce",
			wwwAuthExtras: { nonce: freshNonce },
			additionalHeaders: { "DPoP-Nonce": freshNonce },
		};
	},
} as const;
