export type DPoPErrorCode =
	| "INVALID_DPOP_PROOF"
	| "MISSING_ACCESS_TOKEN"
	| "ATH_MISMATCH"
	| "JTI_REPLAY";

export interface ProblemDetail {
	type: string;
	title: string;
	status: number;
	detail: string;
	code: DPoPErrorCode;
	/** Value for the `error` parameter of the WWW-Authenticate: DPoP header (RFC 9449 §7.1). */
	wwwAuthError: string;
}

/** Clamp HTTP status to 200-599 integer range; returns 500 for out-of-range or non-integer values. */
export function clampHttpStatus(status: number): number {
	return Number.isInteger(status) && status >= 200 && status <= 599 ? status : 500;
}

const PROBLEM_CONTENT_TYPE = "application/problem+json; charset=utf-8";
const BASE_URL = "https://hono-dpop.dev/errors";

/** Build an `WWW-Authenticate: DPoP error="...", key="value", ...` header value. */
export function wwwAuthenticateHeader(
	wwwAuthError: string,
	extras?: Record<string, string>,
): string {
	const params: string[] = [`error="${wwwAuthError}"`];
	if (extras) {
		for (const [k, v] of Object.entries(extras)) {
			params.push(`${k}="${v.replace(/"/g, '\\"')}"`);
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
	const headers: Record<string, string> = {
		"Content-Type": PROBLEM_CONTENT_TYPE,
		"WWW-Authenticate": wwwAuthenticateHeader(problem.wwwAuthError, extras?.wwwAuthExtras),
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

export const DPoPErrors = {
	invalidProof(detail: string): ProblemDetail {
		return {
			type: `${BASE_URL}/invalid-dpop-proof`,
			title: "Invalid DPoP proof",
			status: 401,
			detail,
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
} as const;
