import type { Context, Env } from "hono";
import type { ProblemDetail } from "./errors.js";
import type { JwsAlgorithm, PublicJwk } from "./jwk.js";
import type { DPoPNonceStore } from "./stores/types.js";

export interface DPoPVerifiedProof {
	/** RFC 7638 SHA-256 JWK thumbprint of the proof's public key (base64url, no padding). */
	jkt: string;
	jti: string;
	jwk: PublicJwk;
	htm: string;
	/** Normalized URL (query and fragment stripped). */
	htu: string;
	iat: number;
	ath?: string;
	/** Raw `DPoP` header value. */
	raw: string;
}

export interface DPoPEnv extends Env {
	Variables: {
		dpop: DPoPVerifiedProof | undefined;
	};
}

export interface DPoPOptions {
	nonceStore: DPoPNonceStore;
	algorithms?: readonly JwsAlgorithm[];
	/** Allowed clock skew on `iat` in seconds (default: 60). */
	iatTolerance?: number;
	/** How long a `jti` is remembered, in milliseconds (default: 5 minutes). */
	jtiTtl?: number;
	/**
	 * Override request URL extraction. Default: `c.req.url`.
	 * Use this when behind a reverse proxy that rewrites the host or scheme.
	 */
	getRequestUrl?: (c: Context) => string | Promise<string>;
	/**
	 * Override access-token extraction. Default: parses `Authorization: DPoP <token>`.
	 * Returning `undefined` means no access token is present (skip ath verification).
	 */
	getAccessToken?: (c: Context) => string | undefined | Promise<string | undefined>;
	/** Reject with 401 when access token is missing (default: false). */
	requireAccessToken?: boolean;
	/** Custom error response. Default: RFC 9457 Problem Details + RFC 9449 WWW-Authenticate. */
	onError?: (error: ProblemDetail, c: Context) => Response | Promise<Response>;
}
