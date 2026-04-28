import type { Context } from "hono";
import { createMiddleware } from "hono/factory";
import { getHonoProblemDetails } from "./compat.js";
import { DPoPErrors, DPoPProofError, type ProblemDetail, problemResponse } from "./errors.js";
import { type JwsAlgorithm, SUPPORTED_ALGORITHMS, jwkThumbprint } from "./jwk.js";
import type { DPoPEnv, DPoPOptions, DPoPVerifiedProof } from "./types.js";
import {
	type ParsedProof,
	computeAth,
	normalizeHtu,
	parseProof,
	timingSafeEqual,
	verifyProofClaims,
	verifyProofSignature,
} from "./verify.js";

const DEFAULT_IAT_TOLERANCE = 60;
const DEFAULT_JTI_TTL_MS = 5 * 60_000;
const DPOP_HEADER = "DPoP";
const AUTHORIZATION_HEADER = "Authorization";
const DPOP_AUTH_PREFIX = "DPoP ";

export function dpop(options: DPoPOptions) {
	const {
		nonceStore,
		algorithms = SUPPORTED_ALGORITHMS,
		iatTolerance = DEFAULT_IAT_TOLERANCE,
		jtiTtl = DEFAULT_JTI_TTL_MS,
		getRequestUrl,
		getAccessToken,
		requireAccessToken = false,
		onError,
	} = options;

	const allowed = new Set<JwsAlgorithm>(algorithms);

	return createMiddleware<DPoPEnv>(async (c, next) => {
		const errorResponse = (problem: ProblemDetail) => respondWithProblem(problem, c, onError);

		const proofHeader = c.req.header(DPOP_HEADER);
		if (!proofHeader) {
			return errorResponse(DPoPErrors.invalidProof("DPoP header is missing"));
		}

		let parsed: ParsedProof;
		try {
			parsed = parseProof(proofHeader, allowed);

			const requestUrl = getRequestUrl ? await getRequestUrl(c) : c.req.url;
			verifyProofClaims(parsed, {
				htm: c.req.method,
				htu: requestUrl,
				now: Math.floor(Date.now() / 1000),
				iatTolerance,
			});

			await verifyProofSignature(parsed);
		} catch (err) {
			if (err instanceof DPoPProofError) return errorResponse(err.problem);
			throw err;
		}

		const accessToken = await resolveAccessToken(c, getAccessToken);
		if (requireAccessToken && !accessToken) {
			return errorResponse(DPoPErrors.missingAccessToken());
		}
		if (accessToken !== undefined) {
			if (typeof parsed.payload.ath !== "string") {
				return errorResponse(
					DPoPErrors.invalidProof("ath claim is required when an access token is presented"),
				);
			}
			const expected = await computeAth(accessToken);
			if (!timingSafeEqual(expected, parsed.payload.ath)) {
				return errorResponse(DPoPErrors.athMismatch());
			}
		}

		// jti replay check is last so leak-free: only valid proofs reach the store
		const expiresAt = parsed.payload.iat * 1000 + jtiTtl;
		const fresh = await nonceStore.check(parsed.payload.jti, expiresAt);
		if (!fresh) {
			return errorResponse(DPoPErrors.jtiReplay());
		}

		const jkt = await jwkThumbprint(parsed.header.jwk);
		const verified: DPoPVerifiedProof = {
			jkt,
			jti: parsed.payload.jti,
			jwk: parsed.header.jwk,
			htm: parsed.payload.htm,
			htu: normalizeHtu(parsed.payload.htu),
			iat: parsed.payload.iat,
			ath: parsed.payload.ath,
			raw: parsed.raw,
		};
		c.set("dpop", verified);
		await next();
	});
}

async function resolveAccessToken(
	c: Context,
	override?: DPoPOptions["getAccessToken"],
): Promise<string | undefined> {
	if (override) return override(c);
	const auth = c.req.header(AUTHORIZATION_HEADER);
	if (!auth || !auth.startsWith(DPOP_AUTH_PREFIX)) return undefined;
	// HTTP header value normalization strips trailing whitespace, so a bare "DPoP " never
	// reaches the slice — the !startsWith check above already rejects it. The trim() handles
	// the "DPoP   token" (extra interior whitespace) case. Empty strings further downstream
	// are caught by `!accessToken` in the requireAccessToken check.
	return auth.slice(DPOP_AUTH_PREFIX.length).trim();
}

async function respondWithProblem(
	problem: ProblemDetail,
	c: Context,
	onError?: DPoPOptions["onError"],
): Promise<Response> {
	if (onError) return onError(problem, c);
	const pd = await getHonoProblemDetails();
	if (pd) {
		const response = pd
			.problemDetails({
				type: problem.type,
				title: problem.title,
				status: problem.status,
				detail: problem.detail,
				extensions: { code: problem.code },
			})
			.getResponse();
		response.headers.set("WWW-Authenticate", `DPoP error="${problem.wwwAuthError}"`);
		return response;
	}
	return problemResponse(problem);
}
