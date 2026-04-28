import type { Context } from "hono";
import { createMiddleware } from "hono/factory";
import { getHonoProblemDetails } from "./compat.js";
import {
	DPoPErrors,
	DPoPProofError,
	type ProblemDetail,
	problemResponse,
	wwwAuthenticateHeader,
} from "./errors.js";
import { type JwsAlgorithm, SUPPORTED_ALGORITHMS, jwkThumbprint } from "./jwk.js";
import type { NonceProvider } from "./stores/types.js";
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
const DPOP_NONCE_HEADER = "DPoP-Nonce";
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
		nonceProvider,
	} = options;

	const allowed = new Set<JwsAlgorithm>(algorithms);

	return createMiddleware<DPoPEnv>(async (c, next) => {
		const errorResponse = (problem: ProblemDetail) => respondWithProblem(problem, c, onError);

		const proofHeader = c.req.header(DPOP_HEADER);
		if (!proofHeader) {
			return errorResponse(DPoPErrors.invalidProof("DPoP header is missing"));
		}

		// RFC 9449 §4.3: exactly one DPoP header. The Headers API joins multiple
		// same-name headers with ", "; DPoP proofs are base64url-only and never
		// contain commas, so a comma-space sequence is a positive signal of
		// header smuggling.
		if (proofHeader.includes(", ")) {
			return errorResponse(DPoPErrors.invalidProof("multiple DPoP headers are not allowed"));
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

		// Nonce challenge (RFC 9449 §8). Run after sig verification so that we
		// only mint nonces for cryptographically valid proofs — prevents nonce
		// flooding from unauthenticated clients.
		if (nonceProvider) {
			const nonceClaim = parsed.payload.nonce;
			const nonceOk =
				typeof nonceClaim === "string" && (await nonceProvider.isValid(nonceClaim, c));
			if (!nonceOk) {
				return errorResponse(DPoPErrors.useNonce(await nonceProvider.issueNonce(c)));
			}
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

		// Echo the current nonce on success so clients learn it without an extra
		// challenge round-trip (RFC 9449 §8 recommendation).
		if (nonceProvider) {
			await setSuccessNonce(c, nonceProvider);
		}
	});
}

async function setSuccessNonce(c: Context, provider: NonceProvider): Promise<void> {
	c.res.headers.set(DPOP_NONCE_HEADER, await provider.issueNonce(c));
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
		response.headers.set(
			"WWW-Authenticate",
			wwwAuthenticateHeader(problem.wwwAuthError, problem.wwwAuthExtras),
		);
		if (problem.additionalHeaders) {
			for (const [k, v] of Object.entries(problem.additionalHeaders)) {
				response.headers.set(k, v);
			}
		}
		return response;
	}
	return problemResponse(problem);
}
