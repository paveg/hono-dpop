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
import {
	isSupportedAlgorithm,
	type JwsAlgorithm,
	jwkThumbprint,
	SUPPORTED_ALGORITHMS,
} from "./jwk.js";
import type { DPoPEnv, DPoPOptions, DPoPVerifiedProof } from "./types.js";
import {
	computeAth,
	normalizeHtu,
	type ParsedProof,
	parseProof,
	timingSafeEqual,
	verifyProofClaims,
	verifyProofSignature,
} from "./verify.js";

const DEFAULT_IAT_TOLERANCE = 60;
const DEFAULT_JTI_TTL_MS = 5 * 60_000;
const DEFAULT_MAX_PROOF_SIZE = 8192;
const DEFAULT_MAX_ACCESS_TOKEN_SIZE = 4096;
const DPOP_HEADER = "DPoP";
const DPOP_NONCE_HEADER = "DPoP-Nonce";
const AUTHORIZATION_HEADER = "Authorization";
// RFC 7235 §2.1: scheme names are case-insensitive. We compare against the
// lowercase form so `DPoP`, `dpop`, and `Dpop` all match.
const DPOP_AUTH_SCHEME = "dpop";

const sizingEncoder = new TextEncoder();

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
		maxProofSize = DEFAULT_MAX_PROOF_SIZE,
		maxAccessTokenSize = DEFAULT_MAX_ACCESS_TOKEN_SIZE,
		clock = Date.now,
		htuComparison = "strict",
		allowFutureIat = false,
	} = options;

	// Fail fast on unsupported algs at factory time. Without this, a TypeScript
	// escape hatch (`["EvilAlg" as any]`) would survive factory creation and
	// only surface at request time as "unsupported alg", which is harder to
	// catch in development and lets a misconfiguration ship to production.
	for (const alg of algorithms) {
		if (!isSupportedAlgorithm(alg)) {
			throw new TypeError(
				`Unsupported algorithm in algorithms option: ${String(alg)}. ` +
					`Allowed: ${SUPPORTED_ALGORITHMS.join(", ")}`,
			);
		}
	}

	const allowed = new Set<JwsAlgorithm>(algorithms);
	const algsHint = algorithms.join(" ");

	return createMiddleware<DPoPEnv>(async (c, next) => {
		const errorResponse = (problem: ProblemDetail) =>
			respondWithProblem(problem, c, onError, algsHint);

		const proofHeader = c.req.header(DPOP_HEADER);
		if (!proofHeader) {
			return errorResponse(DPoPErrors.invalidProof("DPoP header is missing"));
		}

		// Size shield: bound the input before any decode/parse work.
		if (sizingEncoder.encode(proofHeader).length > maxProofSize) {
			return errorResponse(DPoPErrors.invalidProof(`DPoP header exceeds ${maxProofSize} bytes`));
		}

		// RFC 9449 §4.3: exactly one DPoP header. The Headers API joins multiple
		// same-name headers with ", "; DPoP proofs are base64url-only and never
		// contain commas, so a comma-space sequence is a positive signal of
		// header smuggling.
		if (proofHeader.includes(", ")) {
			return errorResponse(DPoPErrors.invalidProof("multiple DPoP headers are not allowed"));
		}

		// Resolve and size-check the access token BEFORE expensive crypto work.
		// An attacker with their own valid keypair could otherwise force the
		// server to TextEncoder.encode + crypto.subtle.digest a multi-megabyte
		// `Authorization: DPoP ...` value during ath verification before being
		// rejected. Bounded DoS — fail fast on size first.
		const accessToken = await resolveAccessToken(c, getAccessToken);
		if (
			accessToken !== undefined &&
			sizingEncoder.encode(accessToken).length > maxAccessTokenSize
		) {
			return errorResponse(
				DPoPErrors.invalidProof(`access token exceeds ${maxAccessTokenSize} bytes`),
			);
		}

		let parsed: ParsedProof;
		try {
			parsed = parseProof(proofHeader, allowed);

			const requestUrl = getRequestUrl ? await getRequestUrl(c) : c.req.url;
			verifyProofClaims(parsed, {
				htm: c.req.method,
				htu: requestUrl,
				now: Math.floor(clock() / 1000),
				iatTolerance,
				htuComparison,
				allowFutureIat,
			});

			await verifyProofSignature(parsed);
		} catch (err) {
			if (err instanceof DPoPProofError) return errorResponse(err.problem);
			throw err;
		}

		// Lazy + memoized issueNonce: shared between the use_dpop_nonce error
		// path and the success-path echo so a request triggers at most one
		// provider RPC. Matters for shared-store providers (Redis, KV) where
		// each issueNonce() is a network round-trip.
		let cachedNonce: string | undefined;
		const issueNonceOnce = nonceProvider
			? async () => {
					if (cachedNonce === undefined) cachedNonce = await nonceProvider.issueNonce(c);
					return cachedNonce;
				}
			: undefined;

		// Nonce challenge (RFC 9449 §8). Run after sig verification so that we
		// only mint nonces for cryptographically valid proofs — prevents nonce
		// flooding from unauthenticated clients.
		if (nonceProvider && issueNonceOnce) {
			const nonceClaim = parsed.payload.nonce;
			// Always invoke isValid so the request-handling time does not depend on
			// whether the nonce claim is present. Distinguishing "missing nonce" from
			// "invalid nonce" by the absence of the provider RPC is a small timing
			// oracle for shared-store providers (Redis, KV) — close it. Provider
			// implementations are expected to treat the empty string as invalid.
			const candidate = typeof nonceClaim === "string" ? nonceClaim : "";
			const nonceOk = await nonceProvider.isValid(candidate, c);
			if (!nonceOk) {
				return errorResponse(DPoPErrors.useNonce(await issueNonceOnce()));
			}
		}

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
			htu: normalizeHtu(parsed.payload.htu, htuComparison),
			iat: parsed.payload.iat,
			ath: parsed.payload.ath,
			raw: parsed.raw,
		};
		c.set("dpop", verified);

		await next();

		// Echo the current nonce on success so clients learn it without an extra
		// challenge round-trip (RFC 9449 §8 recommendation). Reuses the cached
		// value if the use_dpop_nonce path already minted one (it didn't here,
		// since we reached success — but the closure is still memoized).
		if (issueNonceOnce) {
			c.res.headers.set(DPOP_NONCE_HEADER, await issueNonceOnce());
		}
	});
}

async function resolveAccessToken(
	c: Context,
	override?: DPoPOptions["getAccessToken"],
): Promise<string | undefined> {
	if (override) return override(c);
	const auth = c.req.header(AUTHORIZATION_HEADER);
	if (!auth) return undefined;
	// RFC 7235 §2.1: authentication scheme names are case-insensitive. Match on
	// the lowercase scheme prefix but slice from the original to preserve the
	// token bytes (the token after the scheme is opaque and case-sensitive).
	const space = auth.indexOf(" ");
	if (space < 0) return undefined;
	if (auth.slice(0, space).toLowerCase() !== DPOP_AUTH_SCHEME) return undefined;
	// trim() handles the "DPoP   token" (extra interior whitespace) case.
	// A whitespace-only-after-the-scheme token (e.g. "DPoP    ") cannot reach
	// this line on the platforms we target: the WHATWG fetch Headers API trims
	// trailing whitespace from header values before middleware sees them, so
	// `auth.indexOf(" ")` returns -1 and we exit earlier. The trim here is a
	// belt-and-braces for proxies that preserve interior whitespace before the
	// first non-space token byte.
	return auth.slice(space + 1).trim();
}

async function respondWithProblem(
	problem: ProblemDetail,
	c: Context,
	onError: DPoPOptions["onError"] | undefined,
	algsHint: string,
): Promise<Response> {
	// Surface supported algs on every 401 — RFC 9449 §7.1 lets clients
	// discover the server's algorithm preferences without trial-and-error.
	const enriched: ProblemDetail = {
		...problem,
		wwwAuthExtras: { ...problem.wwwAuthExtras, algs: algsHint },
	};
	if (onError) return onError(enriched, c);
	const pd = await getHonoProblemDetails();
	if (pd) {
		const response = pd
			.problemDetails({
				type: enriched.type,
				title: enriched.title,
				status: enriched.status,
				detail: enriched.detail,
				extensions: { code: enriched.code },
			})
			.getResponse();
		response.headers.set(
			"WWW-Authenticate",
			wwwAuthenticateHeader(enriched.wwwAuthError, enriched.wwwAuthExtras),
		);
		if (enriched.additionalHeaders) {
			for (const [k, v] of Object.entries(enriched.additionalHeaders)) {
				response.headers.set(k, v);
			}
		}
		return response;
	}
	return problemResponse(enriched);
}
