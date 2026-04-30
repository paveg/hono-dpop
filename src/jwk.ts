import { base64urlDecode, base64urlEncode } from "./base64url.js";

export type JwsAlgorithm =
	| "ES256"
	| "ES384"
	| "ES512"
	| "RS256"
	| "RS384"
	| "RS512"
	| "PS256"
	| "PS384"
	| "PS512"
	| "EdDSA"
	| "Ed25519";

export const SUPPORTED_ALGORITHMS = [
	"ES256",
	"ES384",
	"ES512",
	"RS256",
	"RS384",
	"RS512",
	"PS256",
	"PS384",
	"PS512",
	// `EdDSA` is the RFC 8037 / RFC 9449 identifier. `Ed25519` is the more
	// specific identifier introduced by RFC 9758 ("Fully-Specified Algorithms
	// for JOSE and COSE", 2025) — same crypto, different alg string. Verifiers
	// should accept both for forward compatibility.
	"EdDSA",
	"Ed25519",
] as const satisfies readonly JwsAlgorithm[];

export interface EcPublicJwk {
	kty: "EC";
	crv: "P-256" | "P-384" | "P-521";
	x: string;
	y: string;
	[k: string]: unknown;
}

export interface RsaPublicJwk {
	kty: "RSA";
	n: string;
	e: string;
	[k: string]: unknown;
}

export interface OkpPublicJwk {
	kty: "OKP";
	crv: "Ed25519";
	x: string;
	[k: string]: unknown;
}

export type PublicJwk = EcPublicJwk | RsaPublicJwk | OkpPublicJwk;

// JWK private fields per RFC 7517/7518 — proof MUST carry only the public key.
const PRIVATE_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

export function assertPublicJwk(jwk: unknown): asserts jwk is PublicJwk {
	if (!jwk || typeof jwk !== "object") {
		throw new TypeError("jwk must be an object");
	}
	const j = jwk as Record<string, unknown>;
	// Use own-property check so a polluted Object.prototype cannot cause
	// false rejection of an otherwise valid public jwk.
	for (const f of PRIVATE_FIELDS) {
		if (Object.prototype.hasOwnProperty.call(j, f)) {
			throw new TypeError(`jwk must not contain private field "${f}"`);
		}
	}
	switch (j.kty) {
		case "EC":
			if (typeof j.crv !== "string" || !["P-256", "P-384", "P-521"].includes(j.crv)) {
				throw new TypeError("EC jwk has unsupported crv");
			}
			if (typeof j.x !== "string" || typeof j.y !== "string") {
				throw new TypeError("EC jwk requires x and y");
			}
			return;
		case "RSA": {
			if (typeof j.n !== "string" || typeof j.e !== "string") {
				throw new TypeError("RSA jwk requires n and e");
			}
			let nBytes: Uint8Array;
			try {
				nBytes = base64urlDecode(j.n);
			} catch {
				throw new TypeError("RSA jwk has malformed n (not valid base64url)");
			}
			// RSA modulus length policy:
			//   < 256 bytes (2048 bits): cryptographically weak — reject.
			//   > 512 bytes (4096 bits): excessive — DoS amplification via slow verify.
			if (nBytes.length < 256) {
				throw new TypeError(
					`RSA jwk modulus must be at least 2048 bits; got ${nBytes.length * 8} bits`,
				);
			}
			if (nBytes.length > 512) {
				throw new TypeError(
					`RSA jwk modulus must not exceed 4096 bits; got ${nBytes.length * 8} bits`,
				);
			}
			return;
		}
		case "OKP":
			if (j.crv !== "Ed25519") {
				throw new TypeError("OKP jwk only supports Ed25519");
			}
			if (typeof j.x !== "string") {
				throw new TypeError("OKP jwk requires x");
			}
			return;
		default:
			throw new TypeError(`unsupported kty: ${String(j.kty)}`);
	}
}

const encoder = new TextEncoder();

/**
 * RFC 7638 JWK Thumbprint: canonical JSON of required members in lex order,
 * SHA-256, base64url (no padding).
 */
export async function jwkThumbprint(jwk: PublicJwk): Promise<string> {
	let canonical: string;
	switch (jwk.kty) {
		case "EC":
			canonical = JSON.stringify({ crv: jwk.crv, kty: "EC", x: jwk.x, y: jwk.y });
			break;
		case "RSA":
			canonical = JSON.stringify({ e: jwk.e, kty: "RSA", n: jwk.n });
			break;
		case "OKP":
			canonical = JSON.stringify({ crv: jwk.crv, kty: "OKP", x: jwk.x });
			break;
	}
	const digest = await crypto.subtle.digest("SHA-256", encoder.encode(canonical));
	return base64urlEncode(new Uint8Array(digest));
}

interface AlgorithmDescriptor {
	importParams: AlgorithmIdentifier | EcKeyImportParams | RsaHashedImportParams;
	verifyParams: AlgorithmIdentifier | EcdsaParams | RsaPssParams;
}

const ALG: Record<JwsAlgorithm, AlgorithmDescriptor> = {
	ES256: {
		importParams: { name: "ECDSA", namedCurve: "P-256" },
		verifyParams: { name: "ECDSA", hash: "SHA-256" },
	},
	ES384: {
		importParams: { name: "ECDSA", namedCurve: "P-384" },
		verifyParams: { name: "ECDSA", hash: "SHA-384" },
	},
	ES512: {
		importParams: { name: "ECDSA", namedCurve: "P-521" },
		verifyParams: { name: "ECDSA", hash: "SHA-512" },
	},
	RS256: {
		importParams: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
		verifyParams: { name: "RSASSA-PKCS1-v1_5" },
	},
	RS384: {
		importParams: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
		verifyParams: { name: "RSASSA-PKCS1-v1_5" },
	},
	RS512: {
		importParams: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
		verifyParams: { name: "RSASSA-PKCS1-v1_5" },
	},
	PS256: {
		importParams: { name: "RSA-PSS", hash: "SHA-256" },
		verifyParams: { name: "RSA-PSS", saltLength: 32 },
	},
	PS384: {
		importParams: { name: "RSA-PSS", hash: "SHA-384" },
		verifyParams: { name: "RSA-PSS", saltLength: 48 },
	},
	PS512: {
		importParams: { name: "RSA-PSS", hash: "SHA-512" },
		verifyParams: { name: "RSA-PSS", saltLength: 64 },
	},
	EdDSA: {
		importParams: { name: "Ed25519" },
		verifyParams: { name: "Ed25519" },
	},
	Ed25519: {
		importParams: { name: "Ed25519" },
		verifyParams: { name: "Ed25519" },
	},
};

export function isSupportedAlgorithm(alg: string): alg is JwsAlgorithm {
	return (SUPPORTED_ALGORITHMS as readonly string[]).includes(alg);
}

/**
 * Validates that a JWK's key type matches the declared `alg`. Catches the
 * "alg confusion" class of attack where a client claims ES256 but supplies an RSA jwk.
 */
export function assertAlgMatchesJwk(alg: JwsAlgorithm, jwk: PublicJwk): void {
	if (alg.startsWith("ES")) {
		if (jwk.kty !== "EC") throw new TypeError(`alg ${alg} requires EC jwk`);
		const expected = alg === "ES256" ? "P-256" : alg === "ES384" ? "P-384" : "P-521";
		if (jwk.crv !== expected) {
			throw new TypeError(`alg ${alg} requires crv ${expected}`);
		}
		return;
	}
	if (alg.startsWith("RS") || alg.startsWith("PS")) {
		if (jwk.kty !== "RSA") throw new TypeError(`alg ${alg} requires RSA jwk`);
		return;
	}
	// EdDSA (RFC 8037) and Ed25519 (RFC 9758) — both use the same Ed25519 crypto.
	if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
		throw new TypeError(`alg ${alg} requires OKP jwk with crv Ed25519`);
	}
}

export async function importPublicJwk(jwk: PublicJwk, alg: JwsAlgorithm): Promise<CryptoKey> {
	const desc = ALG[alg];
	return crypto.subtle.importKey("jwk", jwk as JsonWebKey, desc.importParams, false, ["verify"]);
}

export function verifyParamsFor(
	alg: JwsAlgorithm,
): AlgorithmIdentifier | EcdsaParams | RsaPssParams {
	return ALG[alg].verifyParams;
}
