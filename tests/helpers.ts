import { base64urlEncode } from "../src/base64url.js";
import type { JwsAlgorithm, PublicJwk } from "../src/jwk.js";

export interface KeyPair {
	publicKey: CryptoKey;
	privateKey: CryptoKey;
}

const ENCODER = new TextEncoder();
const RSA_EXPONENT = new Uint8Array([1, 0, 1]);

function generateParams(
	alg: JwsAlgorithm,
): EcKeyGenParams | RsaHashedKeyGenParams | { name: string } {
	switch (alg) {
		case "ES256":
			return { name: "ECDSA", namedCurve: "P-256" };
		case "ES384":
			return { name: "ECDSA", namedCurve: "P-384" };
		case "ES512":
			return { name: "ECDSA", namedCurve: "P-521" };
		case "RS256":
			return {
				name: "RSASSA-PKCS1-v1_5",
				modulusLength: 2048,
				publicExponent: RSA_EXPONENT,
				hash: "SHA-256",
			};
		case "RS384":
			return {
				name: "RSASSA-PKCS1-v1_5",
				modulusLength: 2048,
				publicExponent: RSA_EXPONENT,
				hash: "SHA-384",
			};
		case "RS512":
			return {
				name: "RSASSA-PKCS1-v1_5",
				modulusLength: 2048,
				publicExponent: RSA_EXPONENT,
				hash: "SHA-512",
			};
		case "PS256":
			return {
				name: "RSA-PSS",
				modulusLength: 2048,
				publicExponent: RSA_EXPONENT,
				hash: "SHA-256",
			};
		case "PS384":
			return {
				name: "RSA-PSS",
				modulusLength: 2048,
				publicExponent: RSA_EXPONENT,
				hash: "SHA-384",
			};
		case "PS512":
			return {
				name: "RSA-PSS",
				modulusLength: 2048,
				publicExponent: RSA_EXPONENT,
				hash: "SHA-512",
			};
		case "EdDSA":
			return { name: "Ed25519" };
	}
}

function signParams(alg: JwsAlgorithm): AlgorithmIdentifier | EcdsaParams | RsaPssParams {
	switch (alg) {
		case "ES256":
			return { name: "ECDSA", hash: "SHA-256" };
		case "ES384":
			return { name: "ECDSA", hash: "SHA-384" };
		case "ES512":
			return { name: "ECDSA", hash: "SHA-512" };
		case "RS256":
		case "RS384":
		case "RS512":
			return "RSASSA-PKCS1-v1_5";
		case "PS256":
			return { name: "RSA-PSS", saltLength: 32 };
		case "PS384":
			return { name: "RSA-PSS", saltLength: 48 };
		case "PS512":
			return { name: "RSA-PSS", saltLength: 64 };
		case "EdDSA":
			return "Ed25519";
	}
}

export async function generateKeyPair(alg: JwsAlgorithm): Promise<KeyPair> {
	return (await crypto.subtle.generateKey(generateParams(alg), true, [
		"sign",
		"verify",
	])) as KeyPair;
}

export async function exportPublicJwk(key: CryptoKey): Promise<PublicJwk> {
	const jwk = (await crypto.subtle.exportKey("jwk", key)) as Record<string, unknown>;
	for (const f of ["alg", "ext", "key_ops", "use"]) delete jwk[f];
	return jwk as unknown as PublicJwk;
}

export interface ProofPayload {
	jti: string;
	htm: string;
	htu: string;
	iat: number;
	ath?: string;
	nonce?: string;
}

export interface SignProofOptions {
	alg: JwsAlgorithm;
	keyPair: KeyPair;
	payload: ProofPayload;
	typ?: string;
	jwk?: unknown;
}

export async function signProof(opts: SignProofOptions): Promise<string> {
	const jwk = opts.jwk ?? (await exportPublicJwk(opts.keyPair.publicKey));
	const headerObj = { typ: opts.typ ?? "dpop+jwt", alg: opts.alg, jwk };
	const headerB64 = base64urlEncode(JSON.stringify(headerObj));
	const payloadB64 = base64urlEncode(JSON.stringify(opts.payload));
	const signingInput = ENCODER.encode(`${headerB64}.${payloadB64}`);
	const sig = await crypto.subtle.sign(signParams(opts.alg), opts.keyPair.privateKey, signingInput);
	return `${headerB64}.${payloadB64}.${base64urlEncode(new Uint8Array(sig))}`;
}

export function nowSeconds(): number {
	return Math.floor(Date.now() / 1000);
}

export function freshJti(): string {
	return crypto.randomUUID();
}
