import { bench, describe } from "vitest";
import type { JwsAlgorithm } from "../src/jwk.js";
import { type ParsedProof, parseProof, verifyProofSignature } from "../src/verify.js";
import { freshJti, generateKeyPair, nowSeconds, signProof } from "../tests/helpers.js";

const ALGORITHMS = [
	"ES256",
	"ES384",
	"ES512",
	"RS256",
	"PS256",
	"EdDSA",
] as const satisfies readonly JwsAlgorithm[];

// Top-level await: vitest's benchmark runner does not invoke beforeAll/beforeEach hooks,
// so async setup must complete before bench() registration.
const allowed = new Set<JwsAlgorithm>(ALGORITHMS);
const proofs = new Map<JwsAlgorithm, ParsedProof>();
for (const alg of ALGORITHMS) {
	const keyPair = await generateKeyPair(alg);
	const jwt = await signProof({
		alg,
		keyPair,
		payload: {
			jti: freshJti(),
			htm: "POST",
			htu: "https://api.example.com/resource",
			iat: nowSeconds(),
		},
	});
	proofs.set(alg, parseProof(jwt, allowed));
}

describe("verifyProofSignature", () => {
	for (const alg of ALGORITHMS) {
		const parsed = proofs.get(alg);
		if (!parsed) throw new Error(`proof for ${alg} not initialized`);
		bench(alg, async () => {
			await verifyProofSignature(parsed);
		});
	}
});
