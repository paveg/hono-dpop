import { bench, describe } from "vitest";
import { type JwsAlgorithm, type PublicJwk, jwkThumbprint } from "../src/jwk.js";
import { exportPublicJwk, generateKeyPair } from "../tests/helpers.js";

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
const jwks = new Map<JwsAlgorithm, PublicJwk>();
for (const alg of ALGORITHMS) {
	const kp = await generateKeyPair(alg);
	jwks.set(alg, await exportPublicJwk(kp.publicKey));
}

describe("jwkThumbprint", () => {
	for (const alg of ALGORITHMS) {
		const jwk = jwks.get(alg);
		if (!jwk) throw new Error(`jwk for ${alg} not initialized`);
		bench(alg, async () => {
			await jwkThumbprint(jwk);
		});
	}
});
