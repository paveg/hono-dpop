import { bench, describe } from "vitest";
import type { JwsAlgorithm } from "../src/jwk.js";
import { parseProof } from "../src/verify.js";
import { freshJti, generateKeyPair, nowSeconds, signProof } from "../tests/helpers.js";

// Top-level await: vitest's benchmark runner does not invoke beforeAll/beforeEach hooks,
// so async setup must complete before bench() registration.
const ALLOWED = new Set<JwsAlgorithm>(["ES256"]);
const keyPair = await generateKeyPair("ES256");
const proof = await signProof({
	alg: "ES256",
	keyPair,
	payload: {
		jti: freshJti(),
		htm: "POST",
		htu: "https://api.example.com/resource",
		iat: nowSeconds(),
	},
});

describe("parseProof", () => {
	bench("typical ES256 proof", () => {
		parseProof(proof, ALLOWED);
	});
});
