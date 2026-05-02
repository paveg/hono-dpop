// Type-compat fixture. Exercises every public export across the barrel and
// each subpath so that any d.ts emit drift on a future TypeScript bump
// surfaces here at PR time. Imports come from `dist/` — the post-build
// artifacts that consumers actually receive — and are checked against
// each TS version in the CI `type-compat` matrix.

import type {
	AccessTokenClaimsWithCnf,
	D1DatabaseLike,
	D1PreparedStatementLike,
	D1StoreOptions,
	DPoPEnv,
	DPoPErrorCode,
	DPoPNonceStore,
	DPoPOptions,
	DPoPVerifiedProof,
	DurableObjectStorageLike,
	DurableObjectStoreOptions,
	EcPublicJwk,
	JwsAlgorithm,
	KVNamespaceLike,
	KVStoreOptions,
	MemoryNonceProviderOptions,
	MemoryNonceStore,
	MemoryNonceStoreOptions,
	NonceProvider,
	OkpPublicJwk,
	ProblemDetail,
	ProblemResponseExtras,
	PublicJwk,
	RedisClientLike,
	RedisStoreOptions,
	RsaPublicJwk,
} from "../../dist/index.js";
import {
	assertJktBinding,
	assertPublicJwk,
	clampHttpStatus,
	DPoPErrors,
	DPoPProofError,
	dpop,
	jwkThumbprint,
	memoryNonceProvider,
	problemResponse,
	SUPPORTED_ALGORITHMS,
	verifyJktBinding,
	wwwAuthenticateHeader,
} from "../../dist/index.js";
import { d1Store } from "../../dist/stores/cloudflare-d1.js";
import { kvStore } from "../../dist/stores/cloudflare-kv.js";
import { durableObjectStore } from "../../dist/stores/durable-objects.js";
import { memoryNonceStore } from "../../dist/stores/memory.js";
import { redisStore } from "../../dist/stores/redis.js";

// JWK / algorithm types
const _alg: JwsAlgorithm = "ES256";
const _algs: readonly JwsAlgorithm[] = SUPPORTED_ALGORITHMS;
const _ec: EcPublicJwk = { kty: "EC", crv: "P-256", x: "x", y: "y" };
const _rsa: RsaPublicJwk = { kty: "RSA", n: "n", e: "AQAB" };
const _okp: OkpPublicJwk = { kty: "OKP", crv: "Ed25519", x: "x" };
const _pub: PublicJwk = _ec;

// Error / problem-details types
const _code: DPoPErrorCode = "INVALID_DPOP_PROOF";
const _problem: ProblemDetail = {
	type: "https://example.com/problems/x",
	title: "Bad",
	status: 400,
	detail: "no",
	code: "INVALID_DPOP_PROOF",
	wwwAuthError: "invalid_token",
};
const _extras: ProblemResponseExtras = { extraHeaders: { "X-Foo": "bar" } };

// JKT-binding types
const _claims: AccessTokenClaimsWithCnf = { cnf: { jkt: "abc" } };

// Store option types
const _memOpts: MemoryNonceStoreOptions = { maxSize: 1_000 };
const _redisOpts: RedisStoreOptions = { client: {} as RedisClientLike };
const _kvOpts: KVStoreOptions = { namespace: {} as KVNamespaceLike };
const _d1Opts: D1StoreOptions = { database: {} as D1DatabaseLike };
const _doOpts: DurableObjectStoreOptions = {
	storage: {} as DurableObjectStorageLike,
};
const _provOpts: MemoryNonceProviderOptions = { rotateAfter: 60_000 };
const _stmt: D1PreparedStatementLike = {} as D1PreparedStatementLike;

// Middleware factory + verified-proof type
const _store: MemoryNonceStore = memoryNonceStore(_memOpts);
const _opts: DPoPOptions = { nonceStore: _store };
const _mw = dpop(_opts);
type _Env = DPoPEnv;
type _Verified = DPoPVerifiedProof;

// Store factories — each returns the shared NonceStore interface
const _redis: DPoPNonceStore = redisStore(_redisOpts);
const _kv: DPoPNonceStore = kvStore(_kvOpts);
const _d1: DPoPNonceStore = d1Store(_d1Opts);
const _do: DPoPNonceStore = durableObjectStore(_doOpts);
const _provider: NonceProvider = memoryNonceProvider(_provOpts);

// Helper functions
const _status: number = clampHttpStatus(500);
const _www: string = wwwAuthenticateHeader("invalid_token", { algs: "ES256" });
const _resp = problemResponse(_problem, _extras);
const _problemFromHelper: ProblemDetail = DPoPErrors.invalidProof("nope");
const _err: DPoPProofError = new DPoPProofError(_problem);
const _jkt: Promise<string> = jwkThumbprint(_ec);

// Type guards / asserts
declare const _maybeJwk: unknown;
assertPublicJwk(_maybeJwk);
const _isPub: PublicJwk = _maybeJwk;
assertJktBinding(_claims, "abc");
const _bound: boolean = verifyJktBinding(_claims, "abc");

// Suppress "unused" diagnostics — the goal is type-resolution, not values
void _alg;
void _algs;
void _rsa;
void _okp;
void _pub;
void _code;
void _stmt;
void _mw;
void _redis;
void _kv;
void _d1;
void _do;
void _provider;
void _status;
void _www;
void _resp;
void _problemFromHelper;
void _err;
void _jkt;
void _isPub;
void _bound;
