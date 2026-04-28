// Deno runtime smoke test.
//
// Vitest does not run on Deno, so we only verify that the published bundle
// loads and that the public API constructs without error. Run this *after*
// `pnpm build` from the repo root with:
//
//   deno run --allow-read --allow-env --node-modules-dir=auto \
//     .github/scripts/smoke-deno.ts
//
// The `--node-modules-dir=auto` flag lets Deno resolve the `hono` peer
// dependency through the existing pnpm-managed node_modules tree.

// @ts-nocheck — Deno type-checks against its own libs; we only care about
// runtime behavior here, not Deno-flavored type compatibility.
import { dpop, memoryNonceProvider } from "../../dist/index.js";
import { memoryNonceStore } from "../../dist/stores/memory.js";

const store = memoryNonceStore();
if (typeof store?.check !== "function" || typeof store?.purge !== "function") {
	console.error("FAIL: memoryNonceStore() did not return a store with check/purge");
	Deno.exit(1);
}

const provider = memoryNonceProvider();
if (typeof provider?.issueNonce !== "function" || typeof provider?.isValid !== "function") {
	console.error("FAIL: memoryNonceProvider() did not return a provider with issueNonce/isValid");
	Deno.exit(1);
}

const middleware = dpop({ nonceStore: store });
if (typeof middleware !== "function") {
	console.error("FAIL: dpop() did not return a Hono middleware function");
	Deno.exit(1);
}

console.log("OK: hono-dpop loads and constructs cleanly under Deno");
