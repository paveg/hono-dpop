import type { NonceProvider } from "./types.js";

export interface MemoryNonceProviderOptions {
	/** Rotate the nonce after this many milliseconds (default: 5 minutes). */
	rotateAfter?: number;
	/** Accept the previous nonce in addition to the current one (default: true). */
	retainPrevious?: boolean;
	/** Override clock — function returning milliseconds epoch. Default: `Date.now`. */
	clock?: () => number;
}

const DEFAULT_ROTATE_AFTER = 5 * 60_000;

/**
 * In-process server nonce provider per RFC 9449 §8. Generates a UUID nonce that
 * rotates every `rotateAfter` milliseconds. By default, the previous nonce is also
 * accepted to absorb the natural race between rotation and an in-flight client request.
 *
 * Stateful and process-local — for multi-instance deployments, implement `NonceProvider`
 * against a shared store (Redis, Cloudflare KV, etc.).
 */
export function memoryNonceProvider(options: MemoryNonceProviderOptions = {}): NonceProvider {
	const rotateAfter = options.rotateAfter ?? DEFAULT_ROTATE_AFTER;
	const retainPrevious = options.retainPrevious ?? true;
	const clock = options.clock ?? Date.now;

	let current = crypto.randomUUID();
	let previous: string | undefined;
	let rotatedAt = clock();

	const rotateIfDue = (): void => {
		const now = clock();
		if (now - rotatedAt < rotateAfter) return;
		previous = current;
		current = crypto.randomUUID();
		rotatedAt = now;
	};

	return {
		issueNonce() {
			rotateIfDue();
			return current;
		},
		isValid(nonce) {
			rotateIfDue();
			if (nonce === current) return true;
			if (retainPrevious && previous !== undefined && nonce === previous) return true;
			return false;
		},
	};
}
