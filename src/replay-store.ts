import { AntlionError } from "./errors.js";

/**
 * Where each accepted proof is remembered, so it is accepted once.
 *
 * `addIfAbsent` must check and record in one atomic step: resolve `true` if
 * this call recorded the key, `false` if it was already there. A read
 * followed by a write lets two copies of one proof both through. In Redis
 * that is `SET key 1 NX EX ttlSeconds`; in Postgres, `INSERT ... ON CONFLICT
 * DO NOTHING` on a table whose expired rows you delete on a schedule.
 *
 * Throwing, rejecting, or resolving anything but a boolean refuses the
 * request. Keys are at most 87 characters of base64url and one `:`.
 */
export interface ReplayStore {
	addIfAbsent(key: string, ttlSeconds: number): Promise<boolean>;
}

export interface SingleProcessReplayStoreOptions {
	/**
	 * Required. How many live proofs to hold. Each is held for `maxProofAge`
	 * plus six seconds, so this is your peak accepted requests per second
	 * times that, with room to spare. A full store refuses requests rather
	 * than forget a proof early, because forgetting early is accepting a
	 * replay.
	 */
	maxEntries: number;
	/** Swappable clock in milliseconds, for expiry. Defaults to `Date.now`. */
	now?: () => number;
}

/**
 * A replay store for one process, and for tests.
 *
 * `addIfAbsent` is atomic here because there is no `await` between its check
 * and its write, which holds in one JavaScript process and nowhere else. Two
 * processes with one of these each accept every proof twice. Past one
 * process, use a store shared by all of them.
 */
export class SingleProcessReplayStore implements ReplayStore {
	/** key -> expiry in milliseconds. Map order is insertion order. */
	readonly #entries = new Map<string, number>();
	readonly #maxEntries: number;
	readonly #now: () => number;

	constructor(options: SingleProcessReplayStoreOptions) {
		const { maxEntries, now } = options;
		if (!Number.isInteger(maxEntries) || maxEntries < 1) {
			throw new AntlionError(
				"invalid-options",
				`SingleProcessReplayStore maxEntries must be an integer >= 1, received ${String(maxEntries)}`
			);
		}
		if (now !== undefined && typeof now !== "function") {
			throw new AntlionError("invalid-options", "SingleProcessReplayStore now must be a function");
		}
		this.#maxEntries = maxEntries;
		this.#now = now ?? Date.now;
	}

	/** How many keys are held, expired ones included until they are swept. */
	get size(): number {
		return this.#entries.size;
	}

	async addIfAbsent(key: string, ttlSeconds: number): Promise<boolean> {
		const now = this.#now();
		this.#sweepOldest(now);

		const expiresAt = this.#entries.get(key);
		if (expiresAt !== undefined && now < expiresAt) return false;

		if (expiresAt === undefined && this.#entries.size >= this.#maxEntries) {
			this.#sweepAll(now);
			if (this.#entries.size >= this.#maxEntries) {
				throw new AntlionError(
					"replay-store-full",
					`SingleProcessReplayStore is holding ${this.#maxEntries} live proofs`
				);
			}
		}

		this.#entries.delete(key);
		this.#entries.set(key, now + ttlSeconds * 1000);
		return true;
	}

	// Every profile uses one TTL, so the oldest insertions expire first and
	// this stops at the first live entry. A store shared by profiles with
	// different TTLs can strand an expired entry behind a live one; that is
	// what the full sweep is for.
	#sweepOldest(now: number): void {
		for (const [key, expiresAt] of this.#entries) {
			if (now < expiresAt) return;
			this.#entries.delete(key);
		}
	}

	#sweepAll(now: number): void {
		for (const [key, expiresAt] of this.#entries) {
			if (now >= expiresAt) this.#entries.delete(key);
		}
	}
}
