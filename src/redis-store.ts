import { AntlionError } from "./errors.js";
import type { ReplayStore } from "./replay-store.js";

/**
 * The one method of a Redis client the store calls: ioredis's `call`, or
 * node-redis's `sendCommand`. A client from `new Redis()`, `new Cluster()` or
 * `createClient()` is passed as it is.
 *
 * A node-redis cluster's `sendCommand` takes the key first, so wrap it:
 * `{ sendCommand: (args) => cluster.sendCommand(args[1], false, args) }`.
 */
export type RedisClientLike =
	| { call(command: string, args: string[]): Promise<unknown> }
	| { sendCommand(args: string[]): Promise<unknown> };

export interface RedisReplayStoreOptions {
	/**
	 * Required. A connected client. You own it: connecting, reconnecting,
	 * timeouts and closing are yours, and an error from it refuses the request
	 * it was serving.
	 */
	client: RedisClientLike;
	/**
	 * Required. Put in front of every key, such as `"dpop:"`. Pick one nothing
	 * else in the database writes under, because an existing key with the same
	 * name reads as a replay. Profiles may share a prefix: replay keys start
	 * with the client key's thumbprint, so two clients never collide.
	 */
	prefix: string;
}

/**
 * A replay store shared by every process connected to one Redis.
 *
 * Each proof is one `SET <prefix><key> 1 PX <ttl> NX`, which records the key
 * only if it is absent, atomically, inside Redis. Keys expire on the Redis
 * server's clock, so the nodes' clocks never meet here.
 *
 * Set `maxmemory-policy` to `noeviction`: under any other policy Redis may
 * evict a replay key before it expires, and that proof is then accepted
 * again. Under `noeviction` a full Redis refuses the write and the request
 * is refused with it.
 *
 * Writes go to a primary. Redis replicates asynchronously, so a primary that
 * fails over before replicating an accepted proof forgets it, and that proof
 * can be accepted once more until it expires.
 */
export class RedisReplayStore implements ReplayStore {
	readonly #send: (args: string[]) => Promise<unknown>;
	readonly #prefix: string;

	constructor(options: RedisReplayStoreOptions) {
		const { client, prefix } = options;
		// `call` first: ioredis also has a `sendCommand`, which takes a Command
		// object rather than an array.
		if (typeof client === "object" && client !== null && "call" in client && typeof client.call === "function") {
			this.#send = ([command, ...args]) => client.call(command as string, args);
		} else if (
			typeof client === "object" &&
			client !== null &&
			"sendCommand" in client &&
			typeof client.sendCommand === "function"
		) {
			this.#send = (args) => client.sendCommand(args);
		} else {
			throw new AntlionError(
				"invalid-options",
				"RedisReplayStore client is required: an ioredis client (call) or a node-redis client (sendCommand)"
			);
		}
		if (typeof prefix !== "string" || prefix === "") {
			throw new AntlionError("invalid-options", "RedisReplayStore prefix is required, such as \"dpop:\"");
		}
		this.#prefix = prefix;
	}

	async addIfAbsent(key: string, ttlSeconds: number): Promise<boolean> {
		const ttlMs = String(Math.ceil(ttlSeconds * 1000));
		const reply = await this.#send(["SET", this.#prefix + key, "1", "PX", ttlMs, "NX"]);
		if (reply === "OK") return true;
		if (reply === null) return false;
		throw new AntlionError(
			"replay-store-failed",
			`RedisReplayStore expected "OK" or null from SET NX, received ${typeof reply}`
		);
	}
}
