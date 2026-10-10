// The "antlion-lacewing/redis" entry point: a replay store shared through
// Redis. It imports no Redis client; you pass yours in.

export { RedisReplayStore } from "./src/redis-store.js";

export type { RedisClientLike, RedisReplayStoreOptions } from "./src/redis-store.js";
