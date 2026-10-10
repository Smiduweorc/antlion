// The "antlion-lacewing/postgres" entry point: a replay store shared through
// Postgres. It imports no Postgres client; you pass yours in.

export { PostgresReplayStore } from "./src/postgres-store.js";

export type { PostgresClientLike, PostgresReplayStoreOptions } from "./src/postgres-store.js";
