---
title: Deployment
---

# Deployment

## Choosing a replay store

| Setup | Store |
| --- | --- |
| One Node process, and tests | `SingleProcessReplayStore` |
| More than one process, with Redis | `RedisReplayStore` from `antlion-lacewing/redis` |
| More than one process, with Postgres | `PostgresReplayStore` from `antlion-lacewing/postgres` |
| Something else shared | Your own `ReplayStore` with one atomic `addIfAbsent(key, ttlSeconds)` |

The Redis store sends one `SET key 1 PX ttl NX` per accepted request, the
Postgres store one `INSERT ... ON CONFLICT DO UPDATE ... WHERE expired`.
The in-memory store is atomic because its check and write have no `await`
between them, which holds in one JavaScript process only.

"More than one process" includes Node's `cluster` module, PM2 in cluster
mode, several containers behind a load balancer, serverless functions (each
warm instance is a process), and a blue/green pair that both take traffic.
`tests/services/multi-process.test.ts` sends one proof to four processes at
once: with a shared store one accepts it; with a memory store in each, all
four do.

Don't use `SingleProcessReplayStore`:

- With more than one process. N processes accept each proof N times.
- If a replay just after a restart matters to you. Its memory goes with the
  process, and a proof accepted just before the restart is accepted once
  more after it, until the proof is too old.
- Without a sensible `maxEntries`. A full store refuses requests rather than
  forget a proof early.

## Sizing

A replay key lives `maxProofAge + 6` seconds: the `iat` window, the 5
seconds a client clock may run ahead, and 1 second because both edges of the
window are inclusive. That is 66 seconds at the default `maxProofAge` of 60,
and 306 at the cap of 300.

```text
live keys = peak accepted requests per second x (maxProofAge + 6)
```

Only accepted requests write a key.

- `SingleProcessReplayStore`: set `maxEntries` above that number. 500
  requests a second at the default is 33,000 keys, so `maxEntries: 50_000`
  leaves room. When it is full, requests are refused with
  `replay-store-failed` (`cause`: `replay-store-full`) until keys expire.
- Redis: the same number of keys, each your prefix plus 87 characters,
  expired by Redis.
- Postgres: the same number of live rows, plus expired rows
  `deleteExpired()` hasn't removed yet. Called once a minute, the table
  stays under about twice the live count.

A larger `maxProofAge` means a bigger store and a longer life for a stolen
proof; a smaller one refuses clients whose clocks run further behind. 60
seconds still forgives an unsynchronised laptop; 300 is the cap because
that is what oauth4webapi accepts.

## Redis

```ts
import { RedisReplayStore } from "antlion-lacewing/redis";

const replay = new RedisReplayStore({ client: redis, prefix: "dpop:" }); // ioredis or node-redis
```

- Set `maxmemory-policy` to `noeviction`. Under any `volatile-*` or
  `allkeys-*` policy Redis evicts keys with a TTL when memory runs short,
  and an evicted replay key is a proof that can be accepted again. Under
  `noeviction` a full Redis refuses the write and the request is refused.
- Use a primary. Writes to a replica fail. Redis replicates asynchronously,
  so a failover before a key is replicated forgets it, and that proof can
  be accepted again until it is too old.
- A Redis without persistence forgets every key on restart, with the same
  result.
- Each request touches one key, so it never crosses cluster slots. An
  ioredis `Cluster` can be passed as it is; a node-redis cluster needs the
  one-line wrapper in the `RedisClientLike` docs. CI tests a single Redis 8
  only; Cluster is untested.

## Postgres

```ts
import { PostgresReplayStore } from "antlion-lacewing/postgres";

const replay = new PostgresReplayStore({ client: pool, table: "dpop_replay" }); // a pg Pool
setInterval(() => replay.deleteExpired().catch(console.error), 60_000); // or your own scheduler
```

- Create the table with your other migrations; the statement is in the
  `PostgresReplayStore` docs. Not `UNLOGGED`: an unlogged table is emptied
  after a crash.
- Leave `synchronous_commit` on for this table, or a crash loses the last
  accepted keys. Asynchronous replication can lose them on failover the
  same way; synchronous replication closes that.
- Schedule `deleteExpired()`. Antlion starts no timers. Nothing is refused
  if you forget; the table grows.
- Each accepted request holds one pool connection for one insert.

Both shared stores expire keys on the database server's clock.

## Nonces across nodes

A nonce is an HMAC over the second it was issued and the origin. Every node
with the same `nonceSecrets` and `origin` accepts every other node's
nonces; nothing else is shared.

- Use the same list, in the same order, on every node. The first secret
  signs; all of them verify.
- Each secret is at least 32 random bytes (the profile enforces it):
  `crypto.getRandomValues(new Uint8Array(32))`.
- Rotation takes three deploys, so no node receives a nonce signed with a
  secret it doesn't have yet:

  1. Add the new secret second: `[old, new]`.
  2. Once every node has step 1, put it first: `[new, old]`.
  3. Once every node has step 2 and `maxProofAge` plus 5 seconds has
     passed, remove the old one: `[new]`.

  Skipping step 1 is not a security problem. A node without the new secret
  answers `use_dpop_nonce` with a nonce of its own, and the client retries.

## Clocks

- The client's. A proof's `iat` may be up to 5 seconds ahead of the node
  (fixed) and up to `maxProofAge` behind.
- Each node's. Freshness and nonces use the node's own clock (the profile's
  `now`). Keep the clocks of every node sharing a store within 1 second of
  each other. At 1 second or more, a proof accepted by the faster node at
  the first instant it allows has its replay key expire before the slower
  node stops accepting it, so the slower node accepts it again. The
  "two nodes sharing a store" test in `tests/compliance/time-replay.test.ts`
  checks both sides of that. NTP or chrony keeps ordinary servers well
  inside it; containers share their host's clock.
- The store's. Redis and Postgres expire keys on their own clock, which only
  has to run at the right speed.

## Rolling deploys

During a rolling deploy old and new nodes take traffic at once. Three
changes open a window of one replay per proof, lasting about
`maxProofAge + 6` seconds after the last old node stops:

- Changing the store, including from `SingleProcessReplayStore` to a shared
  one, or changing the Redis prefix or the Postgres table. Old and new nodes
  remember proofs in different places.
- Changing `maxProofAge`, either way. A proof first accepted by a node with
  the shorter setting can come back to a node with the longer one after its
  key has gone.
- Changing `origin`. This is a burst of refusals, since old and new nodes
  refuse each other's proofs, not a replay window.

If that matters, stop and start instead of rolling, or move to a shared
store first and change the rest afterwards. Turning nonces on or off, and
rotating secrets in the order above, open nothing.
