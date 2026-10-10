---
title: Deployment
---

# Deployment

**What changes when Antlion runs on more than one process: which replay
store, how big, how nonces and clocks behave across nodes, and what a
rolling deploy can open up for a minute.**

Every number here comes from the code or a test, and the condition it holds
under is next to it. Where a number depends on your traffic, the guide gives
the formula and leaves the number to you.

## Choosing a replay store

| Your setup | Store | Why |
| --- | --- | --- |
| One Node process, and tests | `SingleProcessReplayStore` | Atomic because its check and write have no `await` between them. That holds in one JavaScript process only. |
| More than one process, with Redis | `RedisReplayStore` from `antlion-lacewing/redis` | One `SET key 1 PX ttl NX` per accepted request, on the server, through your ioredis or node-redis client. |
| More than one process, with Postgres | `PostgresReplayStore` from `antlion-lacewing/postgres` | One `INSERT ... ON CONFLICT DO UPDATE ... WHERE expired` per accepted request, through your `pg` pool. |
| Something else shared | Your own `ReplayStore` | One method, `addIfAbsent(key, ttlSeconds)`, which checks and records in one atomic step. |

"More than one process" includes Node's `cluster` module, PM2 in cluster
mode, several containers behind one load balancer, serverless functions
(each warm instance is its own process), and a blue/green pair that both
take traffic. `tests/services/multi-process.test.ts` sends one proof to four
processes at once: with a shared store one accepts it, and with a
`SingleProcessReplayStore` in each, all four do.

### What the single-process store must never be used for

- **Any setup above with more than one process.** Each process accepts every
  proof once, so N processes accept it N times.
- **A process that restarts while proofs are in flight, if a replay inside
  that minute matters to you.** Its memory goes with it, and a proof accepted
  just before the restart is accepted once more after it, until the proof is
  too old.
- **A process you can't give a `maxEntries` to.** A full store refuses
  requests rather than forget a proof early. See the next section for the
  number.

## Sizing

A replay key lives for `maxProofAge + 6` seconds: the `iat` window, the 5
seconds a client clock may run ahead, and 1 second because both edges of the
window are inclusive. With the default `maxProofAge` of 60 seconds that is 66
seconds, and with the cap of 300 it is 306 (asserted in
`tests/compliance/time-replay.test.ts`).

So every store holds, at its peak:

```text
live keys = peak accepted requests per second x (maxProofAge + 6)
```

Only accepted requests count. A refusal before the store (a bad signature, a
wrong `htu`, an expired token) never writes a key.

- **`SingleProcessReplayStore`:** `maxEntries` is that number, with room to
  spare. 500 requests a second at the default `maxProofAge` is 33,000 keys,
  so `maxEntries: 50_000` leaves half again. When it is full, requests are
  refused with `replay-store-failed` (whose `cause` is `replay-store-full`)
  until keys expire.
- **Redis:** the same count of keys, each removed by Redis when it expires.
  Each key is your prefix plus 87 characters.
- **Postgres:** the same count of live rows, plus every expired row
  `deleteExpired()` hasn't removed yet. Call it once a minute and the table
  stays near twice the live count at most.

`maxProofAge` trades this size, and the time a stolen proof stays usable,
against clients with slow clocks. A client whose clock runs behind by more
than `maxProofAge` can't get a request accepted. 60 seconds is the default
because it is short and still forgives an unsynchronised laptop; 300 is the
ceiling because that is what oauth4webapi accepts.

## Redis

- **Set `maxmemory-policy` to `noeviction`.** Under any `volatile-*` or
  `allkeys-*` policy Redis evicts keys with a TTL when memory runs short,
  and an evicted replay key is a proof that can be accepted again. Under
  `noeviction` a full Redis refuses the write, the store throws, and the
  request is refused.
- **Use a primary.** Writes to a replica fail. Redis replicates
  asynchronously, so a primary that fails over before replicating a key
  forgets it, and that proof can be accepted again until it is too old.
- **A Redis without persistence** forgets every key when it restarts, with
  the same result for the proofs inside the window at that moment.
- **Cluster** works: each request is one key, so it never crosses slots.
  Pass an ioredis `Cluster` as it is. A node-redis cluster needs the
  one-line wrapper in the `RedisClientLike` docs.

## Postgres

- **Create the table with your other migrations.** The statement is in the
  `PostgresReplayStore` docs. Not `UNLOGGED`: an unlogged table is emptied
  after a crash.
- **Leave `synchronous_commit` on** for this table's writes, or a crash
  loses the last accepted keys. With asynchronous replication, a failover
  can lose them the same way; synchronous replication closes that.
- **Schedule `deleteExpired()`.** Antlion starts no timers. Nothing is
  refused if you forget; the table just grows.
- **Pool size.** Each accepted request holds one connection for one insert.
  Size the pool for that next to whatever else your service does.

Both shared stores take expiry from the database server's clock, so the
nodes' clocks never meet inside the store.

## Nonces across nodes

Nonces are stateless: an HMAC over the second a nonce was issued and the
origin. Every node with the same `nonceSecrets` and the same `origin`
accepts every other node's nonces, and nothing needs sharing beyond the
secrets (`tests/compliance/8-9-nonces.test.ts`, "nonces are stateless").

- **The same list, in the same order, on every node.** The first secret signs
  and all of them verify.
- **At least 32 random bytes each**, which the profile enforces.
- **Rotation is three deploys**, so that no node ever receives a nonce
  signed with a secret it doesn't have yet:

  1. Add the new secret **second**: `[old, new]`. Nodes still sign with
     `old` and now accept `new`.
  2. Once every node has step 1, put it **first**: `[new, old]`.
  3. Once every node has step 2 and `maxProofAge` plus 5 seconds has
     passed, remove the old one: `[new]`.

  Skipping step 1 is not a security problem. A node that doesn't have the new
  secret yet refuses those nonces with `use_dpop_nonce` and a nonce of its
  own, and the client retries.

## Clocks

Three clocks are involved, and each has its own limit.

- **The client's.** A proof's `iat` may be up to 5 seconds ahead of the node
  checking it, which is fixed, and up to `maxProofAge` behind.
- **Each node's.** Freshness and nonces are judged on the node's own clock
  (the profile's `now`). **Keep the clocks of every node sharing a store
  within 1 second of each other.** At 1 second or more, a proof accepted by
  the node whose clock is ahead, at the first instant it allows, has its
  replay key expire before the node whose clock is behind stops accepting
  that proof, so the slower node accepts it a second time. The test
  "two nodes sharing a store refuse a replay while their clocks differ by
  under a second, and not from one second on" in
  `tests/compliance/time-replay.test.ts` pins both sides of that number.
  NTP or chrony keeps ordinary servers well inside it; containers share
  their host's clock.
- **The store's.** Redis and Postgres expire keys on their own clock, which
  only has to run at the right speed.

## Rolling deploys

During a rolling deploy, old and new nodes take traffic at once. Most
changes are harmless. Three open a window of one replay per proof, lasting
about `maxProofAge + 6` seconds after the last old node stops:

- **Changing the store**, including moving from `SingleProcessReplayStore` to
  a shared one, or changing the Redis prefix or the Postgres table. Old and
  new nodes remember proofs in different places, so a proof accepted by one
  can be accepted by the other.
- **Changing `maxProofAge`, either way.** Each node writes keys that live
  its own `maxProofAge + 6` seconds and accepts proofs up to its own
  `maxProofAge` old. A proof first accepted by the node with the shorter
  setting can come back to a node with the longer one after its key has
  gone.
- **Changing `origin`.** Proofs for the old origin are refused by new nodes
  and the other way around, which is a burst of refusals rather than a
  replay window, but clients see it.

If that window matters, do the change as a stop and start rather than a
roll, or put the nodes behind a shared store first and change the rest
afterwards. Turning nonces on or off, and rotating secrets in the order
above, open nothing.
