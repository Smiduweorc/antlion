---
title: Verification
---

# Verification

| Check | Command |
| --- | --- |
| Unit, compliance, conformance, properties, attacks, frameworks | `npm test` |
| Every requirement in `tests/compliance/requirements.json` has a passing test | `npm run compliance` |
| The built package through its `exports` map | `npm run test:dist` |
| Mutation testing | `npm run mutation` |
| Real Redis, Postgres, several processes, a Nimbus client | `npm run test:services` |

`test:services` needs `ANTLION_TEST_REDIS_URL`, `ANTLION_TEST_POSTGRES_URL`,
a JDK and the Nimbus jars. The CI `services` job sets them up.

## Mutation testing

The compliance gate shows each requirement has a passing test, not that the
test would fail if the check broke. Stryker mutates `src/verify.ts`,
`src/proof.ts` and `src/replay-store.ts` one edit at a time and reruns the
covering tests. On Node 26.11, Linux, Stryker 10.0.0, concurrency 4:

| File | Mutants | Killed | Survived | Score |
| --- | ---: | ---: | ---: | ---: |
| `proof.ts` | 206 | 200 | 6 | 97.09% |
| `replay-store.ts` | 70 | 64 | 6 | 91.43% |
| `verify.ts` | 282 | 278 | 4 | 98.58% |
| All | 558 | 542 | 16 | 97.13% |

The first run scored 86.56% with 75 survivors. They were fixed by adding
tests, not by excluding mutants. None of the 16 left changes anything a
caller can observe:

| Where | Mutation | Why no test sees it |
| --- | --- | --- |
| `proof.ts` `COMPACT_JWS` | drop the `^` or `$` anchor | Junk outside the segments is refused later as non-canonical base64url, same code |
| `proof.ts` `modulusBits` | drop `bytes.length === 0` or `bytes[0] === 0` | An empty modulus never decodes; a leading zero gives minus infinity bits |
| `proof.ts` `checkKey` | check `crv` on RSA keys too | No RSA algorithm names a curve |
| `proof.ts` `alg`, `iat` | drop the `typeof` guard | `includes()` and `Number.isFinite()` refuse the same values |
| `proof.ts` `compactVerify` | drop `algorithms: [alg]` | `alg` is already checked; jose uses the same value |
| `replay-store.ts` (6) | full sweep, or skip the reorder, on every call | Only slower |
| `verify.ts` `refusalFor` | issue a nonce without checking nonces are on | `use_dpop_nonce` only happens when they are |
| `verify.ts` `readRequest` | drop `typeof request !== "object"` | A string has no `method` and is refused one line later |
| `verify.ts` `readHeaderValue` label | empty the label | Only printed for a headers object `readRequest` already refused |
| `verify.ts` Bearer check | drop the `?.` | `split(" ", 1)` always has an element |

Stryker runs every test file except `tests/types`, which compile fixtures
with `tsc` and can't type-check Stryker's instrumented source.

## Property tests and fuzzing

`tests/properties/` holds the `fast-check` suites. One changes a single
character of a valid proof or token and requires a refusal, and checks the
`iat` window against random clocks. The fuzz suite sends lone surrogates,
NUL and CR/LF in both headers, correctly signed proofs with arbitrary header
or payload bytes, megabyte values, and arbitrary methods and URLs. Every
outcome is a typed `AntlionError`, and oversized values are refused before
anything is decoded.

## Attacks

`tests/attacks/corpus.test.ts` has one test per known attack: a stolen token
with the attacker's key, replay, downgrade to `Bearer`, an unbound token, a
self-issued token, `htu` prefix and host tricks, method swap, `alg: none`
and HMAC with the public key, key swap, `ath` stripped or reused,
pre-generated and stale proofs, duplicate headers, a JSON member named
twice, a token presented as a proof, `jku`/`x5u`/`x5c` injection, and a
private key in the header. Each refusal is also checked for leaks: no
message contains part of the token or proof, and the wire refusal never
names the internal code.

## Other implementations

- Golden vectors: RFC 9449's worked examples, and proofs made by
  python-cryptography and by Nimbus's `DefaultDPoPProofFactory`, regenerated
  by the scripts in `tools/golden/`.
- oauth4webapi, live. A real HTTP server on 127.0.0.1 with a test token
  endpoint. oauth4webapi gets a bound token with ES256, PS256 and Ed25519
  keys, is challenged for a nonce, retries, and reaches two routes. It is
  refused when its proof is replayed, when its clock is an hour slow, when
  another key presents its token, and when it sends the token as `Bearer`.
- Nimbus, live. The same flow from Java with Nimbus OAuth 2.0 SDK 11.38.2,
  for all three key types.

## FAPI 2.0 conformance

The OpenID Foundation's conformance suite has tested DPoP in FAPI 2.0 since
2023, but its plans certify authorization servers and clients. When it
tests a client, it plays the resource server itself. As of October 2026 we
found no plan that tests someone else's resource server.

So Antlion has not been run through the FAPI conformance suite and claims
no FAPI certification. It accepts only the FAPI 2.0 algorithm set, and the
RFC 9449 resource-server requirements are covered section by section in
`tests/compliance/`. If a resource-server plan appears, it will be run and
its report kept here.

## Not yet done

- No external security review. Everything on this page is the maintainer
  checking their own work. The [threat model](./threat-model.md) is written
  for whoever does one.
- Multi-process tests run on Linux only, because GitHub runs service
  containers only there. The stores' unit tests run on Linux, macOS and
  Windows.
