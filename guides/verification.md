---
title: Verification
---

# Verification

**What the test suite checks, how to re-run each part, and what has not
been checked. Nothing here asks you to take our word for it.**

| Check | Command | What it shows |
| --- | --- | --- |
| Unit, compliance, conformance, properties, attacks, frameworks | `npm test` | Every behaviour the README claims |
| Compliance gate | `npm run compliance` | Every requirement in `tests/compliance/requirements.json` has a passing test; writes `compliance-report.md` |
| Built package | `npm run test:dist` | The `exports` map, each entry point's exact surface, and a request verified through the built files |
| Mutation testing | `npm run mutation` | Whether the tests notice when the code under them is changed |
| Real Redis, Postgres, several processes, Nimbus | `npm run test:services` | The shared stores and a Java client against real servers; needs the containers in the CI `services` job and the Nimbus jars |

## Mutation testing

The compliance gate shows that each requirement has a passing test. It
can't show that the test would fail if the check were broken. Stryker can:
it changes the code one small edit at a time (flips a comparison, empties a
string, deletes a statement) and runs the tests that cover that line. A
change no test notices is a "survivor".

`npm run mutation` mutates `src/verify.ts`, `src/proof.ts` and
`src/replay-store.ts`, the code that decides whether a request is accepted.
On the run recorded here (Node 26.11, Linux, Stryker 10.0.0, concurrency 4):

| File | Mutants | Killed | Survived | Score |
| --- | ---: | ---: | ---: | ---: |
| `proof.ts` | 206 | 200 | 6 | 97.09% |
| `replay-store.ts` | 70 | 64 | 6 | 91.43% |
| `verify.ts` | 282 | 278 | 4 | 98.58% |
| All | 558 | 542 | 16 | 97.13% |

The first run scored 86.56% with 75 survivors. They were fixed by adding
tests (`tests/unit/refusal-messages.test.ts`, `tests/unit/proof-edges.test.ts`,
the expiry edge in `tests/unit/replay-store-contract.test.ts`), never by
excluding a mutant. Each of the 16 that remain changes nothing a caller can
observe, and this is why:

| Where | Mutation | Why no test can see it |
| --- | --- | --- |
| `proof.ts` `COMPACT_JWS` | drop the `^` or `$` anchor | Junk outside the three segments is refused later as non-canonical base64url, with the same code. The messages test pins the earlier message for both ends. |
| `proof.ts` `modulusBits` | drop `bytes.length === 0` or `bytes[0] === 0` | An empty modulus never decodes, and a leading zero byte gives `log2(0)`, minus infinity bits, which is under any minimum anyway. |
| `proof.ts` `checkKey` | check `crv` on RSA keys too | No RSA algorithm names a curve, so `undefined !== undefined` is never true. |
| `proof.ts` `alg`, `iat` | drop the `typeof` guard | `includes()` and `Number.isFinite()` already refuse every non-string and non-number. |
| `proof.ts` `compactVerify` | drop `algorithms: [alg]` | `alg` has already been checked against the allowlist and the key; jose verifies with the same value. |
| `replay-store.ts` (6) | run the full sweep, or skip the reorder, on every call | Only slower. The full sweep removes the same expired keys the short one would, and the refusal when full is unchanged. |
| `verify.ts` `refusalFor` | issue a nonce without checking nonces are on | `use_dpop_nonce` is only ever produced when they are. |
| `verify.ts` `readRequest` | drop `typeof request !== "object"` | A string request has no `method`, so it is refused one line later as `invalid-request`. |
| `verify.ts` `readHeaderValue` label | empty the label | Lacewing prints it only for a headers object with no `get`, and `readRequest` has refused that already. |
| `verify.ts` Bearer check | drop the `?.` | `split(" ", 1)` always has an element. |

Stryker runs every test file except `tests/types`. Those compile fixtures
with `tsc`, and the instrumented source Stryker writes doesn't type-check,
so they can't run there. They also can't kill a runtime mutant.

## Property tests and fuzzing

`tests/properties/` holds the `fast-check` suites. `proofs.test.ts` changes
one character of a valid proof or token and requires a refusal, and checks
the `iat` window against random clocks. `fuzz.test.ts` goes past what a real
`Headers` would carry: lone surrogates, NUL and CR/LF in both headers,
correctly signed proofs whose header or payload is arbitrary bytes, values
of a megabyte, and arbitrary methods and URLs. Every outcome is a typed
`AntlionError`. Each oversized value is refused by the length check, before
anything is decoded.

## Attacks

`tests/attacks/corpus.test.ts` is one test per known attack, named for it:
a stolen token with the attacker's own key, replay, downgrade to `Bearer`,
an unbound token, a self-issued token, `htu` prefix and host tricks, method
swap, `alg: none` and HMAC with the public key, key swap, `ath` stripped or
reused, pre-generated and stale proofs, duplicate headers, a JSON member
named twice, a token presented as a proof, `jku`/`x5u`/`x5c` injection, and
a private key in the header. Every refusal is also checked for leaks: no
message contains any part of the token or the proof, and the wire refusal
never names the internal code.

## Other implementations

- **Golden vectors.** RFC 9449's worked examples, and proofs made by
  python-cryptography and by Nimbus's `DefaultDPoPProofFactory`
  (`tests/conformance/golden.test.ts`, regenerated by the scripts in
  `tools/golden/`).
- **oauth4webapi, live.** A real HTTP server on 127.0.0.1 with a test token
  endpoint. oauth4webapi gets a DPoP-bound token with ES256, PS256 and
  Ed25519 keys, is challenged for a nonce, retries, and reaches two routes.
  It is refused when its proof is replayed over the wire, when its clock is
  an hour slow, when another key presents its token, and when it sends the
  token as `Bearer` (`tests/conformance/live-oauth4webapi.test.ts`).
- **Nimbus, live.** The same flow driven from Java by Nimbus OAuth 2.0 SDK
  11.38.2, for all three key types (`tests/services/nimbus-live.test.ts`).

## FAPI 2.0 conformance

The OpenID Foundation's conformance suite has supported DPoP in its FAPI 2.0
tests since 2023. Its published test plans certify authorization servers
and clients. When it tests a client, the suite plays the authorization
server and the resource server itself. As of October 2026 we found no plan
that points the suite at someone else's resource server and checks its DPoP
handling.

So Antlion has **not** been run through the FAPI conformance suite, and it
**claims no FAPI certification**. What it does claim is narrower: it
accepts only the FAPI 2.0 algorithm set, and the RFC 9449 resource-server
requirements are covered section by section in `tests/compliance/`. If a
resource-server plan appears, it will be run and its report kept here.

## Not yet done

- **No external security review.** The threat model in
  [Threat model](./threat-model.md) is written for whoever does one. Until
  then, everything on this page is the maintainers checking their own work.
- **Multi-process tests run on Linux only**, because GitHub runs service
  containers only there. The stores' unit tests run on every operating
  system in the matrix.
