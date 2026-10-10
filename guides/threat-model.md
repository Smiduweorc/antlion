---
title: Threat model
---

# Threat model

**What Antlion protects, against whom, what it assumes, and what it leaves
to something else. Written for anyone reviewing the code, and for anyone
deciding whether it fits their service.**

## What is protected

A resource server's routes, behind access tokens that the authorization
server has bound to a client key (`cnf.jkt`, RFC 9449 section 6). Antlion's
promise is narrow:

> A request is accepted only if its access token passes your Lacewing
> profile, the token is bound to the key that signed the DPoP proof, the
> proof was made for this method and this URL, it is fresh, and this
> server has not accepted it before.

Everything below is about keeping that sentence true.

## Who the attackers are

| Attacker | Has | Wants |
| --- | --- | --- |
| **Token thief** | An access token, from a log, a proxy, a browser extension, a leaked HAR file or a compromised downstream service. Not the client's private key. | To call the API as the client. |
| **Proof thief** | A token and one or more proofs the client sent, captured on the wire after TLS (a logging proxy, a misconfigured gateway). | To replay a captured request, or reuse a proof on another route or method. |
| **Network attacker in front of the service** | Control over headers between the TLS terminator and the service, or of the client's own request headers. | To make the service check `htu` against a host the attacker chose, or to smuggle a second header past the check. |
| **Unauthenticated caller** | Nothing but the ability to send requests. | To crash the verifier, make it accept garbage, fill the replay store, or learn something from the refusals. |
| **Malicious client** | Its own key and its own bound token. | To use one proof more than once, or a proof made in advance, or to get its token accepted without a proof. |

## What each attacker gets

| Attack | Result | Where it is enforced | Test |
| --- | --- | --- | --- |
| Present a stolen token with a proof from the thief's own key | `jkt-mismatch` | `verify.ts`, binding step | `tests/attacks/corpus.test.ts` |
| Present a stolen token as `Bearer` | `bearer-scheme` | `verify.ts`, header step | same |
| Replay a captured token and proof | `replayed` | replay store, last step | same, and `tests/services/multi-process.test.ts` across processes |
| Reuse a proof on another URL or method | `htu-mismatch`, `htm-mismatch` | `proof.ts`, request binding | same |
| Point `htu` at a host via `Host` or `X-Forwarded-*` | `htu-mismatch`; those headers are never read | `profile.ts`, `origin` is required | same |
| Send two `Authorization` or two `DPoP` headers | `duplicate-authorization`, `duplicate-proof` | `verify.ts`, `node.ts` reads `headersDistinct` | same, and `tests/integration/frameworks.test.ts` |
| `alg: none`, HMAC keyed with the public key, swap the header key | `malformed-proof`, `proof-algorithm`, `proof-signature` | `proof.ts` | same |
| A token signed by the attacker and bound to the attacker's key | `token-invalid`; the token is checked only against your Lacewing profile's keys | `verify.ts`, `proof.ts` is the only place a header key is used | same, and the lint rule on `EmbeddedJWK` |
| A proof made in advance with a lying clock | Refused once `iat` is outside the window. With nonces on, refused unless it carries a nonce this server issued in the last `maxProofAge` seconds. | `verify.ts`, freshness | `tests/compliance/time-replay.test.ts`, `8-9-nonces.test.ts` |
| Garbage, oversized or malformed input | A typed refusal, before any signature work for anything malformed or oversized | `verify.ts`, `proof.ts` length and shape checks | `tests/properties/fuzz.test.ts` |
| Fill the replay store with unauthenticated requests | Not possible: nothing reaches the store before both signatures and the binding pass | `verify.ts` order | `tests/compliance/order.test.ts` |
| Learn which check failed | The client gets one of four RFC error values; the precise code goes only to your logs, and no message repeats request content | `errors.ts`, `verify.ts` refusal | `tests/attacks/corpus.test.ts` leak check |

## What Antlion assumes

If one of these is false, the promise above is weaker, and how much weaker
is stated.

- **Your Lacewing profile is right.** Issuer, audience, algorithms and keys
  are yours. Antlion adds checks to the profile and never removes any, but a
  profile that trusts the wrong key accepts the wrong tokens with or without
  Antlion.
- **The authorization server binds tokens to the key that proved
  possession.** If it puts any other thumbprint in `cnf.jkt`, the binding
  check compares against the wrong value.
- **`origin` is the origin your clients sign against.** It is checked to be
  a well-formed origin, not that it is yours.
- **The replay store is shared by every process that takes traffic for the
  profile, and it doesn't lose writes.** A store per process accepts each
  proof once per process. Redis evicting keys, Redis or Postgres losing a
  write on failover or crash, and a process restart for the in-memory store
  each let a proof inside its window be accepted once more.
  [Deployment](./deployment.md) has each case and the setting that closes it.
- **The clocks of nodes sharing a store are within one second.** From one
  second of difference on, a proof can be accepted once by a fast node and
  once more by a slow one. The arithmetic and the test are in
  [Deployment](./deployment.md#clocks).
- **Nonce secrets stay secret.** Anyone with a secret can mint nonces, which
  takes back what nonces add (protection against proofs made in advance),
  but not the binding or replay protection.
- **jose, Lacewing and WebCrypto are correct.** Signature verification, the
  RFC 7638 thumbprint, and HMAC are theirs.

## Out of scope

| Not protected | Why | Where it goes |
| --- | --- | --- |
| A compromised client | Code running inside the client (malware, XSS, a malicious extension) can ask the key to sign fresh proofs. The server can't tell those from the real client. | The client: non-extractable keys, a content security policy. |
| Token confidentiality | DPoP binds a token; it doesn't hide one. | Lacewing's JWE support. |
| The token endpoint, refresh tokens, `dpop_jkt` | The authorization server's half of the protocol. | The authorization server. |
| Denial of service by volume | Antlion refuses cheaply, but every request still costs something. | Your edge or gateway. |
| Timing of the binding comparisons | `cnf.jkt` and `ath` are compared with ordinary string equality. Both values are public to whoever holds the token, so a timing difference reveals nothing they don't already have. Nonces, which are secrets' output, are compared by `crypto.subtle.verify`. | Not needed. |
| Any request where your code ignores the refusal | Antlion throws; acting on it is yours. | Your handler. |

## Review status

No external review has been done. This document exists so that one can
start from it. When a review happens, its report and a log of the issues
fixed go in this repository next to this file, and this section links to
them.
