---
title: Threat model
---

# Threat model

Antlion protects a resource server's routes behind access tokens that the
authorization server has bound to a client key (`cnf.jkt`, RFC 9449
section 6). A request is accepted only if:

- its access token passes your Lacewing profile,
- the token is bound to the key that signed the DPoP proof,
- the proof was made for this method and this URL,
- the proof is fresh,
- and this server has not accepted the proof before.

## Attackers

| Attacker | Has | Wants |
| --- | --- | --- |
| Token thief | A token from a log, proxy, extension, HAR file or downstream service; not the key | To call the API as the client |
| Proof thief | A token and proofs captured after TLS (a logging proxy, a gateway) | To replay a request, or reuse a proof on another route or method |
| Header attacker | Control of headers between the TLS terminator and the service, or of its own request | To get `htu` checked against its own host, or smuggle a second header |
| Unauthenticated caller | The ability to send requests | To crash the verifier, get garbage accepted, fill the replay store, or learn from refusals |
| Malicious client | Its own key and bound token | To reuse a proof, use one made in advance, or skip the proof |

## What each attack gets

| Attack | Result | Enforced in |
| --- | --- | --- |
| Stolen token with a proof from the thief's key | `jkt-mismatch` | `verify.ts`, binding |
| Stolen token sent as `Bearer` | `bearer-scheme` | `verify.ts`, headers |
| Replay a captured token and proof | `replayed` | replay store, last step |
| Reuse a proof on another URL or method | `htu-mismatch`, `htm-mismatch` | `proof.ts` |
| Point `htu` at a host via `Host` or `X-Forwarded-*` | `htu-mismatch` | `profile.ts`, `origin` is required |
| Two `Authorization` or two `DPoP` headers | `duplicate-authorization`, `duplicate-proof` | `verify.ts`, `node.ts` |
| `alg: none`, HMAC with the public key, swapped header key | `malformed-proof`, `proof-algorithm`, `proof-signature` | `proof.ts` |
| Token signed and bound by the attacker | `token-invalid` | `verify.ts`; only your Lacewing keys verify tokens |
| Proof made in advance with a wrong clock | refused once `iat` leaves the window; with nonces on, refused without a recent server nonce | `verify.ts`, freshness |
| Garbage, oversized or malformed input | a typed refusal, before any signature work | `verify.ts`, `proof.ts` |
| Fill the replay store | not possible; the store is asked only after both signatures and the binding pass | `verify.ts` order |
| Learn which check failed | the client gets one of four RFC error values, and no message repeats request content | `errors.ts`, `verify.ts` |

The tests for each row are in `tests/attacks/`, `tests/compliance/` and
`tests/properties/`.

## Assumptions

If one of these is false, the guarantee above is weaker:

- Your Lacewing profile is right. A profile that trusts the wrong key
  accepts the wrong tokens with or without Antlion.
- The authorization server puts the thumbprint of the key that proved
  possession in `cnf.jkt`.
- `origin` is the origin your clients sign against. Antlion checks that it
  is well formed, not that it is yours.
- Every process taking traffic for the profile shares one replay store, and
  the store doesn't lose writes. Redis eviction, a failover or crash that
  loses a write, and a restart of the in-memory store each let a proof
  inside its window be accepted once more. [Deployment](./deployment.md)
  has the setting for each.
- Clocks of nodes sharing a store are within one second
  ([Deployment](./deployment.md#clocks)).
- Nonce secrets stay secret. Anyone with one can mint nonces, which undoes
  the protection against proofs made in advance, but not the binding or
  replay protection.
- jose, Lacewing and WebCrypto are correct.

## What DPoP does, and what it does not

People expect more from DPoP than it gives, and then expect it from Antlion.

- **It stops replay, not theft.** A leaked token is useless without the key.
  Malware or an XSS running inside the client can still use the key to sign
  fresh proofs, and nothing on the server can tell.
- **It hides nothing.** The token is as readable as it was before. If the
  payload is a secret, that is Lacewing's JWE support.
- **It isn't stateless.** Replay protection needs a store, and nonces need
  either shared state or a shared secret. A proof is single-use, so
  something has to remember which ones it has seen:
  there is no safe DPoP verifier that is stateless.
- **`iat` alone is not freshness.** It is the client's clock, so a proof can
  be signed today for use tomorrow. Server nonces close that.
- **It is not interchangeable with mTLS.** FAPI accepts both, but they fit
  different infrastructure. DPoP lives in the application layer and survives
  TLS being terminated at a proxy; mTLS needs the certificate to reach you.

## Out of scope

- A compromised client. Malware, XSS or an extension inside the client can
  have the key sign fresh proofs, and the server can't tell. A leaked token
  is useless without the key; a leaked key is not.
- Token confidentiality. DPoP binds a token and hides nothing. Use
  Lacewing's JWE support if the payload is secret.
- The token endpoint, refresh tokens and `dpop_jkt`. That is the
  authorization server's half.
- Denial of service by volume. Refusals are cheap but not free; throttle at
  your edge.
- Timing of the binding comparisons. `cnf.jkt` and `ath` are compared with
  plain string equality because both are public to whoever holds the token.
  Nonces are compared with `crypto.subtle.verify`.
- A handler that ignores the refusal. Antlion throws; the rest is yours.

## Review status

No external review has been done. When one happens, its report and the
fixes go in this repository next to this file.
