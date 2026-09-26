---
title: Boundaries
---

# Boundaries

**This layer decides whether the one presenting a token is the one it was
issued to, and whether this request is the one they signed. It does not
decide whether the token itself is valid, how the key was made, or what the
client does with it.**

Lacewing answers "is this token real, and is it meant for me". Antlion
answers the question Lacewing deliberately leaves open: "is the caller
allowed to be holding it". The two look like one check from the outside and
are kept apart on purpose. Lacewing's profile is passed in unchanged, and
Antlion adds refusals to it without loosening a single one of Lacewing's.

## What this layer owns

- **Reading the two headers.** Exactly one `Authorization: DPoP` and exactly
  one `DPoP`. A second copy of either is a refusal, and so is the `Bearer`
  scheme. Two headers joined by `Headers` into one value are detectable,
  because a compact JWS never contains a comma.
- **The proof.** `typ` is `dpop+jwt`. `alg` is on the allowlist and matches
  the key's type and curve. The key is public, and a proof carrying private
  key members is refused. The signature is checked against the key in the
  proof's own header, which is the only place in the package that happens.
- **The request binding.** `htm` matches the request method exactly. `htu`
  matches the configured origin plus the request path, normalised per
  RFC 3986, with the query and fragment removed. `ath` is the SHA-256 of the
  exact token string presented, and it is always required.
- **The key binding.** The RFC 7638 thumbprint of the verified proof key,
  computed by `jose` and never read from input, equals the token's
  `cnf.jkt`. A token with no `cnf.jkt` is refused.
- **Freshness.** `iat` inside a window you size, under a hard ceiling, with a
  small fixed allowance for a client clock running ahead. Server nonces,
  when you turn them on: stateless, expiring, and signed with a secret you
  can rotate.
- **Replay.** Each proof is accepted once, recorded through a store contract
  with one atomic method. The store is asked last, and a store error is a
  refusal.
- **The order of all of the above**, which is fixed: cheap checks, then
  signatures, then the binding, then the store.
- **The refusal on the wire.** The 401 (or 400 for a duplicated or
  malformed `Authorization` header), `WWW-Authenticate: DPoP` with the right
  error and the accepted algorithms, and `DPoP-Nonce` with
  `Cache-Control: no-store` when a nonce is due. The client is told the RFC
  error value; you are told exactly which check failed.
- **The header names** a browser client needs in your CORS policy, as
  exported constants.

## What this layer never does

| Excluded | Why | Where it goes |
| --- | --- | --- |
| Verifying the access token itself | Signature, issuer, audience, `typ`, expiry and revocation already have one owner. A second implementation here is a second policy that can disagree with the first. | The Lacewing profile you pass in. Antlion calls it and changes nothing about it. |
| Creating proofs, and retrying on a nonce challenge | That is the client's half of the protocol, and a resource server has no key to sign with. | [oauth4webapi](https://github.com/panva/oauth4webapi) or [openid-client](https://github.com/panva/openid-client). |
| Issuing bound tokens, `dpop_jkt`, PAR, PKCE | Putting `cnf.jkt` into a token is the authorization server's job, and so is binding the authorization code to the key. | [oidc-provider](https://github.com/panva/node-oidc-provider), Keycloak, Curity, or whatever issues your tokens. |
| Binding refresh tokens | Refresh tokens are redeemed at the authorization server, which is the one that has to check the binding. | The authorization server. Public clients should have their refresh tokens bound too, and that is its setting. |
| Accepting `Bearer` on a DPoP route | An endpoint that accepts both is only as strong as `Bearer`, so the binding protects nothing. | Two routes, two profiles: a plain Lacewing profile for the old traffic, an Antlion profile for the new, chosen by your router rather than by the client. |
| Working out the request URL | `Host`, `X-Forwarded-*` and `Forwarded` are set by the client or by the nearest proxy. An `htu` checked against them checks the attacker's own claim. | `origin`, required. |
| Deciding whether nonces are on | A nonce costs a round trip and closes pre-generated proofs. Which matters more is a property of your clients and your threat model. | `nonce: "required" \| "off"`, required, with no default. |
| Choosing the replay store | Twenty nodes with twenty memory stores accept the same proof twenty times. Only your deployment knows what is shared. | A store you pass in. The contract is one atomic `addIfAbsent`: `SET key 1 NX EX ttlSeconds` in Redis, `INSERT ... ON CONFLICT DO NOTHING` in Postgres. |
| mTLS (RFC 8705) | A different binding at a different layer, which needs the client certificate to reach the service. | Not here. |
| Opaque tokens and introspection | A JWT access token carries `cnf.jkt` itself. Introspection is a network call and a cache, with failure modes of its own. | Out of v1, and possibly for good. |
| Protecting a compromised client | Code running inside the client can use the key to sign fresh proofs. No check on the server can tell that apart from the real client. | The client: non-extractable WebCrypto keys, a content security policy, and not getting XSS'd. |
| Hiding the token's contents | DPoP binds a token. It does not encrypt one. | Lacewing's JWE support. |
| Client key storage and rotation | A client that rotates its key mid-session breaks its own bound tokens, and a browser key that can be exported can be stolen. | The client, and its documentation. |
| The CORS policy | Which origins may call your API is your API's decision. | Your server. Antlion exports the header names to put in it. |
| Rate-limiting bad proofs | Throttling a caller is about the traffic you receive, and it needs to happen before any of this runs. | Your edge or gateway. |
| Cryptography | The novel code is the policy. A hand-rolled JOSE implementation is a worse one. | `jose`, as a direct dependency, for the proof only. |
| Logging, metrics, `process.env`, work at import time, `node:` imports | Same as every sibling. | The typed refusal handed back to you; the options object; a constructor call; `globalThis.crypto` for hashing. |

## One process

The in-memory replay store is for one process and for tests. Its check and
its write happen with no `await` between them, which makes it atomic in one
JavaScript process and in no other situation. The store contract is written so
that moving to Redis or Postgres is a constructor change, and the package
will not pretend a memory store is anything else.

Nonces are the other half of this. Each is an HMAC over the second it was
issued, rather than an entry in a list the server remembers, so every node
that holds the same secret
accepts the same nonces, and rotating the secret is a configuration change
rather than a migration.

## No benchmarks yet

There is no performance claim here, because there is no public harness behind
one yet. When there is, it will run on ordinary CI hardware and the numbers
will be reproducible.
